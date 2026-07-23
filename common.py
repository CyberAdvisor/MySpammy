"""
Shared utilities for the Gmail spam cleaner.

Uses plain IMAP (to read/trash Spam) and SMTP (to send the digest),
authenticated with a Gmail address + an App Password -- no OAuth, no
Google Cloud Console setup required.

Used by sweep.py (deletes matching spam) and digest.py (sends the daily
summary).
"""
import html
import imaplib
import json
import logging
import os
import re
import smtplib
from dataclasses import dataclass
from datetime import datetime
from email import message_from_bytes
from email.errors import HeaderParseError
from email.header import decode_header
from email.message import Message
from email.utils import parseaddr
from typing import Optional
from zoneinfo import ZoneInfo

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

SPAM_FOLDER = '"[Gmail]/Spam"'

VALID_FIELDS = {"subject", "from", "body"}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(BASE_DIR, "credentials.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_JSONL_PATH = os.path.join(BASE_DIR, "log.jsonl")
STATE_PATH = os.path.join(BASE_DIR, "state.json")
ERROR_LOG_PATH = os.path.join(BASE_DIR, "errors.log")

# Errors go to a dedicated file so a broken rule or connection hiccup never
# gets lost in stdout when run as a background automation.
logging.basicConfig(
    filename=ERROR_LOG_PATH,
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("gmail_spam_cleaner")

MOUNTAIN_TZ = ZoneInfo("America/Denver")


def local_timestamp() -> str:
    """Current time in Mountain Time, formatted for log lines, e.g.
    '2026-07-19 08:00 MDT'. Automatically shows MDT or MST depending on
    the time of year -- America/Denver handles the daylight saving
    transition correctly, no manual offset math needed."""
    return datetime.now(MOUNTAIN_TZ).strftime("%Y-%m-%d %H:%M %Z")


@dataclass
class CompiledRule:
    name: str
    field: str
    pattern: re.Pattern
    perm_delete: bool = False


# ---------------------------------------------------------------------------
# Config / rules
# ---------------------------------------------------------------------------

def load_config(path: str = CONFIG_PATH) -> dict:
    """Load config.json. Raises if the file is missing or not valid JSON --
    that's a hard stop, since there's nothing sensible to run without it."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_spam_domain_perm_delete(config: dict) -> bool:
    """Read the global 'spam_domain_perm_delete' setting: whether the
    hardcoded Spam Domain check (see sweep.py) permanently deletes
    (true) or moves to Trash (false, the default). Any non-boolean value
    is logged and treated as False -- a config mistake must never
    silently escalate to permanent, unrecoverable deletion."""
    value = config.get("spam_domain_perm_delete", False)
    if not isinstance(value, bool):
        logger.warning(
            "'spam_domain_perm_delete' must be true/false, got %r -- defaulting to false (Trash, not permanent)",
            value,
        )
        return False
    return value


def compile_rules(config: dict) -> list[CompiledRule]:
    """Validate and compile every enabled rule's regex (field in
    subject/from/body + pattern).

    A rule with a bad field name or a regex that fails to compile is
    logged to errors.log and skipped -- it never silently matches
    everything, and it never crashes the whole sweep.

    Optional "perm_delete" (bool): if true, a match permanently deletes
    the message instead of moving it to Trash. Defaults to False. Any
    non-boolean value is logged and treated as False -- a config mistake
    must never silently escalate a rule to irreversible deletion.
    """
    compiled = []
    for rule in config.get("rules", []):
        name = rule.get("name", "<unnamed>")

        if not rule.get("enabled", True):
            continue

        field = rule.get("field")

        if field not in VALID_FIELDS:
            logger.warning(
                "Skipping rule '%s': field '%s' must be one of %s",
                name, field, sorted(VALID_FIELDS),
            )
            continue

        pattern_str = rule.get("pattern", "")
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            logger.warning("Skipping rule '%s': invalid regex '%s' (%s)", name, pattern_str, e)
            continue

        perm_delete = rule.get("perm_delete", False)
        if not isinstance(perm_delete, bool):
            logger.warning(
                "Rule '%s': 'perm_delete' must be true/false, got %r -- defaulting to false (Trash, not permanent)",
                name, perm_delete,
            )
            perm_delete = False

        compiled.append(CompiledRule(name=name, field=field, pattern=pattern, perm_delete=perm_delete))

    return compiled


def match_message(fields: dict, rules: list[CompiledRule]) -> Optional[str]:
    """Return the name of the first rule that matches, or None.

    `fields` is a dict with keys subject/from/body (values may be empty
    strings if unavailable).
    """
    for rule in rules:
        value = fields.get(rule.field, "") or ""
        if rule.pattern.search(value):
            return rule.name
    return None


def get_rule_perm_delete(rules: list[CompiledRule], rule_name: str) -> bool:
    """Look up whether a compiled rule (by name) is configured for
    permanent deletion instead of Trash. Returns False (the safe default)
    if no rule with that name is found."""
    for rule in rules:
        if rule.name == rule_name:
            return rule.perm_delete
    return False


def rules_need_body(rules: list[CompiledRule]) -> bool:
    """Whether any enabled rule inspects the message body -- if not, sweep.py
    can skip decoding the full body for speed."""
    return any(r.field == "body" for r in rules)


# ---------------------------------------------------------------------------
# Credentials / connections
# ---------------------------------------------------------------------------

def load_credentials() -> dict:
    """Load {"email": ..., "app_password": ...} from credentials.json."""
    if not os.path.exists(CREDENTIALS_PATH):
        raise RuntimeError(
            f"No credentials.json found at {CREDENTIALS_PATH}. "
            "Create it with your Gmail address and an App Password -- see README.md."
        )
    with open(CREDENTIALS_PATH, "r", encoding="utf-8") as f:
        creds = json.load(f)

    if not creds.get("email") or not creds.get("app_password"):
        raise RuntimeError("credentials.json must contain both 'email' and 'app_password'.")

    return creds


def get_imap_connection() -> imaplib.IMAP4_SSL:
    """Open and log in an IMAP connection to Gmail."""
    creds = load_credentials()
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    imap.login(creds["email"], creds["app_password"])
    return imap


def get_smtp_connection() -> smtplib.SMTP_SSL:
    """Open and log in an SMTP connection to Gmail."""
    creds = load_credentials()
    smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
    smtp.login(creds["email"], creds["app_password"])
    return smtp


def trash_message(imap, uid: bytes) -> bool:
    """Move a message out of Spam and into Trash on Gmail.

    Uses Gmail's IMAP label extension (X-GM-LABELS) to add the \\Trash
    label and remove the \\Spam label directly, in one checked round trip
    each. This is more reliable than the classic copy-to-Trash-folder +
    flag-\\Deleted + expunge sequence, because that sequence has a silent
    failure mode: if the STORE \\Deleted call isn't checked and happens to
    fail, the message ends up copied into Trash *without* ever being
    removed from Spam -- so it appears "deleted" in the log but is still
    sitting in Spam.

    Returns True only if BOTH label operations report OK. If either one
    fails, the caller should NOT count the message as deleted.
    """
    status_add, _ = imap.uid("store", uid, "+X-GM-LABELS", "(\\Trash)")
    status_remove, _ = imap.uid("store", uid, "-X-GM-LABELS", "(\\Spam)")
    return status_add == "OK" and status_remove == "OK"


def permanently_delete_message(imap, uid: bytes) -> bool:
    """Permanently delete a message while it is in the Spam folder.

    IRREVERSIBLE -- there is no 30-day Trash recovery window for a message
    deleted this way, unlike trash_message(). Per Gmail's documented IMAP
    behavior, deleting a message (flag \\Deleted + expunge) while it is
    currently in the Spam or Trash label causes true permanent deletion;
    doing the same from any other label just removes that label and
    leaves the message in All Mail. This function assumes the caller has
    the Spam folder selected (imap.select(SPAM_FOLDER)) when it's called.

    Returns True only if BOTH the flag and expunge operations report OK.
    """
    store_status, _ = imap.uid("store", uid, "+FLAGS", "(\\Deleted)")
    if store_status != "OK":
        return False
    expunge_status, _ = imap.expunge()
    return expunge_status == "OK"


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

def parse_message(raw_bytes: bytes) -> Message:
    """Parse raw RFC822 bytes (as returned by an IMAP FETCH) into an
    email.message.Message."""
    return message_from_bytes(raw_bytes)


def _safe_decode(data: bytes, charset: str) -> str:
    """Decode bytes using the given charset, falling back gracefully if the
    charset name isn't a real Python codec.

    Some mail servers (Gmail included) label parts with placeholder charset
    names like 'unknown-8bit' or 'x-unknown' that aren't valid codecs --
    Python raises LookupError for these rather than a decode error. In that
    case, or if the named codec simply fails, fall back to utf-8 and then
    latin-1 (which never fails, since every byte value is a valid latin-1
    code point), always replacing undecodable bytes rather than crashing.
    """
    charset = charset or "utf-8"
    for candidate in (charset, "utf-8", "latin-1"):
        try:
            return data.decode(candidate, errors="replace")
        except (LookupError, UnicodeDecodeError):
            continue
    # Should be unreachable since latin-1 always succeeds, but guard anyway.
    return data.decode("latin-1", errors="replace")


def _decode_header_value(value: str) -> str:
    """Decode a possibly MIME-encoded header (e.g. '=?UTF-8?B?...?=') into
    a plain string.

    Some spam messages contain malformed encoded-words -- e.g. base64 data
    with invalid padding -- which makes Python's decode_header() raise
    HeaderParseError instead of degrading gracefully. In that case (or any
    other decoding failure), fall back to the raw header text rather than
    crashing; it's still usable for regex matching even if it
    isn't fully "cleaned" of encoding artifacts.
    """
    if not value:
        return ""
    try:
        parts = decode_header(value)
    except (HeaderParseError, ValueError):
        return value

    decoded = []
    for text, charset in parts:
        if isinstance(text, bytes):
            decoded.append(_safe_decode(text, charset))
        else:
            decoded.append(text)
    return "".join(decoded)


def _extract_body_text(msg: Message) -> str:
    """Walk a parsed email message (single-part or multipart) and return its
    text content for regex matching.

    Concatenates BOTH text/plain and text/html content -- not just
    whichever comes first. Some spam messages include a garbage/decoy
    text/plain part specifically to defeat text-based filters, while the
    actual link or content (e.g. a tracking-pixel URL) sits in the
    text/html part. Searching only "whichever part exists first" would
    miss that. Regex matching against raw HTML still works fine for
    finding a substring like a URL, since we're not trying to render it.
    """
    plain_chunks = []
    html_chunks = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            text = _safe_decode(payload, part.get_content_charset())
            if content_type == "text/plain":
                plain_chunks.append(text)
            elif content_type == "text/html":
                html_chunks.append(text)
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload is not None:
            text = _safe_decode(payload, msg.get_content_charset())
            if content_type == "text/plain":
                plain_chunks.append(text)
            elif content_type == "text/html":
                html_chunks.append(text)
            elif content_type.startswith("multipart/"):
                # Content-Type claims multipart, but Python's parser
                # couldn't actually split it into separate parts here --
                # msg.is_multipart() came back False despite the header,
                # which happens when the 'boundary' parameter is missing
                # or malformed (something spam senders do deliberately to
                # defeat content scanners). Rather than silently returning
                # an empty body, fall back to treating the raw undivided
                # content as searchable text -- it still contains the
                # actual message content, just with MIME part headers and
                # boundary delimiters mixed in as literal text alongside it.
                plain_chunks.append(text)

    text_chunks = plain_chunks + html_chunks
    combined = "\n".join(text_chunks)

    # Normalize HTML entities: &nbsp; -> non-breaking space -> regular
    # space, &amp; -> &, etc. Without this, a rule matching a plain phrase
    # like "you are our winner" fails against HTML where the spaces are
    # literally "&nbsp;" markup rather than space characters -- something
    # that renders identically to a normal space in an email client but
    # defeats a literal-text regex on the raw extracted content.
    combined = html.unescape(combined)
    combined = combined.replace("\xa0", " ")

    return combined


def email_address(from_header: str) -> str:
    """Extract the bare email address (local-part@domain) out of a raw
    From header like 'Some Name <foo@bar.com>' or a bare address, with any
    display name stripped. Falls back to the original string if parsing
    yields nothing usable. Used to isolate the sender's domain for the
    Spam Domain check (see sweep.py/domain_check.py)."""
    _, addr = parseaddr(from_header or "")
    return addr or (from_header or "")


def extract_fields(msg: Message) -> dict:
    """Pull subject/from/body out of a parsed email.message.Message.

    Spam senders produce all kinds of malformed MIME (bad encoded-word
    padding, invalid charsets, broken multipart structure, etc.), and new
    variants of "malformed" surface over time -- there's no way to
    anticipate every one in advance. Rather than chase each case
    individually, every field here is computed independently and guarded:
    if decoding one field fails in some new way we haven't seen yet, that
    field falls back to a safe default (empty string) and a warning is
    logged, but the other fields -- and the message overall -- are still
    usable rather than the whole run crashing.
    """
    try:
        subject = _decode_header_value(msg.get("Subject", ""))
    except Exception as e:
        logger.warning("Failed to decode Subject header, using raw value: %s", e)
        subject = str(msg.get("Subject", "") or "")

    try:
        from_ = _decode_header_value(msg.get("From", ""))
    except Exception as e:
        logger.warning("Failed to decode From header, using raw value: %s", e)
        from_ = str(msg.get("From", "") or "")

    try:
        body = _extract_body_text(msg)
    except Exception as e:
        logger.warning("Failed to extract message body, using empty body: %s", e)
        body = ""

    return {
        "subject": subject,
        "from": from_,
        "body": body,
    }


# ---------------------------------------------------------------------------
# Log / state persistence
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if not os.path.exists(STATE_PATH):
        return {"last_digest_run": None}
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def append_log(entry: dict) -> None:
    with open(LOG_JSONL_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_log_entries() -> list[dict]:
    if not os.path.exists(LOG_JSONL_PATH):
        return []
    entries = []
    with open(LOG_JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def clear_log() -> None:
    open(LOG_JSONL_PATH, "w", encoding="utf-8").close()


def read_error_log() -> list[str]:
    """Return each non-blank line currently in errors.log, in order."""
    if not os.path.exists(ERROR_LOG_PATH):
        return []
    with open(ERROR_LOG_PATH, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def clear_error_log() -> None:
    """Truncate errors.log after its contents have been reported in a digest.

    Safe to call even though the logging module's FileHandler keeps its own
    file descriptor open in append mode: on POSIX, append-mode writes always
    seek to end-of-file first, so a subsequent write from that handler lands
    correctly after this truncation rather than leaving a gap.
    """
    open(ERROR_LOG_PATH, "w", encoding="utf-8").close()
