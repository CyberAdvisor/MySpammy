"""
Sends a daily digest email with these sections:
  - DNS Deleted and/or DNS Trashed: since spam_domain_perm_delete is a
    single global setting, normally only one of these will have any
    activity in a given digest period -- that one section is shown alone.
    Both appear together only if the setting was changed mid-period. If
    neither has activity, the section matching the currently active
    setting is shown at 0, so the digest still reflects which mode is in
    effect.
  - Rule Deleted: config.json rule matches with "perm_delete": true
    (permanently deleted, condensed to one line each: rule/From/Subject)
  - Rule Trashed: config.json rule matches without perm_delete (moved to
    Trash, same condensed format)
  - Remaining: messages still sitting in Spam (condensed: From/Subject)
  - Errors: any errors.log entries since the last digest

Intended to run once every 24 hours via a scheduled automation, at a fixed time.
"""
from datetime import datetime, timezone
from email.mime.text import MIMEText

from common import (
    load_config,
    get_spam_domain_perm_delete,
    load_credentials,
    get_imap_connection,
    get_smtp_connection,
    parse_message,
    extract_fields,
    read_log_entries,
    clear_log,
    read_error_log,
    clear_error_log,
    clear_run_log,
    load_state,
    save_state,
    logger,
    local_timestamp,
    MOUNTAIN_TZ,
    SPAM_FOLDER,
)
from sweep import SPAM_DOMAIN_RULE_NAME

MAX_REMAINING_LISTED = 200  # sanity cap so a huge spam folder doesn't blow up the email


def list_current_spam_summaries(imap) -> list[dict]:
    """Fetch subject/from for messages currently in Spam."""
    summaries = []

    status, _ = imap.select(SPAM_FOLDER)
    if status != "OK":
        raise RuntimeError(f"Could not select {SPAM_FOLDER} (status={status})")

    status, data = imap.uid("search", None, "ALL")
    if status != "OK":
        raise RuntimeError(f"IMAP search failed (status={status})")

    uids = data[0].split()[:MAX_REMAINING_LISTED]

    for uid in uids:
        status, msg_data = imap.uid("fetch", uid, "(RFC822)")
        if status != "OK" or not msg_data or msg_data[0] is None:
            logger.warning("Failed to fetch spam message UID %s for digest", uid.decode())
            continue

        try:
            msg = parse_message(msg_data[0][1])
            fields = extract_fields(msg)
        except Exception as e:
            logger.warning("Failed to process spam message UID %s for digest, skipping: %s", uid.decode(), e)
            continue

        summaries.append({
            "from": fields["from"],
            "subject": fields["subject"],
        })

    return summaries


def build_digest_body(
    deleted_entries: list[dict],
    remaining: list[dict],
    error_lines: list[str],
    spam_domain_perm_delete: bool = False,
) -> str:
    lines = []
    lines.append(f"Gmail Spam Cleaner -- Daily Digest ({local_timestamp()})")
    lines.append("")

    dns_deleted_entries = [
        e for e in deleted_entries
        if e.get("matched_rule") == SPAM_DOMAIN_RULE_NAME and e.get("deletion_type") == "permanent"
    ]
    dns_trashed_entries = [
        e for e in deleted_entries
        if e.get("matched_rule") == SPAM_DOMAIN_RULE_NAME and e.get("deletion_type") != "permanent"
    ]
    rule_deleted_entries = [
        e for e in deleted_entries
        if e.get("matched_rule") != SPAM_DOMAIN_RULE_NAME and e.get("deletion_type") == "permanent"
    ]
    rule_trashed_entries = [
        e for e in deleted_entries
        if e.get("matched_rule") != SPAM_DOMAIN_RULE_NAME and e.get("deletion_type") != "permanent"
    ]

    def dns_section(label: str, entries: list[dict]) -> None:
        lines.append(f"{label}: {len(entries)}")
        lines.append("-" * 50)
        if entries:
            count = len(entries)
            noun = "email" if count == 1 else "emails"
            lines.append(f"{count} spam {noun} from nonexistent sender domains ({SPAM_DOMAIN_RULE_NAME} check)")
        else:
            lines.append("(none)")
        lines.append("")

    # spam_domain_perm_delete is a single global setting, so in almost every
    # digest period only ONE of DNS Deleted/DNS Trashed will ever be
    # nonzero -- showing both every time means one is "(none)" nearly
    # always, which is just clutter. Only show both when a mid-period
    # config change actually produced entries of both types; otherwise
    # show a single section for whichever type is relevant.
    if dns_deleted_entries and dns_trashed_entries:
        dns_section("DNS Deleted", dns_deleted_entries)
        dns_section("DNS Trashed", dns_trashed_entries)
    elif dns_deleted_entries:
        dns_section("DNS Deleted", dns_deleted_entries)
    elif dns_trashed_entries:
        dns_section("DNS Trashed", dns_trashed_entries)
    else:
        # No DNS-caught spam this period -- show the section matching the
        # currently active setting, so the digest still reflects which
        # mode is in effect even with zero activity.
        label = "DNS Deleted" if spam_domain_perm_delete else "DNS Trashed"
        dns_section(label, [])

    # Rule Deleted -- config.json matches with perm_delete: true (permanent, no Trash recovery)
    lines.append(f"Rule Deleted: {len(rule_deleted_entries)}")
    lines.append("-" * 50)
    if rule_deleted_entries:
        for e in rule_deleted_entries:
            lines.append(f"rule={e['matched_rule']} | From: {e['from']} | Subject: {e['subject']}")
    else:
        lines.append("(none)")
    lines.append("")

    # Rule Trashed -- config.json matches with perm_delete: false/default (recoverable in Trash)
    lines.append(f"Rule Trashed: {len(rule_trashed_entries)}")
    lines.append("-" * 50)
    if rule_trashed_entries:
        for e in rule_trashed_entries:
            lines.append(f"rule={e['matched_rule']} | From: {e['from']} | Subject: {e['subject']}")
    else:
        lines.append("(none)")
    lines.append("")

    # Remaining -- still sitting in Spam
    lines.append(f"Remaining: {len(remaining)}")
    lines.append("-" * 50)
    if remaining:
        for r in remaining:
            lines.append(f"From: {r['from']} | Subject: {r['subject']}")
    else:
        lines.append("(none)")
    lines.append("")

    # Errors -- unchanged
    lines.append(f"Errors in the last 24 hours: {len(error_lines)}")
    lines.append("-" * 50)
    if error_lines:
        for line in error_lines:
            lines.append(f"  {line}")
    else:
        lines.append("(none)")

    return "\n".join(lines).rstrip() + "\n"


def send_digest(sender_email: str, recipient: str, body: str):
    message = MIMEText(body)
    message["From"] = sender_email
    message["To"] = recipient
    message["Subject"] = f"Spam Cleaner Digest - {datetime.now(MOUNTAIN_TZ).strftime('%Y-%m-%d')}"

    smtp = get_smtp_connection()
    try:
        smtp.sendmail(sender_email, [recipient], message.as_string())
    finally:
        smtp.quit()


def run():
    config = load_config()
    recipient = config.get("digest_recipient")
    if not recipient or recipient == "you@example.com":
        raise SystemExit("Set a real 'digest_recipient' in config.json before running digest.py.")

    creds = load_credentials()

    # Reset run.log for this run -- see clear_run_log()'s docstring for why
    # this is safe even though the shell wrapper's own stdout redirect for
    # this process is a separate, already-open append-mode file handle.
    clear_run_log()

    # Capture errors.log before this run's own operations can add to it, so
    # what's reported is errors accumulated since the last digest (mostly
    # from sweep.py's daily run), not from this digest run itself.
    error_lines = read_error_log()

    imap = get_imap_connection()
    try:
        remaining = list_current_spam_summaries(imap)
    finally:
        try:
            imap.close()
        except Exception:
            pass
        imap.logout()

    deleted_entries = read_log_entries()

    body = build_digest_body(deleted_entries, remaining, error_lines, get_spam_domain_perm_delete(config))
    send_digest(creds["email"], recipient, body)

    clear_log()
    clear_error_log()
    state = load_state()
    state["last_digest_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

    print(
        f"[{local_timestamp()}] Digest sent to {recipient}: {len(deleted_entries)} deleted, "
        f"{len(remaining)} remaining, {len(error_lines)} error(s)."
    )


if __name__ == "__main__":
    run()
