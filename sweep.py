"""
Scans the Gmail Spam folder over IMAP and deletes any message matching an
enabled rule in config.json. Intended to run once a day via a scheduled
automation.

Before config.json rules are checked at all, every message's sender domain
is checked via DNS: if the domain is confirmed NOT to resolve (no A record
at all, or the domain has no dot and so can't be a real domain), the
message is hardcoded-flagged as "Spam Domain" and deleted -- this check
itself always runs and cannot be turned off via config.json. Whether the
match is permanently deleted or moved to Trash is controlled by the
top-level "spam_domain_perm_delete" setting (default false -> Trash;
see common.get_spam_domain_perm_delete). If the check is inconclusive
(DNS error, unexpected failure), the message is NOT flagged on that basis
alone; it falls through to normal config.json rule matching instead. A
lookup failure must never cause a deletion by itself.

Messages matched by a config.json rule go to Trash by default (see
common.trash_message), giving a 30-day recovery window in case a rule is
too broad. A rule can opt into permanent deletion instead by setting
"perm_delete": true (see common.get_rule_perm_delete).

Every deletion is appended to log.jsonl for digest.py to summarize later.
Connection and per-message errors go to errors.log rather than stopping
the run.
"""
from datetime import datetime, timezone

from common import (
    load_config,
    compile_rules,
    get_imap_connection,
    parse_message,
    extract_fields,
    match_message,
    get_rule_perm_delete,
    get_spam_domain_perm_delete,
    email_address,
    trash_message,
    permanently_delete_message,
    append_log,
    logger,
    local_timestamp,
    SPAM_FOLDER,
)
from domain_check import check_domain_registration

SPAM_DOMAIN_RULE_NAME = "Spam Domain"


def sender_domain(from_header: str) -> str:
    """Extract the domain portion of the sender's email address, or ''
    if it can't be determined."""
    addr = email_address(from_header)
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1]


def run():
    config = load_config()
    rules = compile_rules(config)
    spam_domain_perm_delete = get_spam_domain_perm_delete(config)

    if not rules:
        logger.warning("No enabled/valid config.json rules found -- only the hardcoded Spam Domain check will run.")

    imap = get_imap_connection()
    deleted_count = 0
    total_count = 0

    try:
        status, _ = imap.select(SPAM_FOLDER)
        if status != "OK":
            raise RuntimeError(f"Could not select {SPAM_FOLDER} (status={status})")

        status, data = imap.uid("search", None, "ALL")
        if status != "OK":
            raise RuntimeError(f"IMAP search failed (status={status})")

        uids = data[0].split()
        total_count = len(uids)

        for uid in uids:
            status, msg_data = imap.uid("fetch", uid, "(RFC822)")
            if status != "OK" or not msg_data or msg_data[0] is None:
                logger.warning("Failed to fetch message UID %s", uid.decode())
                continue

            try:
                raw_bytes = msg_data[0][1]
                msg = parse_message(raw_bytes)
                fields = extract_fields(msg)
            except Exception as e:
                # Belt and suspenders: extract_fields already guards each
                # field individually, but this catches anything still
                # unforeseen (e.g. a malformed MIME structure that breaks
                # parse_message itself) so one bad message can't abort the
                # whole run.
                logger.warning("Failed to process message UID %s, skipping: %s", uid.decode(), e)
                continue

            # Hardcoded check first, ahead of any config.json rule. Only an
            # explicit "unregistered" result (domain doesn't resolve) counts
            # -- "unknown" (check failed for any other reason) falls through
            # to normal rule matching below rather than being treated as spam.
            domain = sender_domain(fields["from"])
            try:
                registration_status = check_domain_registration(domain) if domain else "unknown"
            except Exception as e:
                logger.warning("Domain check errored unexpectedly for domain '%s': %s", domain, e)
                registration_status = "unknown"

            is_spam_domain = registration_status == "unregistered"
            if is_spam_domain:
                matched_rule = SPAM_DOMAIN_RULE_NAME
            else:
                matched_rule = match_message(fields, rules)

            if matched_rule:
                # Spam Domain matches permanently delete by default, but
                # respect the global "spam_domain_perm_delete" override if
                # set to false in config.json. Config.json rule matches go
                # to Trash by default, but permanently delete instead if
                # that specific rule has "perm_delete": true.
                if is_spam_domain:
                    should_perm_delete = spam_domain_perm_delete
                else:
                    should_perm_delete = get_rule_perm_delete(rules, matched_rule)

                if should_perm_delete:
                    deletion_succeeded = permanently_delete_message(imap, uid)
                    deletion_type = "permanent"
                else:
                    deletion_succeeded = trash_message(imap, uid)
                    deletion_type = "trash"

                if not deletion_succeeded:
                    logger.warning(
                        "Failed to delete message UID %s (%s deletion did not confirm OK) -- "
                        "not counted as deleted", uid.decode(), deletion_type,
                    )
                    continue

                append_log({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "uid": uid.decode(),
                    "from": fields["from"],
                    "subject": fields["subject"],
                    "matched_rule": matched_rule,
                    "deletion_type": deletion_type,
                })
                deleted_count += 1

    finally:
        try:
            imap.close()
        except Exception:
            pass
        imap.logout()

    print(f"[{local_timestamp()}] Sweep complete: {deleted_count} message(s) deleted out of {total_count} in spam.")


if __name__ == "__main__":
    run()
