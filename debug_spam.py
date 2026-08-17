"""
Diagnostic tool -- does NOT delete anything.

Connects to Spam, and for every message currently there, prints:
  - subject / from
  - content-type structure (multipart? which parts?)
  - length of extracted body
  - first 150 chars of extracted body
  - whether each enabled rule matches it
  - the hardcoded Spam Domain check's verdict (DNS-based domain
    existence check -- see domain_check.py), and what sweep.py would
    actually do as a result

Run this instead of sweep.py when a rule "isn't catching" something, to see
exactly what the code sees.

Usage:
    python3 debug_spam.py            # check all rules against all spam
    python3 debug_spam.py 42         # only inspect message index 42 in full

Version: 1.0.4

Change log:
  - v1.0.4 (2026-08-17): Synchronized module version metadata with the
    Spam Domain deletion-safety release.
"""
import sys

from common import (
    load_config,
    compile_rules,
    get_imap_connection,
    parse_message,
    extract_fields,
    match_message,
    SPAM_FOLDER,
)
from domain_check import check_domain_registration
from sweep import sender_domain, SPAM_DOMAIN_RULE_NAME


def describe_structure(msg, indent=""):
    lines = []
    if msg.is_multipart():
        lines.append(f"{indent}{msg.get_content_type()} (multipart)")
        for part in msg.get_payload():
            lines.extend(describe_structure(part, indent + "  "))
    else:
        payload = msg.get_payload(decode=True)
        size = len(payload) if payload else 0
        disp = msg.get("Content-Disposition", "")
        lines.append(f"{indent}{msg.get_content_type()} ({size} bytes) disposition={disp!r}")
    return lines


def run():
    only_index = int(sys.argv[1]) if len(sys.argv) > 1 else None

    config = load_config()
    rules = compile_rules(config)
    print(f"Loaded {len(rules)} enabled/valid rule(s): {[r.name for r in rules]}")
    print()

    imap = get_imap_connection()
    try:
        status, _ = imap.select(SPAM_FOLDER)
        if status != "OK":
            print(f"Could not select {SPAM_FOLDER} (status={status})")
            return

        status, data = imap.uid("search", None, "ALL")
        if status != "OK":
            print(f"IMAP search failed (status={status})")
            return

        uids = data[0].split()
        print(f"{len(uids)} message(s) currently in Spam.")
        print()

        for i, uid in enumerate(uids):
            if only_index is not None and i != only_index:
                continue

            status, msg_data = imap.uid("fetch", uid, "(RFC822)")
            if status != "OK" or not msg_data or msg_data[0] is None:
                print(f"[{i}] uid={uid.decode()} FAILED TO FETCH")
                continue

            try:
                msg = parse_message(msg_data[0][1])
                fields = extract_fields(msg)
                matched = match_message(fields, rules)
            except Exception as e:
                print(f"[{i}] uid={uid.decode()} FAILED TO PROCESS: {e}")
                continue

            domain = sender_domain(fields["from"])
            try:
                registration_status = check_domain_registration(domain) if domain else "unknown"
            except Exception as e:
                registration_status = f"errored: {e}"

            would_delete_as_spam_domain = registration_status == "unregistered"
            effective_verdict = SPAM_DOMAIN_RULE_NAME if would_delete_as_spam_domain else matched

            print(f"[{i}] uid={uid.decode()}")
            print(f"    Subject: {fields['subject']!r}")
            print(f"    From:    {fields['from']!r}")
            print(f"    Spam Domain check: {registration_status}"
                  + ("  <-- sweep.py would delete this, skipping config.json rules entirely" if would_delete_as_spam_domain else ""))
            print(f"    Config.json rule match: {matched}")
            print(f"    Effective verdict (what sweep.py would actually do): {effective_verdict}")
            print(f"    Body length: {len(fields['body'])}")
            print(f"    Body preview: {fields['body'][:150]!r}")

            if only_index is not None:
                print()
                print("    -- structure --")
                for line in describe_structure(msg):
                    print("    " + line)

            print()

    finally:
        try:
            imap.close()
        except Exception:
            pass
        imap.logout()


if __name__ == "__main__":
    run()
