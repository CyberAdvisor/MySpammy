# Gmail Spam Cleaner

## Why this exists

Gmail's spam filter catches a lot, but it isn't perfect -- every few days
a legitimate email ends up misclassified as spam. The only way to catch
that is to actually look through the Spam folder, which can mean wading
through up to 100 spam messages a day just to make sure nothing real got
buried in there.

This project cuts that job down. Rules you define (regex patterns, plus a
hardcoded check for sender domains that don't even exist) identify
confirmed spam and delete it automatically, so there's far less to look
through by hand. The daily digest email goes a step further: it summarizes
what was deleted and what's still sitting in Spam, so on days when there's
nothing worth reviewing, you can tell at a glance and skip checking the
Spam folder entirely.

## What it does

Periodically scans your Gmail Spam folder, trashes messages matching
regex rules you define, logs every deletion, and emails you a daily
digest of what was deleted plus what's still sitting in Spam.

Uses plain IMAP (to read/trash Spam) and SMTP (to send the digest),
authenticated with your Gmail address and an **App Password**. No Google
Cloud Console project, no OAuth consent screen, no external dependencies --
everything runs on Python's standard library.

## 1. Turn on 2-Step Verification

App Passwords require 2-Step Verification to be enabled on your Google
account. Turn it on through your Google Account security settings.

## 2. Generate an App Password

1. Open your Google Account's App Passwords page.
2. Create a new app password (name it something like "spam-cleaner").
3. Google shows you a 16-character password once -- copy it.

This password only works for mail protocol access (IMAP/SMTP); it does not
grant access to your Google account in general and can be revoked any time
from the same page.

## 3. Make sure IMAP is enabled

Gmail settings -> "See all settings" -> Forwarding and POP/IMAP tab ->
enable IMAP access, if it isn't already.

## 4. Create credentials.json

Copy the example and fill in your address and app password:

```bash
cp credentials.json.example credentials.json
```

```json
{
  "email": "you@gmail.com",
  "app_password": "abcd efgh ijkl mnop"
}
```

`credentials.json` is gitignored -- keep it out of version control.

## 5. Edit your rules

Open `config.json`. It ships with four sample rules, all `"enabled": false`,
purely to show the format -- they will never run as-is.

Each rule matches text against subject/from/to/body via regex:

```json
{
  "name": "unique_short_name",
  "enabled": true,
  "field": "subject",
  "pattern": "some.*regex",
  "perm_delete": false
}
```

- `field`: one of `subject`, `from`, `to`, `body`
- `pattern`: a Python regex, matched case-insensitively, matched anywhere in the field (not anchored to the whole string)
- `enabled`: set `false` to keep a rule around without running it
- `perm_delete` (optional, defaults to `false`): if `true`, a match is **permanently deleted** instead of moved to Trash -- no 30-day recovery window. Leave this off (or omit it) unless you're confident a rule can't produce a false positive; an invalid value (anything that isn't `true`/`false`) is treated as `false` rather than erroring, so a typo here can never accidentally escalate to permanent deletion.
- `last_hit` (auto-managed, do not set by hand): the date (Mountain Time) `sweep.py` last saw this rule match a message. Added automatically the first time a rule matches, and updated on every match after that. `config.json` is only rewritten on days a rule actually matched, so a rule with an old (or missing) `last_hit` is a rule you can review for possibly being stale/no-longer-needed. This does not apply to the hardcoded Spam Domain check (section 6), which has no `config.json` entry to update.

**Gotcha:** the `from` and `to` fields are the raw header, e.g. `Some Name <a@domain.com>` --
not just the email address. If you anchor a regex pattern with `$` expecting it to
end at the domain, it won't match, because of the trailing `>`. Leave patterns
unanchored (drop `$`) unless you're deliberately matching the trailing angle bracket.

Also set `digest_recipient` to your real email address (it starts as the placeholder `you@example.com`, which the digest script refuses to run against).

**Top-level settings (outside `rules`):**

- `digest_recipient`: your real email address, as above.
- `rule_deleted_summary_only` (optional, defaults to `false`): if `true`, the digest's **Rule Deleted** section shows a per-rule count breakdown (e.g. `Top Stories: 2`) instead of itemized `From`/`Subject` detail for each match. Only affects **Rule Deleted** -- **Rule Trashed** is always itemized regardless of this setting.

## 6. Automatic "Spam Domain" check (always runs; deletion type is configurable)

Before any `config.json` rule is checked, `sweep.py` looks up the sender's
domain via DNS (see `domain_check.py`). If the domain **doesn't resolve at
all** -- no DNS record exists, or the domain has no dot in it and so can't
be a real domain to begin with -- the message is immediately logged with
the rule name `Spam Domain` and deleted. `config.json` rules are skipped
entirely for that message.

The check doesn't look up the sender's full domain as written -- it first
reduces it to the last two dot-separated labels (e.g. `mail.spam.xyz`
becomes `spam.xyz`) and checks that instead, on the assumption this is the
registrable domain. **Known limitation:** this reduction doesn't account
for multi-part TLDs like `.co.uk` -- for a domain such as
`example.co.uk`, it would incorrectly take `co.uk` as the "registrable"
part rather than `example.co.uk`, which can produce an incorrect DNS
check for such domains. This is a deliberate simplification (implementing
the full public suffix list was judged unnecessary complexity for a
diagnostic check) and is worth knowing about if you see an unexpected
result for a domain with a compound TLD.

Domain check results are cached for the duration of a single `sweep.py`
run (many spam messages in one run often share a sender domain), so a
domain's status is only looked up once per run even if it appears in
multiple messages.

**This check itself cannot be turned off** -- it always runs before any
config.json rule. But whether it permanently deletes or moves to Trash is
controlled by the top-level `spam_domain_perm_delete` setting in
`config.json`:

```json
{
  "spam_domain_perm_delete": false
}
```

- `false` (the default): matches move to **Trash** (30-day recovery window).
- `true`: matches are **permanently deleted** immediately (no Trash, no recovery).

An invalid value (anything that isn't `true`/`false`) is treated as
`false`, the safer option -- same pattern as the per-rule `perm_delete`
setting.

It exists because a `From:` header referencing a domain that doesn't
resolve at all is close to unambiguous evidence of spam -- no real sender
uses a domain that doesn't exist -- and testing showed it catches the
large majority of "made up domain" spam that regex rules alone struggle
to catch reliably.

This originally used RDAP (the structured WHOIS replacement) instead of
DNS, but RDAP required a slow HTTP round trip per domain and was subject
to rate limiting that occasionally caused real spam to be missed on one
sweep pass. Comparing DNS results against RDAP's verdict across 50 real
spam messages showed zero disagreements, so the check now uses plain DNS
resolution instead -- standard library only, no rate limits, and much
faster.

**Known limitation:** a domain can be legitimately registered and used
purely for email while having no DNS A record at all (e.g. a company that
sends mail from a domain but hosts no website on it). Such a domain would
show as "doesn't resolve" here even though it's completely real. This
tradeoff was accepted after the empirical comparison above showed no
disagreements in practice, but it's worth knowing about if you ever see
an unexpected deletion -- and is exactly why `spam_domain_perm_delete`
defaults to `false` (Trash, recoverable) rather than `true`.

**Safety property:** if the DNS check is inconclusive for any reason, the
message is **not** flagged as spam on that basis. It falls through to
normal `config.json` rule matching instead, exactly as if the check hadn't
run. A check failure never causes a deletion by itself.

You can see what this check decides for messages currently in Spam by
running `debug_spam.py`, which prints the Spam Domain check's verdict for
every message alongside everything else it shows.

`debug_spam.py` takes an optional message index:

```bash
python3 debug_spam.py       # check all rules against all spam
python3 debug_spam.py 42    # inspect only message index 42, in full
```

Passing an index limits output to that one message and adds a MIME
structure breakdown (content-type of every part, byte size, and
disposition) -- useful for seeing exactly how a message is put together
when a body-based rule "isn't catching" something.

## 7. Common regex rule examples

Reference patterns to adapt, organized by field. All match case-insensitively already (rules compile with `re.IGNORECASE`), and match anywhere in the field unless anchored.

**Subject**

```json
{"name": "prize_bait", "enabled": true, "field": "subject", "pattern": "free.*(gift|prize|money)"}
{"name": "won_notification", "enabled": true, "field": "subject", "pattern": "you.?ve won"}
{"name": "urgent_pressure", "enabled": true, "field": "subject", "pattern": "urgent.*action.*required"}
{"name": "fake_payment", "enabled": true, "field": "subject", "pattern": "\\$\\d+[,.]?\\d*\\s*(million|k|reward)"}
{"name": "account_verify", "enabled": true, "field": "subject", "pattern": "verify your account"}
{"name": "explicit_content", "enabled": true, "field": "subject", "pattern": "fuck|pussy|erection secret"}
```

**From**

```json
{"name": "known_spam_domains", "enabled": true, "field": "from", "pattern": "@(shady-domain1|shady-domain2)\\.(com|net)"}
{"name": "suspicious_tld", "enabled": true, "field": "from", "pattern": "@.*\\.(xyz|top|click|info)"}
```

**Body**

```json
{"name": "click_here_bait", "enabled": true, "field": "body", "pattern": "click here (now|immediately|to)"}
{"name": "crypto_wallet", "enabled": true, "field": "body", "pattern": "bitcoin.*(wallet|payment|address)"}
{"name": "one_time_offer", "enabled": true, "field": "body", "pattern": "one.?time (offer|deal)"}
{"name": "decoy_filler_text", "enabled": true, "field": "body", "pattern": "Top Stories of the Day:.*-----"}
```

That last one (`decoy_filler_text`) is worth calling out: some spam includes a garbage/word-salad `text/plain` part specifically to defeat text-based filters, while the real payload (a tracking link, the actual pitch) sits in the `text/html` part. Since `body` extraction combines both parts (see the Gotcha note above), a rule targeting the decoy text itself still catches these reliably.

Tips for writing your own:

- `\b` (word boundary) keeps a term from matching inside unrelated words -- `\bwin\b` won't match "window."
- `.*` between words allows anything (including nothing) in between -- `free.*prize` matches "free prize," "free trip and prize," etc.
- `|` means "or" -- group with parentheses: `(bitcoin|crypto|wallet)`.
- Escape literal special characters: `.` -> `\.`, `$` -> `\$`, `?` -> `\?`. In JSON, backslashes need to be doubled (`\\.` not `\.`).
- Start narrow. Run `debug_spam.py` periodically to see what's still sitting in Spam and what patterns show up repeatedly, then add rules incrementally rather than writing broad catch-alls that risk false positives.

## 8. Test manually before automating

From the project folder:

```bash
cd ~/Documents/Projects/MySpammy
python3 sweep.py   # scans spam, trashes matches, prints a summary
python3 digest.py  # sends the digest email immediately
```

Check `errors.log` if anything looks off.

Once testing is complete, commit and push your changes, then set up (or confirm) the Shortcuts automations described in section 9.

## 9. Project location and development workflow

The project lives in a single folder on the Mac:

```text
~/Documents/Projects/MySpammy
```

This folder is connected to GitHub and is where you edit, test, commit,
push, and run the scheduled Shortcuts automations from -- there's no
separate copy.

### Clone the project

Clone the GitHub repository into the Projects directory:

```bash
cd ~/Documents/Projects
git clone https://github.com/CyberAdvisor/MySpammy.git
```

This creates:

```text
~/Documents/Projects/MySpammy
```

Make all code, configuration, and documentation changes in this directory.

The normal workflow is:

1. Make changes in `~/Documents/Projects/MySpammy`.
2. Test the changes there (see section 8).
3. Commit and push the changes to GitHub.

The next scheduled Shortcuts run automatically picks up the changes, since it runs from this same folder.

## 10. Schedule with Shortcuts

Both the sweep and the digest run as **once-daily** automations using
macOS's built-in Shortcuts app -- no third-party scheduler required.
(Shortcuts' Time of Day automations only support Daily/Weekly/Monthly
repeat, so sub-daily scheduling isn't an option here.)

Shortcuts should run the project from `~/Documents/Projects/MySpammy` -- the
same folder used for development and Git.

### One-time setup

1. Open **Shortcuts**.
2. Menu bar: **Shortcuts** -> **Settings** -> **Advanced** -> turn on
   **Allow Running Scripts**.

### Create the sweep shortcut

1. Click **+** for a new shortcut.
2. Search the action library for **Run Shell Script**, drag it into the workflow.
3. Paste into the script box:

   ```bash
   cd ~/Documents/Projects/MySpammy && /Library/Developer/CommandLineTools/usr/bin/python3 sweep.py >> run.log 2>&1
   ```

4. Leave **Shell** set to `/bin/zsh`.
5. Rename the shortcut (top-left) to **Spam Sweep**.
6. Close the editor.

### Create the digest shortcut

Repeat the same steps, naming it **Spam Digest**, using:

```bash
cd ~/Documents/Projects/MySpammy && /Library/Developer/CommandLineTools/usr/bin/python3 digest.py >> run.log 2>&1
```

### Schedule them

1. In Shortcuts, click the **Automation** tab in the sidebar.
2. Click **+** -> **Create Personal Automation** -> **Time of Day**.
3. Set a time, **Repeat: Daily**.
4. **Next** -> add action **Run Shortcut** -> pick **Spam Sweep**.
5. Turn **off** "Ask Before Running" so it runs silently.
6. Repeat for **Spam Digest**, at a later time on the same day, also Daily.

**Verifying it actually ran:** these automations run silently in the
background with no visible confirmation. Check
`~/Documents/Projects/MySpammy/run.log` after a scheduled time passes to
confirm the script executed.

**`run.log` resets itself once a day.** Every `sweep.py` run appends a
line, but `digest.py` clears the file at the start of each of its runs
before adding its own completion line -- so `run.log` never grows
unbounded, and after a digest run it'll show just that one fresh entry
rather than the whole day's accumulated sweep history.

## Files

| File | Purpose |
|---|---|
| `common.py` | Shared logic: config loading, rule matching, IMAP/SMTP connections, message parsing |
| `VERSION` | Single project-wide version number (e.g. `1.0.1`), bumped on any release regardless of which files changed. Matches the git tag for that release (e.g. `v1.0.1`) and the version cited in each changed file's own `Change log:` docstring entry. |
| `domain_check.py` | DNS-based domain existence check for sender domains -- used by `sweep.py` for the hardcoded Spam Domain check, and by `debug_spam.py` |
| `debug_spam.py` | Diagnostic tool: shows what's extracted from each spam message, whether rules match, and the Spam Domain check's verdict -- does NOT delete anything |
| `sweep.py` | Scans Spam and processes matching messages each time it is run. Under the recommended Shortcuts configuration, it runs once daily. It runs the hardcoded Spam Domain check first, then `config.json` rules. |
| `digest.py` | Sends the daily summary email, normally run once a day |
| `Spam Sweep.sh` | Shell wrapper used by Shortcuts to run `sweep.py` from `~/Documents/Projects/MySpammy` |
| `Spam Digest.sh` | Shell wrapper used by Shortcuts to run `digest.py` from `~/Documents/Projects/MySpammy` |
| `config.json` | Your editable rules and digest recipient (does not affect the hardcoded Spam Domain check) |
| `credentials.json` | Your Gmail address + app password (create from `credentials.json.example`, do not share or commit) |
| `log.jsonl` | Deletion log since the last digest (auto-managed) |
| `state.json` | Tracks last digest run time (auto-managed) |
| `errors.log` | Connection/rule errors (auto-managed) |
| `run.log` | Sweep/digest completion log written by your scheduler's shell redirect (not by the Python scripts directly) -- reset by `digest.py` at the start of each of its runs, so it never grows unbounded |

## Safety notes

- **Config.json rule matches go to Trash by default** (30-day recovery window) -- a rule that's too broad is recoverable, not catastrophic. A rule can opt into **permanent deletion** instead by setting `"perm_delete": true` (see section 5); do this only for rules you're confident can't produce a false positive.
- **The hardcoded Spam Domain check always runs**, but whether it permanently deletes or moves to Trash is controlled by `spam_domain_perm_delete` in `config.json` (defaults to `false`/Trash). Permanent deletion has no recovery window; Trash gives 30 days.
- `log.jsonl` records `"deletion_type": "trash"` or `"permanent"` for every deletion. The digest email lists sections in this order: **Errors**, **Remaining**, **Rule Trashed**, **Rule Deleted**, then a **DNS Deleted** or **DNS Trashed** section for the hardcoded check depending on the active `spam_domain_perm_delete` setting (both only appear together if you changed that setting mid-period). **Rule Deleted** is itemized by default, or shown as a per-rule count breakdown if `rule_deleted_summary_only` is `true` (see section 5); **Rule Trashed** is always itemized.
- A rule with invalid `field` or unparseable regex is skipped and logged to `errors.log`, not silently ignored or crash-inducing.
- The hardcoded Spam Domain check (see section 6) only ever deletes on an explicit "this domain doesn't resolve" result -- a failed or inconclusive check never triggers a deletion by itself.
- `credentials.json` grants mail access to your account -- keep it out of version control (see `.gitignore`) and revoke the app password from your Google account if it's ever exposed.