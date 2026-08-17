# MySpammy contributor guide

## Project shape

MySpammy is a small, macOS-oriented Gmail Spam cleaner written for the
Python standard library. `sweep.py` reads Gmail Spam over IMAP and applies
the DNS-based sender-domain check before configured regex rules. `digest.py`
emails the daily report; `debug_spam.py` is the read-only diagnostic entry
point. Shared configuration, IMAP/SMTP, MIME parsing, logging, and persistence
live in `common.py`.

The user runs the scripts from this repository through daily macOS Shortcuts.
There are no external Python dependencies and no automated test suite.

## Files and configuration

- Treat `config.json` and `credentials.json` as private, local runtime data.
  They are intentionally ignored. Never print, commit, or copy their contents;
  change them only when the task explicitly asks for a local configuration
  change. Update the tracked `*.example` file when its schema changes.
- `log.jsonl`, `state.json`, `errors.log`, and `run.log` are generated runtime
  files. Do not add them to version control or rely on their current contents
  in code or documentation.
- Keep paths centralized through the `*_PATH` constants in `common.py`; scripts
  must work regardless of the shell's current directory.
- `README.md` is the user-facing setup and operating guide. Update it with any
  behavior, config, scheduler, or safety change. Verify safety claims against
  the current implementation—some older prose/docstrings may describe an
  earlier deletion policy.
- `VERSION` and git tags use `vX.Y.Z`, and the git tag must match the GitHub
  release version. Every code change is a versioned release: increment
  `VERSION`, create the matching `vX.Y.Z` tag when publishing, and add a
  `Change log:` entry using that version to every changed source file. Include
  the date and a concise description of the behavior change in each entry.
- Before pushing code to GitHub, document the change in the GitHub-facing
  change notes (commit message and, when applicable, pull request/release
  description). The notes must identify the version and summarize the user-
  visible behavior, safety impact, and verification performed.

## Safety-critical behavior

- Do not run `sweep.py` or `digest.py` during routine development: they access
  the live Gmail account and can delete mail or send email. Use
  `debug_spam.py` only when live, read-only account access is explicitly in
  scope.
- Preserve the fail-safe rule: malformed mail, failed IMAP operations, invalid
  regexes/config values, and inconclusive DNS lookups must be logged and
  skipped—not treated as a match or a deletion.
- Preserve the distinction between recoverable Trash moves and irreversible
  permanent deletion. Configuration parsing must default to the safer Trash
  behavior for invalid or omitted boolean values, and deletion counts/logs must
  be recorded only after IMAP confirms success.
- The Spam Domain check takes precedence over regex rules. If changing that
  check, keep its per-run cache and ensure only an explicit `"unregistered"`
  verdict can trigger it; `"unknown"` must fall through to normal matching.

## Implementation conventions

- Target the Python version bundled with macOS Command Line Tools (currently
  Python 3.9); retain standard-library-only dependencies unless a task
  explicitly authorizes a dependency change.
- Handle bad email/MIME input defensively and continue processing other
  messages. Use the shared logger for operational errors.
- Rule ordering is meaningful: `match_message()` returns the first matching
  configured rule. Keep regex matching case-insensitive and avoid changing
  configuration semantics incidentally.
- When adding a configuration setting, validate its type explicitly and choose
  the safe default. Document the setting in both `README.md` and
  `config.json.example`.

## Verification

For code-only changes, at minimum compile all entry points without writing to
the protected macOS bytecode cache:

```bash
PYTHONPYCACHEPREFIX=/tmp/myspammy-pycache python3 -m py_compile \
  common.py sweep.py digest.py domain_check.py debug_spam.py
```

Do not make networked Gmail calls as a verification step unless the task
explicitly authorizes them. Before finishing, inspect `git diff --check` and
`git status --short`; preserve unrelated local changes, including locally
deleted scheduler wrapper files.
