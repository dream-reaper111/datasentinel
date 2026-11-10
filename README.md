# DataSentinel

DataSentinel's first milestone is an explicitly scoped, local-only sensitive-data pattern review tool. It checks bounded text files for email patterns, possible US Social Security number patterns, and Luhn-valid payment-card candidates. Reports contain **no matched values**: only keyed HMAC fingerprints, relative file paths, line numbers, file hashes, POSIX mode bits, and cautious classification. Findings are pattern candidates, not confirmed personal data or policy violations.

## Run

Python 3.12+ and the standard library are sufficient. Set a unique, private random `DATASENTINEL_HMAC_KEY` of at least 32 bytes. Keep it consistent if you need stable fingerprints across runs; rotating it changes fingerprints. Do not put the key in command arguments or commit it.

```bash
export DATASENTINEL_HMAC_KEY='replace-with-a-private-random-secret-of-at-least-32-bytes'
PYTHONPATH=. python3.12 -m datasentinel.cli /path/to/explicitly-authorized-directory > assessment.json
PYTHONPATH=. python3.12 -m datasentinel.cli --suppressions /path/to/approved-suppressions.json /path/to/explicitly-authorized-directory > assessment.json
python3.12 -m unittest discover -s tests -v
```

Suppressions are a JSON list of 64-character HMAC hex digests from prior review; no raw values are needed. A repeated candidate in another file retains a separate location with `duplicate_fingerprint: true`. The scanner does not follow symlinks, skips `.git`, `.venv`, `node_modules`, and `__pycache__`, caps depth at ten, files at 5,000, entries at 20,000, each file at 2 MiB, and total read content at 100 MiB. Binary-looking files are skipped with a reason.

The `world_readable_mode_bit` records a POSIX mode observation. It does not evaluate ACLs, effective permissions, encryption at rest, or actual unauthorized access. Paths and metadata can themselves be sensitive, so protect assessment JSON. No data is sent externally.

## Status

The bounded CLI, masking, fingerprinting, suppression, and isolated tests work. Read-only file-share connectors, document format extraction, policy management, retention analysis, authenticated API, and dashboard are not implemented. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md). The next milestone is configurable detectors and approved false-positive review records without storing raw matches.
