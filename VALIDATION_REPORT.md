# DataSentinel validation report

Date: 2026-11-09. Tests use only nonfunctional, isolated pattern strings.

| Check | Actual result |
| --- | --- |
| Python compilation | Passed |
| `python3 -m unittest discover -s tests -v` | 5 passed, 0 failed, 0 skipped |
| Luhn, masking, permissions metadata, HMAC suppression, duplicate locations, scope rejection | Unit tested |
| Authorized production data or file shares | Not accessed or verified |
| Ruff/pytest | Unavailable in documented environment |
| API/dashboard/database | Not implemented in offline first milestone |

No precision, recall, false-positive rate, or compliance claim has been measured. Next validation requires an authorized, privacy-reviewed dataset and review of filesystem ACL handling.
