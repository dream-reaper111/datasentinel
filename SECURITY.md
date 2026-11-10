# Security model

Scan only paths you are authorized to assess. The application performs no network requests, writes no target files, and never exports raw matches. Keep `DATASENTINEL_HMAC_KEY` private and unique; a shared or exposed key weakens fingerprint privacy. Do not place real sensitive values in test fixtures or issue reports.

Pattern matches are candidates. The current CLI cannot prove a file contains regulated data, is effectively world-readable under ACLs, or violates retention/encryption policy. The JSON report includes paths and hashes and must be protected. No API, tenant access control, or persistent audit store exists in this offline milestone.
