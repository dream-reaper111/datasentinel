"""Bounded local-only pattern review; matched values never leave process memory."""

from __future__ import annotations

import bisect
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 100 * 1024 * 1024
MAX_FILES = 5000
MAX_ENTRIES = 20000
MAX_FINDINGS = 10000
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}(?![\w.-])")
SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}


class ScopeError(ValueError):
    pass


def luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def load_suppressions(path: Path | None) -> set[str]:
    if path is None:
        return set()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ScopeError("suppression file must be a regular JSON file of at most 1 MiB")
    try:
        values = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScopeError("invalid suppression JSON") from exc
    if not isinstance(values, list) or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in values):
        raise ScopeError("suppressions must be a list of HMAC hex digests")
    return set(values)


def _candidates(text: str):
    for name, pattern in (("email_pattern", EMAIL), ("possible_ssn", SSN), ("luhn_card_candidate", CARD)):
        for match in pattern.finditer(text):
            value = match.group()
            if name == "luhn_card_candidate" and not luhn(value):
                continue
            yield name, value, match.start()


def scan(root: Path, secret: bytes, suppressions: set[str] | None = None) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ScopeError("explicit scope must be a real directory")
    if len(secret) < 32:
        raise ScopeError("HMAC key must contain at least 32 bytes")
    root = root.resolve(strict=True)
    suppressed = suppressions or set()
    findings = []
    issues = []
    files_examined = 0
    entries = 0
    total_bytes = 0
    unique_locations: set[tuple[str, str]] = set()
    seen_fingerprints: set[str] = set()
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        directory_names[:] = sorted(name for name in directory_names
                                    if name not in SKIP_DIRS and not (here / name).is_symlink()
                                    and len((here / name).relative_to(root).parts) <= 10)
        entries += len(directory_names) + len(file_names)
        if entries > MAX_ENTRIES:
            raise ScopeError("directory entry limit exceeded")
        for name in sorted(file_names):
            path = here / name
            if path.is_symlink() or not path.is_file():
                continue
            files_examined += 1
            if files_examined > MAX_FILES:
                raise ScopeError("file count limit exceeded")
            relative = str(path.relative_to(root))
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as stream:
                    metadata = os.fstat(stream.fileno())
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    raw = stream.read(MAX_FILE + 1)
            except OSError:
                issues.append({"path": relative, "reason": "unreadable file"})
                continue
            if len(raw) > MAX_FILE:
                issues.append({"path": relative, "reason": "file exceeds 2 MiB"})
                continue
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL:
                raise ScopeError("total read limit exceeded")
            if b"\x00" in raw[:4096]:
                issues.append({"path": relative, "reason": "binary file skipped"})
                continue
            text = raw.decode("utf-8", errors="replace")
            line_offsets = [0] + [i + 1 for i, char in enumerate(text) if char == "\n"]
            for kind, value, offset in _candidates(text):
                normalized = "".join(char for char in value if char.isdigit()) if kind != "email_pattern" else value.lower()
                digest = hmac.new(secret, (kind + ":" + normalized).encode(), hashlib.sha256).hexdigest()
                if digest in suppressed or (digest, relative) in unique_locations:
                    continue
                unique_locations.add((digest, relative))
                duplicate_fingerprint = digest in seen_fingerprints
                seen_fingerprints.add(digest)
                findings.append({"kind": kind, "fingerprint_hmac_sha256": digest,
                                 "relative_path": relative, "line": bisect.bisect_right(line_offsets, offset),
                                 "duplicate_fingerprint": duplicate_fingerprint,
                                 "file_sha256": hashlib.sha256(raw).hexdigest(),
                                 "mode_octal": format(stat.S_IMODE(metadata.st_mode), "04o"),
                                 "world_readable_mode_bit": bool(metadata.st_mode & stat.S_IROTH),
                                 "classification": "high_review" if kind != "email_pattern" else "medium_review",
                                 "interpretation": "pattern candidate only; content and access require authorized review"})
                if len(findings) > MAX_FINDINGS:
                    raise ScopeError("finding count limit exceeded")
    return {"schema_version": 1, "scope": str(root), "files_examined": files_examined,
            "bytes_read": total_bytes, "findings": findings, "issues": issues,
            "privacy_note": "raw matches are neither stored nor returned; HMAC key must remain private"}
