from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .core import ScopeError, load_suppressions, scan


def main() -> None:
    parser = argparse.ArgumentParser(prog="datasentinel")
    parser.add_argument("root", type=Path, help="explicitly authorized local directory")
    parser.add_argument("--suppressions", type=Path, help="JSON list of keyed fingerprints")
    args = parser.parse_args()
    key = os.environ.get("DATASENTINEL_HMAC_KEY", "").encode()
    try:
        report = scan(args.root, key, load_suppressions(args.suppressions))
    except (ScopeError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
