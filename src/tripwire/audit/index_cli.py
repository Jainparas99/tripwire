"""Build offline SQLite indexes from verified audit JSONL logs."""

from __future__ import annotations

import argparse
from pathlib import Path

from tripwire.audit.log import AuditLog


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, nargs="+", help="JSONL audit logs to index")
    args = parser.parse_args()

    for path in args.logs:
        if not path.is_file():
            parser.error(f"not an audit log: {path}")
        index = AuditLog(path).build_index()
        print(f"{path} -> {index}")


if __name__ == "__main__":
    main()
