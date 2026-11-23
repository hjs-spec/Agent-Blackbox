"""CLI for Agent Blackbox."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import AgentBlackbox
from .store import InvalidJournal


EXIT_CODES = {
    "verified": 0,
    "not_found": 3,
    "unknown_key": 4,
    "invalid_record": 5,
    "storage_error": 6,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agent Blackbox incident review utility")
    parser.add_argument("--storage", default="./blackbox_logs", help="Blackbox log directory")
    parser.add_argument("--trusted-keys", help="Independent directory of trusted public keys")

    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Review an incident event hash")
    review.add_argument("event_hash")

    # Backward-compatible alias.
    blame = sub.add_parser("blame", help="Alias for review")
    blame.add_argument("event_hash")

    tree = sub.add_parser("tree", help="Show declared dependency tree")
    tree.add_argument("event_hash")

    verify = sub.add_parser("verify", help="Verify a locally recorded event")
    verify.add_argument("event_hash")

    return parser


def _tree_hashes(root):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node["hash"]
        pending.extend(node.get("children", []))


def main() -> int:
    args = build_parser().parse_args()
    event_hash = args.event_hash
    try:
        if Path(args.storage).exists() and not Path(args.storage).is_dir():
            raise NotADirectoryError(args.storage)
        if not Path(args.storage).exists():
            # A read-only lookup should not create a directory on a typo.
            box = None
        else:
            box = AgentBlackbox(args.storage, trusted_keys=args.trusted_keys)
        result = {}
        hashes = [event_hash]
        if box is not None and args.command in {"review", "blame"}:
            result = box.review_incident(event_hash)
            hashes = [entry["event_hash"] for entry in result["chain"]] or [event_hash]
        elif box is not None and args.command == "tree":
            result = box.get_causality_tree(event_hash)
            hashes = _tree_hashes(result)
        status = "not_found"
        for event_hash in hashes:
            status = box.verification_status(event_hash) if box is not None else "not_found"
            if status != "verified":
                break
    except InvalidJournal as exc:
        result = {"detail": str(exc)}
        status = "invalid_record"
    except OSError as exc:
        result = {"detail": str(exc)}
        status = "storage_error"

    result["verification_status"] = status
    if args.command == "verify":
        result["valid"] = status == "verified"
    if status != "verified":
        result["problem_event"] = event_hash
        print(f"agent-blackbox: {status} ({result.get('detail', event_hash)})", file=sys.stderr)
    print(json.dumps(result, indent=2))
    return EXIT_CODES[status]


if __name__ == "__main__":
    raise SystemExit(main())
