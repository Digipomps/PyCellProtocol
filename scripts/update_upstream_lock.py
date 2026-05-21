#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "pycellprotocol.upstream-lock.v1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Record upstream CellProtocol parity heads.")
    parser.add_argument("--cellprotocol", type=Path, default=ROOT.parent / "CellProtocol")
    parser.add_argument("--cellscaffold", type=Path, default=ROOT.parent / "CellScaffold")
    parser.add_argument("--output", type=Path, default=ROOT / "upstream-lock.json")
    args = parser.parse_args()

    previous = load_json(args.output)
    previous_repos = previous.get("repositories", {}) if isinstance(previous, dict) else {}
    repositories = {
        "CellProtocol": repo_record(
            "Digipomps/CellProtocol",
            args.cellprotocol,
            previous_repos.get("CellProtocol"),
        ),
        "CellScaffold": repo_record(
            "Digipomps/CellScaffold",
            args.cellscaffold,
            previous_repos.get("CellScaffold"),
        ),
    }
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": previous.get("generatedAt") if isinstance(previous, dict) else None,
        "repositories": repositories,
    }
    comparable_previous = comparable(previous)
    comparable_next = comparable(payload)
    if comparable_previous != comparable_next or not payload["generatedAt"]:
        payload["generatedAt"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def repo_record(repository: str, path: Path, previous: Any) -> dict[str, Any]:
    path = path.expanduser().resolve()
    if not (path / ".git").exists():
        if isinstance(previous, dict) and previous.get("head"):
            return previous
        return {
            "repository": repository,
            "status": "unavailable",
            "reason": f"{path} is not a git checkout",
        }
    return {
        "repository": repository,
        "status": "available",
        "remote": git(path, "config", "--get", "remote.origin.url"),
        "branch": git(path, "rev-parse", "--abbrev-ref", "HEAD"),
        "head": git(path, "rev-parse", "HEAD"),
        "commitDate": git(path, "show", "-s", "--format=%cI", "HEAD"),
    }


def git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def comparable(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    copy = dict(payload)
    copy.pop("generatedAt", None)
    return copy


if __name__ == "__main__":
    raise SystemExit(main())
