#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


RELEVANT_PATTERNS: dict[str, list[str]] = {
    "CellProtocol": [
        ".github/workflows/notify-pycellprotocol.yml",
        "Sources/CellApple/AppleBridgeTransport.swift",
        "Sources/CellApple/IdentityVault.swift",
        "Sources/CellBase/CellConfiguration/",
        "Sources/CellBase/Cells/Bridging/",
        "Sources/CellBase/Cells/CellResolver/",
        "Sources/CellBase/Cells/Vault/",
        "Sources/CellBase/Crypto/VaultLegacyPayloadDecoder.swift",
        "Sources/CellBase/Identity/",
        "Sources/CellBase/Protocols/CloudBridgeProtocol.swift",
        "Sources/CellVapor/CloudBridge/",
        "Sources/CellVapor/VaporIdentityVault.swift",
        "Tests/CellBaseTests/*Bridge*",
        "Tests/CellBaseTests/*Resolver*",
        "Tests/CellBaseTests/*Vault*",
        "Tests/CellBaseTests/*CellConfiguration*",
        "Tests/CellBaseTests/SkeletonTests.swift",
    ],
    "CellScaffold": [
        ".github/workflows/notify-pycellprotocol.yml",
        "Sources/App/Controllers/VaporBridgehead.swift",
        "Sources/App/Controllers/VaporSproutBridgeDiscovery.swift",
        "Sources/App/Controllers/VaporSproutResolver.swift",
        "Sources/App/Controllers/VaporVaultMVP.swift",
        "Sources/App/Services/EditableCellConfigurationSupport.swift",
        "Sources/App/Services/SproutBridgeDiscoveryCompatibility.swift",
        "Sources/App/Services/SproutResolverCompatibility.swift",
        "Sources/App/Cells/*Bridge*.swift",
        "Sources/App/Cells/CellConfigurationStudio/",
        "Sources/App/Cells/UniversalResolver/",
        "Sources/App/Cells/VaultStudio/",
        "Sources/UserSimulationScaffoldCore/BridgeDriver.swift",
        "Tests/AppTests/*Bridge*",
        "Tests/AppTests/*Resolver*",
        "Tests/AppTests/*Vault*",
        "Tests/AppTests/*CellConfiguration*",
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify whether upstream changes affect PyCellProtocol parity surfaces.")
    parser.add_argument("--cellprotocol", type=Path, default=ROOT.parent / "CellProtocol")
    parser.add_argument("--cellscaffold", type=Path, default=ROOT.parent / "CellScaffold")
    parser.add_argument("--lock", type=Path, default=ROOT / "upstream-lock.json")
    parser.add_argument("--summary", type=Path, default=ROOT / "upstream-relevance.json")
    args = parser.parse_args()

    previous = load_json(args.lock)
    previous_repositories = previous.get("repositories", {}) if isinstance(previous, dict) else {}
    records = [
        classify_repo("CellProtocol", args.cellprotocol, previous_repositories.get("CellProtocol")),
        classify_repo("CellScaffold", args.cellscaffold, previous_repositories.get("CellScaffold")),
    ]
    relevant_records = [record for record in records if record["relevant"]]
    changed_count = sum(len(record["changedFiles"]) for record in records)
    payload = {
        "relevant": bool(relevant_records),
        "changedCount": changed_count,
        "repositories": records,
    }
    args.summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_github_outputs(payload)
    write_step_summary(payload)

    if payload["relevant"]:
        print("Relevant upstream changes detected.")
        for record in relevant_records:
            print(f"- {record['name']}: {len(record['relevantFiles'])} relevant files")
            for path in record["relevantFiles"][:20]:
                print(f"  - {path}")
    else:
        print("No relevant upstream resolver/vault/CellConfiguration/bridge changes detected.")
    return 0


def classify_repo(name: str, path: Path, previous: Any) -> dict[str, Any]:
    path = path.expanduser().resolve()
    if not (path / ".git").exists():
        return {
            "name": name,
            "status": "unavailable",
            "previousHead": previous.get("head") if isinstance(previous, dict) else None,
            "currentHead": None,
            "changedFiles": [],
            "relevantFiles": [],
            "relevant": False,
            "reason": f"{path} is not a git checkout",
        }

    current_head = git(path, "rev-parse", "HEAD")
    previous_head = previous.get("head") if isinstance(previous, dict) else None
    changed_files = changed_files_between(path, previous_head, current_head)
    relevant_files = [file for file in changed_files if is_relevant_path(name, file)]
    return {
        "name": name,
        "status": "available",
        "previousHead": previous_head,
        "currentHead": current_head,
        "changedFiles": changed_files,
        "relevantFiles": relevant_files,
        "relevant": bool(relevant_files),
    }


def changed_files_between(path: Path, previous_head: str | None, current_head: str) -> list[str]:
    if previous_head == current_head:
        return []
    if previous_head and commit_exists(path, previous_head):
        output = git(path, "diff", "--name-only", f"{previous_head}..{current_head}")
    else:
        output = git(path, "show", "--name-only", "--format=", current_head)
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def is_relevant_path(repo_name: str, changed_path: str) -> bool:
    patterns = RELEVANT_PATTERNS.get(repo_name, [])
    for pattern in patterns:
        if pattern.endswith("/") and changed_path.startswith(pattern):
            return True
        if fnmatch.fnmatch(changed_path, pattern):
            return True
    return False


def commit_exists(path: Path, commit: str) -> bool:
    process = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return process.returncode == 0


def git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_github_outputs(payload: dict[str, Any]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    relevant = "true" if payload["relevant"] else "false"
    repositories = ",".join(
        record["name"] for record in payload["repositories"] if record["relevant"]
    )
    lines = [
        f"relevant={relevant}",
        f"changed_count={payload['changedCount']}",
        f"repositories={repositories}",
    ]
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def write_step_summary(payload: dict[str, Any]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = ["## Upstream relevance", ""]
    if payload["relevant"]:
        lines.append("Relevant upstream changes were detected.")
    else:
        lines.append("No relevant upstream resolver/vault/CellConfiguration/bridge changes were detected.")
    lines.append("")
    for record in payload["repositories"]:
        lines.append(f"### {record['name']}")
        lines.append(f"- status: `{record['status']}`")
        lines.append(f"- changed files: `{len(record['changedFiles'])}`")
        lines.append(f"- relevant files: `{len(record['relevantFiles'])}`")
        for file in record["relevantFiles"][:20]:
            lines.append(f"- `{file}`")
        lines.append("")
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
