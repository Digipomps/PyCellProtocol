import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_upstream_relevance",
    ROOT / "scripts" / "check_upstream_relevance.py",
)
assert SPEC is not None and SPEC.loader is not None
check_upstream_relevance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_upstream_relevance)


def test_cellprotocol_relevance_matches_contract_critical_paths():
    assert check_upstream_relevance.is_relevant_path(
        "CellProtocol",
        "Sources/CellBase/Cells/Bridging/BridgeCommand.swift",
    )
    assert check_upstream_relevance.is_relevant_path(
        "CellProtocol",
        "Sources/CellBase/CellConfiguration/CellConfiguration.swift",
    )
    assert check_upstream_relevance.is_relevant_path(
        "CellProtocol",
        "Sources/CellBase/Cells/Vault/VaultCell.swift",
    )
    assert check_upstream_relevance.is_relevant_path(
        "CellProtocol",
        "Tests/CellBaseTests/ResolverTests.swift",
    )


def test_upstream_relevance_ignores_non_contract_paths():
    assert not check_upstream_relevance.is_relevant_path(
        "CellProtocol",
        "Docs/README.md",
    )
    assert not check_upstream_relevance.is_relevant_path(
        "CellScaffold",
        "Public/images/logo.png",
    )


def test_cellscaffold_relevance_matches_bridge_and_resolver_paths():
    assert check_upstream_relevance.is_relevant_path(
        "CellScaffold",
        "Sources/App/Controllers/VaporBridgehead.swift",
    )
    assert check_upstream_relevance.is_relevant_path(
        "CellScaffold",
        "Sources/App/Cells/ConferenceMVP/ConferenceSharedCellBridgeSupport.swift",
    )
    assert check_upstream_relevance.is_relevant_path(
        "CellScaffold",
        "Sources/App/Services/SproutResolverCompatibility.swift",
    )
