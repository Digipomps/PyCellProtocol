import asyncio

from cellprotocol.cells import (
    EntityAnchorCell,
    GraphIndexCell,
    StructuralValueProfileCell,
    TrustedIssuersProxyCell,
    VaultCell,
)
from cellprotocol.identity import InMemoryIdentityVault


def run(coro):
    return asyncio.run(coro)


def test_vault_cell_contracts_create_list_link_and_state():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        vault = VaultCell(owner=owner)

        created = await vault.set("vault.note.create", {"id": "n1", "title": "One", "content": "Links [[n2]]", "tags": ["a"]}, owner)
        assert created["status"] == "ok"
        listed = await vault.set("vault.note.list", {"tags": ["a"]}, owner)
        assert [note["id"] for note in listed["notes"]] == ["n1"]
        link = await vault.set("vault.link.add", {"fromNoteID": "n1", "toNoteID": "n2"}, owner)
        assert link["link"]["relationship"] == "wiki"
        forward = await vault.set("vault.links.forward", {"id": "n1"}, owner)
        assert forward["ids"] == ["n2"]
        state = await vault.get("vault.state", owner)
        assert state["schemaVersion"] == "haven.vault.state.v1"
        assert state["noteCount"] == 1
        assert state["linkCount"] == 1

    run(scenario())


def test_graph_index_extracts_wiki_links():
    async def scenario():
        graph = GraphIndexCell()
        result = await graph.set("graph.reindex", {"notes": [{"id": "n1", "content": "See [[n2]] and [[n3]]"}]})
        assert result["edgeCount"] == 2
        assert await graph.set("graph.outgoing", {"id": "n1"}) == {"status": "ok", "ids": ["n2", "n3"]}
        assert await graph.set("graph.incoming", {"id": "n2"}) == {"status": "ok", "ids": ["n1"]}

    run(scenario())


def test_entity_anchor_identity_links_and_batch_persist():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        entity = EntityAnchorCell(owner=owner)

        persisted = await entity.set(
            "entity.batchPersist",
            {"schema": "test.schema", "mutations": [{"keypath": "person.displayName", "value": "Ada"}]},
            owner,
        )
        assert persisted["status"] == "persisted"
        assert await entity.get("person.displayName", owner) == "Ada"

        approval = await entity.set("identityLinks.approveEnrollment", {"approvalID": "approval/1"}, owner)
        assert approval["status"] == "approved"
        completed = await entity.set("identityLinks.completeEnrollment", {"linkID": "link/1", "approvalJTI": "jti-1"}, owner)
        assert completed["status"] == "completed"
        replay = await entity.set("identityLinks.completeEnrollment", {"linkID": "link/2", "approvalJTI": "jti-1"}, owner)
        assert replay["status"] == "error"
        revoked = await entity.set("identityLinks.revoke", {"linkID": "link/1"}, owner)
        assert revoked["status"] == "revoked"
        state = await entity.get("identityLinks.state", owner)
        assert state["status"] == "ready"

    run(scenario())


def _triangle_edgelist():
    # K3 plus a pendant tail: closed triad + one leaf.
    return {
        "graphID": "t",
        "directed": True,
        "nodes": [{"id": n, "type": "x"} for n in ["a", "b", "c", "d"]],
        "edges": [
            {"u": "a", "v": "b", "type": "r"},
            {"u": "b", "v": "c", "type": "r"},
            {"u": "c", "v": "a", "type": "r"},
            {"u": "c", "v": "d", "type": "s"},
        ],
    }


def test_structural_value_profile_load_and_compute():
    async def scenario():
        cell = StructuralValueProfileCell()
        loaded = await cell.set("graph.profile.load", _triangle_edgelist())
        assert loaded == {"status": "ok", "graphID": "t", "N": 4, "E": 4}

        profile = await cell.set("graph.profile.compute", {"nulls": 20, "bootstrap": 20, "seed": 3})
        assert profile["status"] == "ok"
        assert profile["schemaVersion"] == "haven.graph.structural-value-profile.v1"
        p1 = profile["pillar1_scale_health"]
        assert p1["N"] == 4 and p1["E_undirected_simple"] == 4
        assert p1["giant_fraction"] == 1.0
        # one triangle among 4 wedges: transitivity 3/ (3+1)?; here open_triad_ratio < 1
        assert profile["pillar3_potential_value"]["open_triad_ratio"] < 1.0
        assert profile["pillar4_complexity"]["vn_entropy_norm"] > 0.0
        # tiny graph: fractal must be gated off
        assert profile["fractal_gate"]["estimable"] is False
        # pillar 2 unavailable without usage traces
        assert profile["pillar2_current_value"]["status"] == "unavailable"

        state = await cell.get("graph.profile.state")
        assert state["hasProfile"] is True and state["N"] == 4

    run(scenario())


def test_structural_value_profile_is_deterministic_and_emits_audit():
    async def scenario():
        cell_a = StructuralValueProfileCell()
        cell_b = StructuralValueProfileCell()
        spec = {"graph": _triangle_edgelist(), "nulls": 25, "bootstrap": 25, "seed": 11}
        a = await cell_a.set("graph.profile.compute", spec)
        b = await cell_b.set("graph.profile.compute", spec)
        assert a["null_model_zscores"] == b["null_model_zscores"]
        assert a["bootstrap_stability"] == b["bootstrap_stability"]
        # audit FlowElement was queued
        element = cell_a._flow_queue.get_nowait()
        assert element.topic == "graph.profile.computed"
        assert element.content["fractal_estimable"] is False
        assert element.content["inputHash"].startswith("sha256:")

    run(scenario())


def test_structural_value_profile_pillar2_available_with_usage():
    async def scenario():
        cell = StructuralValueProfileCell()
        await cell.set("graph.profile.load", _triangle_edgelist())
        profile = await cell.set("graph.profile.compute", {
            "nulls": 0,
            "bootstrap": 0,
            "usage": {"nodeReads": {"a": 5, "b": 2}, "edgeTraversals": {"a->b": 3}},
        })
        p2 = profile["pillar2_current_value"]
        assert p2["status"] == "available"
        assert p2["read_coverage"] == 0.5  # 2 of 4 nodes read

    run(scenario())


def test_structural_value_profile_from_graph_index():
    async def scenario():
        graph = GraphIndexCell()
        await graph.set("graph.reindex", {"notes": [{"id": "n1", "content": "See [[n2]] and [[n3]]"}]})
        state = await graph.get("graph.state")

        cell = StructuralValueProfileCell()
        loaded = await cell.set("graph.profile.fromGraphIndex", state)
        assert loaded["status"] == "ok"
        assert loaded["N"] == 3 and loaded["E"] == 2
        profile = await cell.set("graph.profile.compute", {"nulls": 0, "bootstrap": 0})
        assert profile["pillar1_scale_health"]["N"] == 3

    run(scenario())


def test_trusted_issuers_proxy_fails_closed_without_swift_verifier():
    async def scenario():
        cell = TrustedIssuersProxyCell()
        result = await cell.set("trustedIssuers.evaluate", {"issuerId": "did:key:test", "candidateVc": {}}, None)
        assert result["status"] == "unavailable"
        assert result["trusted"] is False

    run(scenario())
