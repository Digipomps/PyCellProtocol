import asyncio

from cellprotocol.cells import EntityAnchorCell, GraphIndexCell, TrustedIssuersProxyCell, VaultCell
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


def test_trusted_issuers_proxy_fails_closed_without_swift_verifier():
    async def scenario():
        cell = TrustedIssuersProxyCell()
        result = await cell.set("trustedIssuers.evaluate", {"issuerId": "did:key:test", "candidateVc": {}}, None)
        assert result["status"] == "unavailable"
        assert result["trusted"] is False

    run(scenario())
