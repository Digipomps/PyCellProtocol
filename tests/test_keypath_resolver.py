import asyncio

from cellprotocol.configuration import CellConfiguration
from cellprotocol.general_cell import GeneralCell
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.keypath import get_keypath, set_keypath
from cellprotocol.resolver import CellResolver, CellUsageScope, RemoteCellHostRoute


def run(coro):
    return asyncio.run(coro)


def test_keypath_supports_append_indexes_and_match_tokens():
    root = {}
    set_keypath(root, "people[+].name", "Ada")
    set_keypath(root, "people[0].age", 42)
    set_keypath(root, "people[id=bob].name", "Bob")
    set_keypath(root, "people[id=bob].age", 39)

    assert get_keypath(root, "people[0].name") == "Ada"
    assert get_keypath(root, "people[id=bob].age") == 39


def test_resolver_scopes_and_remote_route_layouts():
    async def scenario():
        vault = InMemoryIdentityVault()
        alice = await vault.identity("alice")
        bob = await vault.identity("bob")
        resolver = CellResolver()
        await resolver.register_named_emit_cell("Template", factory=lambda owner=None: GeneralCell(owner=owner), scope=CellUsageScope.template)
        await resolver.register_named_emit_cell("Shared", factory=lambda owner=None: GeneralCell(owner=owner), scope=CellUsageScope.scaffoldUnique)
        await resolver.register_named_emit_cell("Personal", factory=lambda owner=None: GeneralCell(owner=owner), scope=CellUsageScope.identityUnique)

        assert await resolver.cell_at_endpoint("cell:///Template", alice) is not await resolver.cell_at_endpoint("cell:///Template", alice)
        assert await resolver.cell_at_endpoint("cell:///Shared", alice) is await resolver.cell_at_endpoint("cell:///Shared", bob)
        assert await resolver.cell_at_endpoint("cell:///Personal", alice) is await resolver.cell_at_endpoint("cell:///Personal", alice)
        assert await resolver.cell_at_endpoint("cell:///Personal", alice) is not await resolver.cell_at_endpoint("cell:///Personal", bob)

        route = RemoteCellHostRoute(websocketEndpoint="bridgehead", schemePreference="wss", pathLayout="publisherUUIDThenEndpoint")
        assert route.bridge_url("example.test", "ConferenceAIGatewayPreview", "bridge-uuid") == "wss://example.test/bridgehead/bridge-uuid/ConferenceAIGatewayPreview"
        default_route = RemoteCellHostRoute(schemePreference="wss")
        assert default_route.bridge_url("example.test", "LoginCell", "bridge-uuid") == "wss://example.test/bridgehead/LoginCell/bridge-uuid"

    run(scenario())


def test_load_cell_applies_cell_references_and_set_keys_and_values():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        resolver = CellResolver()
        source = GeneralCell(owner=owner, name="Source")
        target = GeneralCell(owner=owner, name="Target")
        await resolver.register_named_emit_cell("Target", emit_cell=target, identity=owner)
        config = CellConfiguration.from_json(
            {
                "name": "Loader",
                "cellReferences": [
                    {
                        "endpoint": "cell:///Target",
                        "label": "target",
                        "subscribeFeed": False,
                        "setKeysAndValues": [{"key": "state.message", "string": "hello"}],
                    }
                ],
                "skeleton": {"Text": {"text": "Loader"}},
            }
        )

        loaded = await resolver.load_cell(config, source, owner)

        assert loaded == [target]
        assert await target.get("state.message", owner) == "hello"
        assert await source.attached_status("target", owner) == "connected"

    run(scenario())
