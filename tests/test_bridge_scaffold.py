import asyncio

from cellprotocol.bridge import BridgeCommand, BridgeEndpoint
from cellprotocol.general_cell import GeneralCell
from cellprotocol.value import KeyValue, SetValueResponse, TypedValue
from cellprotocol_scaffold import entity_anchor_data


def run(coro):
    return asyncio.run(coro)


def test_bridge_endpoint_handles_get_set_description():
    async def scenario():
        cell = GeneralCell(name="Echo")
        endpoint = BridgeEndpoint(cell)

        set_response = await endpoint.handle(
            BridgeCommand("set", TypedValue("keyValue", KeyValue("state.value", "ok")), 1)
        )
        assert set_response[0].cmd == "response"
        assert isinstance(set_response[0].payload.value, SetValueResponse)
        assert set_response[0].payload.value.state == "ok"

        get_response = await endpoint.handle(BridgeCommand("get", TypedValue("string", "state.value"), 2))
        assert get_response[0].payload.value == "ok"

        description = await endpoint.handle(BridgeCommand("description", cid=3))
        assert description[0].payload.kind == "description"
        assert description[0].payload.value["name"] == "Echo"

    run(scenario())


def test_entity_anchor_data_is_static_value_free_and_autocompleteable():
    contract = entity_anchor_data.contract()
    assert contract["safety"]["expose_values"] is False
    assert "keypaths" in contract
    result = entity_anchor_data.autocomplete(query="identity", scope="sprout")
    paths = [item["path"] for item in result["suggestions"]]
    assert "proofs.identityLinks" in paths
