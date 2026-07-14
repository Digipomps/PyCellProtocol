import json
from pathlib import Path

from cellprotocol.bridge import BridgeCommand
from cellprotocol.configuration import CellConfiguration
from cellprotocol.identity import Identity, identity_signing_fingerprint
from cellprotocol.value import KeyValue, SetValueResponse, TypedValue


FIXTURES = Path(__file__).parent / "fixtures"


def test_swift_origin_identity_and_description_command_fixture_round_trip():
    fixture = json.loads(
        (FIXTURES / "swift_identity_description_command.json").read_text(encoding="utf-8")
    )
    identity = Identity.from_json(fixture["identity"])

    assert identity.publicSecureKey == fixture["identity"]["publicSecureKey"]["compressedKey"]
    assert identity_signing_fingerprint(identity) == (
        "EdDSA:Curve25519:" + fixture["identity"]["publicSecureKey"]["compressedKey"]
    )
    assert identity.to_json() == fixture["identity"]

    command = BridgeCommand.from_json(fixture["descriptionCommand"])
    assert command.command == "description"
    assert command.identity is not None
    assert command.identity.to_json() == fixture["identity"]
    assert command.to_json() == fixture["descriptionCommand"]


def test_bridge_command_encodes_swift_key_value_payload():
    command = BridgeCommand(
        cmd="set",
        cid=42,
        payload=TypedValue("keyValue", KeyValue("vault.note.create", {"title": "T", "content": "C"})),
    )

    encoded = command.to_json()

    assert encoded == {
        "cmd": "set",
        "cid": 42,
        "&keyValue": {
            "key": "vault.note.create",
            "object": {"title": "T", "content": "C"},
        },
    }
    decoded = BridgeCommand.from_json(encoded)
    assert decoded.command == "set"
    assert decoded.payload.kind == "keyValue"
    assert decoded.payload.value.key == "vault.note.create"
    assert decoded.payload.value.value == {"title": "T", "content": "C"}


def test_bridge_command_preserves_swift_set_value_response_key():
    command = BridgeCommand("response", TypedValue("setValueResponse", SetValueResponse.ok({"id": "n1"})), 9)

    encoded = command.to_json()

    assert encoded["&setValueResponse"] == {"state": "ok", "value": {"id": "n1"}}
    decoded = BridgeCommand.from_json(json.dumps(encoded))
    assert decoded.payload.value.state == "ok"
    assert decoded.payload.value.value == {"id": "n1"}


def test_cell_configuration_parses_current_skeleton_wrappers_and_refs():
    raw = {
        "name": "Python parity",
        "discovery": {
            "sourceCellEndpoint": "cell:///Vault",
            "purposeRefs": ["beta", "alpha", "alpha", ""],
        },
        "cellReferences": [
            {
                "endpoint": "cell:///Vault",
                "label": "vault",
                "subscribeFeed": False,
                "setKeysAndValues": [{"key": "vault.note.list", "target": "notes"}],
            }
        ],
        "skeleton": {
            "Tabs": {
                "activeTabStateKeypath": "ui.activeTab",
                "panels": [
                    {
                        "id": "notes",
                        "content": [{"Text": {"text": "Notes", "keypath": "notes"}}],
                    }
                ],
            }
        },
    }

    config = CellConfiguration.from_json(raw)
    encoded = config.to_json()

    assert encoded["discovery"]["purposeRefs"] == ["alpha", "beta"]
    assert encoded["cellReferences"][0]["subscribeFeed"] is False
    assert encoded["skeleton"]["Tabs"]["activeTabStateKeypath"] == "ui.activeTab"
    assert "notes" in config.skeleton_keypaths()
