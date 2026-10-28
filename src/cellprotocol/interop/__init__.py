"""Cross-language wire contracts: entity extension, invitation and chat.

Byte-compatible with CellProtocol Swift. Checked against the golden fixtures
in `tests/fixtures/interop/v1`, copied from CellProtocol `fixtures/interop/v1`.
"""

from . import models, verify
from .canonical import CanonicalEncodingError, canonical_json, canonical_payload, sorted_keys
from .models import WIRE_TYPES, WireDecodeError

__all__ = [
    "CanonicalEncodingError",
    "WIRE_TYPES",
    "WireDecodeError",
    "canonical_json",
    "canonical_payload",
    "models",
    "sorted_keys",
    "verify",
]
