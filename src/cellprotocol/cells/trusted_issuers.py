from __future__ import annotations

from typing import Any, Protocol

from ..general_cell import GeneralCell


class CredentialVerifier(Protocol):
    async def evaluate(self, payload: dict[str, Any], requester: Any | None = None) -> dict[str, Any]: ...


class UnavailableCredentialVerifier:
    async def evaluate(self, payload: dict[str, Any], requester: Any | None = None) -> dict[str, Any]:
        _ = payload, requester
        return {
            "status": "unavailable",
            "decision": "unavailable",
            "trusted": False,
            "reason": "No Swift TrustedIssuers verifier endpoint is configured.",
        }


class SwiftCredentialVerifierClient:
    def __init__(self, resolver: Any, endpoint: str = "cell:///TrustedIssuers") -> None:
        self.resolver = resolver
        self.endpoint = endpoint

    async def evaluate(self, payload: dict[str, Any], requester: Any | None = None) -> dict[str, Any]:
        try:
            cell = await self.resolver.cell_at_endpoint(self.endpoint, requester)
            result = await cell.set("trustedIssuers.evaluate", payload, requester)
            if isinstance(result, dict):
                return result
            return {"status": "ok", "result": result}
        except Exception as error:
            return {
                "status": "unavailable",
                "decision": "unavailable",
                "trusted": False,
                "reason": str(error),
            }


class TrustedIssuersProxyCell(GeneralCell):
    def __init__(self, verifier: CredentialVerifier | None = None, owner: Any | None = None, name: str = "TrustedIssuers") -> None:
        super().__init__(owner=owner, name=name)
        self.verifier = verifier or UnavailableCredentialVerifier()
        self.agreement_template.add_grant("rw--", "trustedIssuers")
        self._get_handlers["trustedIssuers.state"] = self._state
        self._set_handlers["trustedIssuers.evaluate"] = self._evaluate

    async def _state(self, keypath: str, requester: Any | None) -> dict[str, Any]:
        _ = keypath, requester
        return {
            "status": "ready",
            "mode": self.verifier.__class__.__name__,
            "keys": ["trustedIssuers.state", "trustedIssuers.evaluate"],
        }

    async def _evaluate(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        _ = keypath
        if not isinstance(value, dict):
            return {"status": "error", "decision": "unavailable", "trusted": False, "reason": "payload must be object"}
        return await self.verifier.evaluate(value, requester)
