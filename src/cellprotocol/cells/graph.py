from __future__ import annotations

import re
from typing import Any

from ..general_cell import GeneralCell
from ..value import from_json_value


class GraphIndexCell(GeneralCell):
    def __init__(self, owner: Any | None = None, name: str = "GraphIndex", uuid: str | None = None) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self.nodes: set[str] = set()
        self.edges: dict[str, set[str]] = {}
        self.agreement_template.add_grant("rw--", "graph")
        self._get_handlers["graph.state"] = self._get_state
        for key in ["graph.reindex", "graph.outgoing", "graph.incoming", "graph.neighbors"]:
            self._set_handlers[key] = self._set_graph

    async def _get_state(self, keypath: str, requester: Any | None) -> dict[str, Any]:
        _ = keypath, requester
        return {
            "status": "ready",
            "nodeCount": len(self.nodes),
            "edgeCount": sum(len(targets) for targets in self.edges.values()),
            "nodes": sorted(self.nodes),
            "edges": [
                {"from": source, "to": target}
                for source, targets in sorted(self.edges.items())
                for target in sorted(targets)
            ],
        }

    async def _set_graph(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        payload = from_json_value(value)
        if not isinstance(payload, dict):
            return {"status": "error", "message": "payload must be object"}
        if keypath == "graph.reindex":
            return self._reindex(payload)
        node = _node_id(payload)
        if not node:
            return {"status": "error", "message": "id is required"}
        if keypath == "graph.outgoing":
            return {"status": "ok", "ids": sorted(self.edges.get(node, set()))}
        if keypath == "graph.incoming":
            return {"status": "ok", "ids": sorted(source for source, targets in self.edges.items() if node in targets)}
        if keypath == "graph.neighbors":
            outgoing = self.edges.get(node, set())
            incoming = {source for source, targets in self.edges.items() if node in targets}
            return {"status": "ok", "ids": sorted(outgoing | incoming)}
        _ = requester
        return {"status": "error", "message": f"unknown operation {keypath}"}

    def _reindex(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.nodes.clear()
        self.edges.clear()
        for item in payload.get("notes", []):
            if not isinstance(item, dict):
                continue
            note_id = item.get("id")
            content = item.get("content", "")
            if not isinstance(note_id, str):
                continue
            self.nodes.add(note_id)
            targets = set(re.findall(r"\[\[([^\]]+)\]\]", content if isinstance(content, str) else ""))
            self.edges[note_id] = targets
            self.nodes.update(targets)
        return {"status": "ok", "nodeCount": len(self.nodes), "edgeCount": sum(len(v) for v in self.edges.values())}


def _node_id(payload: dict[str, Any]) -> str | None:
    for key in ("id", "node-id", "note_id", "noteID"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    return None
