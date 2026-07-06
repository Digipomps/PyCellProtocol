"""StructuralValueProfileCell: content-blind structural value metrics.

A native HAVEN cell that computes the Structural Value Profile proposed in
CellProtocolDocuments/Deliverables/Fractal_Dimension_Data_Value_Advisory_
2026-07-04.md: pillars 1 (scale/health), 3 (potential value) and 4
(complexity), plus null-model z-scores, a bootstrap stability check, and a
gated fractal-dimension diagnostic that stays off below ~15 usable box scales.

Pillar 2 (current/realized value) requires FlowElement usage traces; it is
reported as unavailable unless usage-weight input is supplied with the graph.

Design notes:
- Pure standard library, matching the dependency-light cellprotocol core.
  The heavy-numerics lane (numpy/scipy) is intentionally not required for v1.
- The computation is a deterministic pure function of the input payload and
  the seed, so the emitted FlowElement is replayable.
- Content-blind: only edgelist structure and coarse node/edge type labels are
  consumed, never node prose.
- Analysis-only: the cell never mutates source entities.

Wire surface (Swift parity target):
- set graph.profile.load        {graphID, directed, nodes:[{id,type}], edges:[{u,v,type}]}
- set graph.profile.fromGraphIndex {graphID?, nodes:[...], edges:[{from,to}]}
- set graph.profile.compute     {nulls?, bootstrap?, drop?, seed?, usage?}  (graph optional inline)
- get graph.profile.state       -> {status, schemaVersion, graphID, N, E, hasProfile}
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import zlib
from collections import defaultdict, deque
from typing import Any

from ..general_cell import FlowElement, GeneralCell
from ..value import from_json_value

STATE_SCHEMA = "haven.graph.structural-value-profile.v1"
FRACTAL_MIN_BOX_SCALES = 15


# ------------------------------ graph helpers ------------------------------

def _build_adjacency(nodes: list[str], edges: list[tuple[str, str]]) -> tuple[list[str], dict[str, set[str]]]:
    node_ids = list(nodes)
    seen = set(node_ids)
    adj: dict[str, set[str]] = {n: set() for n in node_ids}
    for u, v in edges:
        for x in (u, v):
            if x not in seen:
                seen.add(x)
                node_ids.append(x)
                adj[x] = set()
        if u != v:
            adj[u].add(v)
            adj[v].add(u)
    return node_ids, adj


def _undirected_edge_count(adj: dict[str, set[str]]) -> int:
    return sum(len(s) for s in adj.values()) // 2


def _components(nodes: list[str], adj: dict[str, set[str]]) -> list[list[str]]:
    seen: set[str] = set()
    comps: list[list[str]] = []
    for start in nodes:
        if start in seen:
            continue
        comp: list[str] = []
        q = deque([start])
        seen.add(start)
        while q:
            x = q.popleft()
            comp.append(x)
            for y in adj[x]:
                if y not in seen:
                    seen.add(y)
                    q.append(y)
        comps.append(comp)
    return sorted(comps, key=len, reverse=True)


def _diameter_and_effective(adj: dict[str, set[str]], comp: list[str]) -> tuple[int, float]:
    allowed = set(comp)
    all_d: list[int] = []
    ecc = 0
    for s in comp:
        dist = {s: 0}
        q = deque([s])
        while q:
            x = q.popleft()
            for y in adj[x]:
                if y in allowed and y not in dist:
                    dist[y] = dist[x] + 1
                    q.append(y)
        vals = list(dist.values())
        ecc = max(ecc, max(vals) if vals else 0)
        all_d.extend(v for v in vals if v > 0)
    if not all_d:
        return 0, 0.0
    all_d.sort()
    idx = min(len(all_d) - 1, int(math.ceil(0.9 * len(all_d)) - 1))
    return ecc, float(all_d[idx])


def _triangles_and_wedges(nodes: list[str], adj: dict[str, set[str]]) -> tuple[int, int]:
    triangles = 0
    wedges = 0
    for v in nodes:
        nb = list(adj[v])
        d = len(nb)
        wedges += d * (d - 1) // 2
        for i in range(len(nb)):
            for j in range(i + 1, len(nb)):
                if nb[j] in adj[nb[i]]:
                    triangles += 1
    return triangles // 3, wedges


def _mean_local_clustering(nodes: list[str], adj: dict[str, set[str]]) -> float:
    total = 0.0
    counted = 0
    for v in nodes:
        nb = list(adj[v])
        d = len(nb)
        if d < 2:
            continue
        links = 0
        for i in range(len(nb)):
            for j in range(i + 1, len(nb)):
                if nb[j] in adj[nb[i]]:
                    links += 1
        total += 2 * links / (d * (d - 1))
        counted += 1
    return total / counted if counted else 0.0


def _articulation_points_and_bridges(nodes: list[str], adj: dict[str, set[str]]) -> tuple[int, int]:
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    timer = [0]
    aps: set[str] = set()
    bridges = 0
    for root in nodes:
        if root in disc:
            continue
        stack = [(root, None, iter(adj[root]))]
        disc[root] = low[root] = timer[0]
        timer[0] += 1
        root_children = 0
        while stack:
            node, parent, it = stack[-1]
            advanced = False
            for nxt in it:
                if nxt == parent:
                    continue
                if nxt not in disc:
                    if parent is None:
                        root_children += 1
                    disc[nxt] = low[nxt] = timer[0]
                    timer[0] += 1
                    stack.append((nxt, node, iter(adj[nxt])))
                    advanced = True
                    break
                low[node] = min(low[node], disc[nxt])
            if not advanced:
                stack.pop()
                if stack:
                    p = stack[-1][0]
                    low[p] = min(low[p], low[node])
                    if stack[-1][1] is not None and low[node] >= disc[p]:
                        aps.add(p)
                    if low[node] > disc[p]:
                        bridges += 1
        if root_children > 1:
            aps.add(root)
    return len(aps), bridges


# ------------------------------ spectral --------------------------------

def _normalized_laplacian(adj: dict[str, set[str]], comp: list[str]) -> list[list[float]]:
    idx = {n: i for i, n in enumerate(comp)}
    comp_set = set(comp)
    k = len(comp)
    L = [[0.0] * k for _ in range(k)]
    deg = {n: len(adj[n] & comp_set) for n in comp}
    for a in comp:
        ia = idx[a]
        da = deg[a]
        if da == 0:
            continue
        L[ia][ia] = 1.0
        for b in adj[a]:
            if b in idx and b != a:
                db = deg[b]
                if db > 0:
                    L[ia][idx[b]] = -1.0 / math.sqrt(da * db)
    return L


def _jacobi_eigenvalues(A: list[list[float]], sweeps: int = 100, tol: float = 1e-10) -> list[float]:
    n = len(A)
    if n == 0:
        return []
    a = [row[:] for row in A]
    for _ in range(sweeps):
        off = 0.0
        for p in range(n):
            for q in range(p + 1, n):
                off += a[p][q] * a[p][q]
        if off < tol:
            break
        for p in range(n):
            for q in range(p + 1, n):
                if abs(a[p][q]) < 1e-14:
                    continue
                app, aqq, apq = a[p][p], a[q][q], a[p][q]
                phi = 0.5 * math.atan2(2 * apq, aqq - app)
                c, s = math.cos(phi), math.sin(phi)
                for i in range(n):
                    aip, aiq = a[i][p], a[i][q]
                    a[i][p] = c * aip - s * aiq
                    a[i][q] = s * aip + c * aiq
                for i in range(n):
                    api, aqi = a[p][i], a[q][i]
                    a[p][i] = c * api - s * aqi
                    a[q][i] = s * api + c * aqi
    return [a[i][i] for i in range(n)]


def _von_neumann_entropy(adj: dict[str, set[str]], comp: list[str]) -> float:
    if len(comp) < 2:
        return 0.0
    eig = _jacobi_eigenvalues(_normalized_laplacian(adj, comp))
    trace = sum(eig)
    if trace <= 0:
        return 0.0
    s = 0.0
    for e in eig:
        p = max(0.0, e) / trace
        if p > 1e-12:
            s -= p * math.log(p)
    return s


# --------------------------- entropy / MDL ------------------------------

def _degree_entropy(nodes: list[str], adj: dict[str, set[str]]) -> float:
    counts: dict[int, int] = defaultdict(int)
    for v in nodes:
        counts[len(adj[v])] += 1
    total = len(nodes)
    s = 0.0
    for c in counts.values():
        p = c / total
        s -= p * math.log(p)
    return s


def _type_entropy(edge_types: list[str]) -> float:
    counts: dict[str, int] = defaultdict(int)
    for t in edge_types:
        counts[t] += 1
    total = len(edge_types) or 1
    s = 0.0
    for c in counts.values():
        p = c / total
        s -= p * math.log(p)
    return s


def _compressibility_ratio(nodes: list[str], adj: dict[str, set[str]]) -> float:
    index = {n: i for i, n in enumerate(sorted(nodes))}
    lines = []
    for n in sorted(nodes):
        nb = sorted(index[x] for x in adj[n])
        lines.append(f"{index[n]}:" + ",".join(map(str, nb)))
    raw = ("\n".join(lines)).encode("utf-8")
    if not raw:
        return 1.0
    return len(zlib.compress(raw, 9)) / len(raw)


# ------------------------------ null model ------------------------------

def _er_null(n: int, m: int, rng: random.Random) -> tuple[list[str], dict[str, set[str]]]:
    max_edges = n * (n - 1) // 2
    m = min(m, max_edges)
    node_ids = [str(i) for i in range(n)]
    adj: dict[str, set[str]] = {x: set() for x in node_ids}
    placed = 0
    while placed < m:
        u = rng.randrange(n)
        v = rng.randrange(n)
        if u == v:
            continue
        a, b = str(u), str(v)
        if b in adj[a]:
            continue
        adj[a].add(b)
        adj[b].add(a)
        placed += 1
    return node_ids, adj


def _null_zscores(nodes: list[str], adj: dict[str, set[str]], nulls: int, rng: random.Random) -> dict[str, Any]:
    n = len(nodes)
    m = _undirected_edge_count(adj)
    giant = _components(nodes, adj)[0]
    obs_svn = _von_neumann_entropy(adj, giant) / math.log(len(giant)) if len(giant) > 1 else 0.0
    obs_clu = _mean_local_clustering(nodes, adj)
    obs_deg = _degree_entropy(nodes, adj) / math.log(n) if n > 1 else 0.0
    svn_s, clu_s, deg_s = [], [], []
    for _ in range(nulls):
        hn, ha = _er_null(n, m, rng)
        hg = _components(hn, ha)[0]
        svn_s.append(_von_neumann_entropy(ha, hg) / math.log(len(hg)) if len(hg) > 1 else 0.0)
        clu_s.append(_mean_local_clustering(hn, ha))
        deg_s.append(_degree_entropy(hn, ha) / math.log(n) if n > 1 else 0.0)

    def z(obs: float, sample: list[float]) -> dict[str, float]:
        if not sample:
            return {"observed": round(obs, 4), "null_mean": 0.0, "null_sd": 0.0, "z": 0.0}
        mu = sum(sample) / len(sample)
        sd = math.sqrt(sum((x - mu) ** 2 for x in sample) / len(sample))
        return {
            "observed": round(obs, 4),
            "null_mean": round(mu, 4),
            "null_sd": round(sd, 4),
            "z": round((obs - mu) / sd, 3) if sd > 1e-9 else 0.0,
        }

    return {
        "vn_entropy_norm": z(obs_svn, svn_s),
        "mean_clustering": z(obs_clu, clu_s),
        "degree_entropy_norm": z(obs_deg, deg_s),
    }


# ------------------------------ core metrics ----------------------------

def _core_metrics(nodes: list[str], adj: dict[str, set[str]], directed_edge_count: int, edge_types: list[str]) -> dict[str, Any]:
    n = len(nodes)
    m = _undirected_edge_count(adj)
    comps = _components(nodes, adj)
    giant = comps[0] if comps else []
    diam, eff = _diameter_and_effective(adj, giant)
    tri, wedge = _triangles_and_wedges(nodes, adj)
    transitivity = (3 * tri / wedge) if wedge else 0.0
    isolates = sum(1 for v in nodes if not adj[v])
    leaves = sum(1 for v in nodes if len(adj[v]) == 1)
    aps, bridges = _articulation_points_and_bridges(nodes, adj)
    svn = _von_neumann_entropy(adj, giant)
    svn_norm = svn / math.log(len(giant)) if len(giant) > 1 else 0.0
    return {
        "N": n,
        "E_directed": directed_edge_count,
        "E_undirected_simple": m,
        "density_undirected": round(2 * m / (n * (n - 1)), 5) if n > 1 else 0.0,
        "mean_degree": round(2 * m / n, 3) if n else 0.0,
        "components": len(comps),
        "giant_fraction": round(len(giant) / n, 4) if n else 0.0,
        "diameter_giant": diam,
        "effective_diameter_p90": eff,
        "isolates": isolates,
        "leaf_fraction": round(leaves / n, 4) if n else 0.0,
        "articulation_points": aps,
        "bridges": bridges,
        "transitivity": round(transitivity, 4),
        "open_triad_ratio": round(1.0 - transitivity, 4),
        "mean_local_clustering": round(_mean_local_clustering(nodes, adj), 4),
        "type_entropy": round(_type_entropy(edge_types), 4),
        "degree_entropy_norm": round(_degree_entropy(nodes, adj) / math.log(n), 4) if n > 1 else 0.0,
        "compressibility_ratio": round(_compressibility_ratio(nodes, adj), 4),
        "vn_entropy": round(svn, 4),
        "vn_entropy_norm": round(svn_norm, 4),
    }


def _bootstrap_stability(nodes: list[str], edges: list[tuple[str, str]], resamples: int, drop: float, rng: random.Random) -> dict[str, Any]:
    keys = ["giant_fraction", "open_triad_ratio", "mean_local_clustering",
            "degree_entropy_norm", "vn_entropy_norm", "effective_diameter_p90"]
    acc: dict[str, list[float]] = {k: [] for k in keys}
    for _ in range(resamples):
        kept = [e for e in edges if rng.random() > drop]
        hn, ha = _build_adjacency(list(nodes), kept)
        m = _core_metrics(hn, ha, len(kept), ["edge"] * len(kept))
        for k in keys:
            acc[k].append(m[k])
    out: dict[str, Any] = {}
    for k in keys:
        vals = acc[k]
        if not vals:
            out[k] = {"mean": 0.0, "sd": 0.0, "cv": 0.0}
            continue
        mu = sum(vals) / len(vals)
        sd = math.sqrt(sum((x - mu) ** 2 for x in vals) / len(vals))
        out[k] = {"mean": round(mu, 4), "sd": round(sd, 4), "cv": round(sd / mu, 4) if abs(mu) > 1e-9 else 0.0}
    return out


def _current_value(nodes: list[str], adj: dict[str, set[str]], usage: Any) -> dict[str, Any]:
    """Pillar 2. Realized value from usage traces; unavailable without them."""
    if not isinstance(usage, dict):
        return {
            "status": "unavailable",
            "reason": "requires FlowElement usage traces; supply usage.nodeReads/usage.edgeTraversals to enable",
        }
    node_reads = usage.get("nodeReads", {})
    edge_traversals = usage.get("edgeTraversals", {})
    if not isinstance(node_reads, dict):
        node_reads = {}
    if not isinstance(edge_traversals, dict):
        edge_traversals = {}
    n = len(nodes)
    m = _undirected_edge_count(adj)
    touched_nodes = sum(1 for v in nodes if float(node_reads.get(v, 0)) > 0)
    total_reads = sum(float(x) for x in node_reads.values())
    total_traversals = sum(float(x) for x in edge_traversals.values())
    return {
        "status": "available",
        "read_coverage": round(touched_nodes / n, 4) if n else 0.0,
        "total_node_reads": round(total_reads, 3),
        "total_edge_traversals": round(total_traversals, 3),
        "usage_weighted_active_fraction": round(touched_nodes / n, 4) if n else 0.0,
        "note": "realized-value proxy from supplied usage; not a price",
    }


# ------------------------------ the cell --------------------------------

class StructuralValueProfileCell(GeneralCell):
    """Content-blind Structural Value Profile for typed HAVEN graphs."""

    def __init__(self, owner: Any | None = None, name: str = "StructuralValueProfile", uuid: str | None = None) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self._graph_id: str | None = None
        self._nodes: list[str] = []
        self._edges: list[tuple[str, str]] = []
        self._edge_types: list[str] = []
        self._last_profile: dict[str, Any] | None = None
        self.agreement_template.add_grant("rw--", "graph.profile")
        self._get_handlers["graph.profile.state"] = self._get_state
        for key in ("graph.profile.load", "graph.profile.fromGraphIndex", "graph.profile.compute"):
            self._set_handlers[key] = self._set_profile

    async def _get_state(self, keypath: str, requester: Any | None) -> dict[str, Any]:
        _ = keypath, requester
        return {
            "status": "ready",
            "schemaVersion": STATE_SCHEMA,
            "graphID": self._graph_id,
            "N": len(self._nodes),
            "E": len(self._edges),
            "hasProfile": self._last_profile is not None,
        }

    async def _set_profile(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        _ = requester
        payload = from_json_value(value)
        if not isinstance(payload, dict):
            return {"status": "error", "message": "payload must be object"}
        if keypath == "graph.profile.load":
            return self._load_edgelist(payload)
        if keypath == "graph.profile.fromGraphIndex":
            return self._load_from_graph_index(payload)
        if keypath == "graph.profile.compute":
            return self._compute(payload)
        return {"status": "error", "message": f"unknown operation {keypath}"}

    # -- loading --

    def _ingest(self, graph_id: Any, node_items: Any, edge_pairs: list[tuple[str, str]], edge_types: list[str]) -> dict[str, Any]:
        node_ids = []
        if isinstance(node_items, list):
            for item in node_items:
                if isinstance(item, dict) and isinstance(item.get("id"), str):
                    node_ids.append(item["id"])
                elif isinstance(item, str):
                    node_ids.append(item)
        self._graph_id = graph_id if isinstance(graph_id, str) else None
        self._nodes, _ = _build_adjacency(node_ids, edge_pairs)
        self._edges = edge_pairs
        self._edge_types = edge_types
        self._last_profile = None
        return {"status": "ok", "graphID": self._graph_id, "N": len(self._nodes), "E": len(self._edges)}

    def _load_edgelist(self, payload: dict[str, Any]) -> dict[str, Any]:
        edges: list[tuple[str, str]] = []
        types: list[str] = []
        for e in payload.get("edges", []):
            if isinstance(e, dict) and isinstance(e.get("u"), str) and isinstance(e.get("v"), str):
                edges.append((e["u"], e["v"]))
                types.append(e.get("type") if isinstance(e.get("type"), str) else "edge")
        return self._ingest(payload.get("graphID"), payload.get("nodes"), edges, types)

    def _load_from_graph_index(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Accept a GraphIndexCell graph.state payload ({nodes, edges:[{from,to}]})."""
        edges: list[tuple[str, str]] = []
        types: list[str] = []
        for e in payload.get("edges", []):
            if isinstance(e, dict) and isinstance(e.get("from"), str) and isinstance(e.get("to"), str):
                edges.append((e["from"], e["to"]))
                types.append("edge")
        nodes = payload.get("nodes")
        return self._ingest(payload.get("graphID"), nodes, edges, types)

    # -- compute --

    def _compute(self, payload: dict[str, Any]) -> dict[str, Any]:
        if isinstance(payload.get("graph"), dict):
            self._load_edgelist(payload["graph"])
        if not self._nodes:
            return {"status": "error", "message": "no graph loaded; call graph.profile.load first or pass inline graph"}

        nulls = _clamp_int(payload.get("nulls", 100), 0, 1000)
        bootstrap = _clamp_int(payload.get("bootstrap", 100), 0, 1000)
        drop = _clamp_float(payload.get("drop", 0.1), 0.0, 0.9)
        seed = _clamp_int(payload.get("seed", 7), 0, 2**31 - 1)
        rng = random.Random(seed)

        _, adj = _build_adjacency(list(self._nodes), self._edges)
        m = _core_metrics(self._nodes, adj, len(self._edges), self._edge_types or ["edge"] * len(self._edges))
        box_scales = m["diameter_giant"]
        profile = {
            "status": "ok",
            "schemaVersion": STATE_SCHEMA,
            "graphID": self._graph_id,
            "pillar1_scale_health": {k: m[k] for k in (
                "N", "E_directed", "E_undirected_simple", "density_undirected", "mean_degree",
                "components", "giant_fraction", "diameter_giant", "effective_diameter_p90",
                "isolates", "leaf_fraction")},
            "pillar2_current_value": _current_value(self._nodes, adj, payload.get("usage")),
            "pillar3_potential_value": {k: m[k] for k in (
                "open_triad_ratio", "mean_local_clustering", "articulation_points", "bridges",
                "leaf_fraction", "type_entropy")},
            "pillar4_complexity": {k: m[k] for k in (
                "vn_entropy", "vn_entropy_norm", "degree_entropy_norm", "compressibility_ratio")},
            "fractal_gate": {
                "usable_box_scales": box_scales,
                "estimable": box_scales >= FRACTAL_MIN_BOX_SCALES,
                "note": f"box-covering fractal dimension gated off below ~{FRACTAL_MIN_BOX_SCALES} usable radii (advisory 2026-07-04)",
            },
            "null_model_zscores": _null_zscores(self._nodes, adj, nulls, rng) if nulls > 0 else {},
            "bootstrap_stability": _bootstrap_stability(list(self._nodes), self._edges, bootstrap, drop, rng) if bootstrap > 0 else {},
            "params": {"nulls": nulls, "bootstrap": bootstrap, "drop": drop, "seed": seed},
        }
        self._last_profile = profile
        self._emit_audit(profile)
        return profile

    def _emit_audit(self, profile: dict[str, Any]) -> None:
        digest = hashlib.sha256(
            json.dumps({"nodes": sorted(self._nodes), "edges": sorted(self._edges)}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.push_flow_element(
            FlowElement(
                title="Structural value profile computed",
                content={
                    "graphID": self._graph_id,
                    "N": profile["pillar1_scale_health"]["N"],
                    "E": profile["pillar1_scale_health"]["E_directed"],
                    "vn_entropy_norm": profile["pillar4_complexity"]["vn_entropy_norm"],
                    "fractal_estimable": profile["fractal_gate"]["estimable"],
                    "inputHash": "sha256:" + digest,
                    "params": profile["params"],
                },
                topic="graph.profile.computed",
                origin=self.uuid,
            )
        )


def _clamp_int(value: Any, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return low


def _clamp_float(value: Any, low: float, high: float) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return low
