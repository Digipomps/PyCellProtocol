"""GraphMetricsCompareCell: compare two Structural Value Profiles.

Serves the two use cases the fractal-dimension advisory (2026-07-04) named for
content-blind structural metrics:

- **Dataset exchange** — put two datasets side by side and see which carries
  more non-random structural signal, size-normalized, as a comparability
  "nutrition label" (never a price).
- **Growth over time** — compare a graph's profile at t0 vs t1 and classify the
  growth as realized-use, integration, or expansion/novelty, with a padding
  warning when size grows but structure thins.

Content-blind and analysis-only. Reuses `compute_profile` so the numbers match
`StructuralValueProfileCell` exactly.

Wire surface:
- set graph.compare.profiles  {a:<profile>, b:<profile>, mode?, labels?}
- set graph.compare.graphs    {a:<edgelist>, b:<edgelist>, mode?, labels?, params?}
- get graph.compare.state     -> {status, schemaVersion, hasComparison, mode}
"""

from __future__ import annotations

from typing import Any

from ..general_cell import FlowElement, GeneralCell
from ..value import from_json_value
from .structural_value_profile import compute_profile, edgelist_from_payload

STATE_SCHEMA = "haven.graph.metrics-compare.v1"

CAVEATS = [
    "structure is a value proxy, not a price; task/marginal-contribution value needs usage or Shapley-style methods",
    "comparisons are only meaningful for graphs of the same kind/purpose",
    "small graphs (N < 1e3, diameter < 15) have unstable clustering/diameter; lead with spectral + degree entropy",
    "leaders are content-blind structural signal, not truth, correctness, or usefulness of the data",
]


def _num(profile: dict[str, Any], pillar: str, key: str) -> float | None:
    section = profile.get(pillar)
    if isinstance(section, dict) and isinstance(section.get(key), (int, float)) and not isinstance(section.get(key), bool):
        return float(section[key])
    return None


def _z(profile: dict[str, Any], key: str) -> float | None:
    zs = profile.get("null_model_zscores")
    if isinstance(zs, dict) and isinstance(zs.get(key), dict):
        val = zs[key].get("z")
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return float(val)
    return None


def _delta(a: float | None, b: float | None) -> dict[str, Any]:
    out: dict[str, Any] = {"a": a, "b": b}
    if a is not None and b is not None:
        out["delta"] = round(b - a, 4)
    return out


def _leader(a: float | None, b: float | None, labels: dict[str, str]) -> str:
    if a is None or b is None:
        return "n/a"
    if abs(a - b) < 1e-9:
        return "tie"
    return labels["a"] if a > b else labels["b"]


def compare_profiles(profile_a: dict[str, Any], profile_b: dict[str, Any], *, mode: str, labels: dict[str, str]) -> dict[str, Any]:
    scale_keys = ["N", "E_undirected_simple", "giant_fraction", "effective_diameter_p90", "leaf_fraction"]
    potential_keys = ["open_triad_ratio", "mean_local_clustering", "bridges", "articulation_points"]
    complexity_keys = ["vn_entropy_norm", "degree_entropy_norm", "compressibility_ratio"]

    comparison = {
        "scale": {k: _delta(_num(profile_a, "pillar1_scale_health", k), _num(profile_b, "pillar1_scale_health", k)) for k in scale_keys},
        "potential_value": {k: _delta(_num(profile_a, "pillar3_potential_value", k), _num(profile_b, "pillar3_potential_value", k)) for k in potential_keys},
        "complexity": {k: _delta(_num(profile_a, "pillar4_complexity", k), _num(profile_b, "pillar4_complexity", k)) for k in complexity_keys},
    }

    # Null-normalized structural signal (preferred) with raw fallback.
    za_vn, zb_vn = _z(profile_a, "vn_entropy_norm"), _z(profile_b, "vn_entropy_norm")
    za_cl, zb_cl = _z(profile_a, "mean_clustering"), _z(profile_b, "mean_clustering")
    raw_a_vn, raw_b_vn = _num(profile_a, "pillar4_complexity", "vn_entropy_norm"), _num(profile_b, "pillar4_complexity", "vn_entropy_norm")

    richness_a = za_vn if za_vn is not None else raw_a_vn
    richness_b = zb_vn if zb_vn is not None else raw_b_vn
    read_a = _read_coverage(profile_a)
    read_b = _read_coverage(profile_b)

    scorecard = {
        "structural_richness": {
            "basis": "null-normalized spectral entropy" if za_vn is not None else "raw normalized spectral entropy",
            "a": round(richness_a, 4) if richness_a is not None else None,
            "b": round(richness_b, 4) if richness_b is not None else None,
            "leader": _leader(richness_a, richness_b, labels),
        },
        "integration": {
            "basis": "null-normalized clustering" if za_cl is not None else "raw clustering",
            "a": round(za_cl if za_cl is not None else (_num(profile_a, "pillar3_potential_value", "mean_local_clustering") or 0.0), 4),
            "b": round(zb_cl if zb_cl is not None else (_num(profile_b, "pillar3_potential_value", "mean_local_clustering") or 0.0), 4),
            "leader": _leader(
                za_cl if za_cl is not None else _num(profile_a, "pillar3_potential_value", "mean_local_clustering"),
                zb_cl if zb_cl is not None else _num(profile_b, "pillar3_potential_value", "mean_local_clustering"),
                labels,
            ),
        },
        "realized_use": {
            "basis": "pillar-2 read coverage from usage traces",
            "a": read_a,
            "b": read_b,
            "leader": _leader(read_a, read_b, labels) if (read_a is not None and read_b is not None) else "unavailable",
        },
    }

    result = {
        "status": "ok",
        "schemaVersion": STATE_SCHEMA,
        "mode": mode,
        "labels": labels,
        "comparison": comparison,
        "scorecard": scorecard,
        "caveats": CAVEATS,
    }
    if mode == "growth":
        result["growth"] = _growth_assessment(profile_a, profile_b, labels)
    return result


def _read_coverage(profile: dict[str, Any]) -> float | None:
    p2 = profile.get("pillar2_current_value")
    if isinstance(p2, dict) and p2.get("status") == "available":
        val = p2.get("read_coverage")
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return float(val)
    return None


def _growth_assessment(before: dict[str, Any], after: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
    def d(pillar: str, key: str) -> float:
        a = _num(before, pillar, key)
        b = _num(after, pillar, key)
        return (b - a) if (a is not None and b is not None) else 0.0

    dN = d("pillar1_scale_health", "N")
    dgiant = d("pillar1_scale_health", "giant_fraction")
    dclust = d("pillar3_potential_value", "mean_local_clustering")
    dleaf = d("pillar1_scale_health", "leaf_fraction")
    ddeg = d("pillar4_complexity", "degree_entropy_norm")
    dcompress = d("pillar4_complexity", "compressibility_ratio")
    read_before, read_after = _read_coverage(before), _read_coverage(after)
    d_read = (read_after - read_before) if (read_before is not None and read_after is not None) else None

    signals = []
    if d_read is not None and d_read > 0.01:
        signals.append("realized-use growth (read coverage up)")
    if dgiant > 0.01 or dclust > 0.01:
        signals.append("integration growth (giant/clustering up)")
    if dN > 0 and (dleaf > 0.02 or ddeg > 0.01):
        signals.append("expansion/novelty growth (new peripheral structure)")
    padding_warning = dN > 0 and dcompress < -0.05 and dgiant <= 0 and dclust <= 0
    if padding_warning:
        signals.append("WARNING: size grew but structure thinned — possible padding/gaming")
    if not signals:
        signals.append("no clear structural growth signal")

    return {
        "from": labels["a"],
        "to": labels["b"],
        "deltas": {
            "N": round(dN, 4),
            "giant_fraction": round(dgiant, 4),
            "mean_local_clustering": round(dclust, 4),
            "leaf_fraction": round(dleaf, 4),
            "degree_entropy_norm": round(ddeg, 4),
            "compressibility_ratio": round(dcompress, 4),
            "read_coverage": round(d_read, 4) if d_read is not None else None,
        },
        "signals": signals,
        "padding_warning": padding_warning,
    }


class GraphMetricsCompareCell(GeneralCell):
    """Compare two Structural Value Profiles for exchange or growth."""

    def __init__(self, owner: Any | None = None, name: str = "GraphMetricsCompare", uuid: str | None = None) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self._last: dict[str, Any] | None = None
        self.agreement_template.add_grant("rw--", "graph.compare")
        self._get_handlers["graph.compare.state"] = self._get_state
        for key in ("graph.compare.profiles", "graph.compare.graphs"):
            self._set_handlers[key] = self._set_compare

    async def _get_state(self, keypath: str, requester: Any | None) -> dict[str, Any]:
        _ = keypath, requester
        return {
            "status": "ready",
            "schemaVersion": STATE_SCHEMA,
            "hasComparison": self._last is not None,
            "mode": self._last.get("mode") if self._last else None,
        }

    async def _set_compare(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        _ = requester
        payload = from_json_value(value)
        if not isinstance(payload, dict):
            return {"status": "error", "message": "payload must be object"}
        mode = payload.get("mode") if payload.get("mode") in ("exchange", "growth") else "exchange"
        labels_in = payload.get("labels") if isinstance(payload.get("labels"), dict) else {}
        labels = {"a": str(labels_in.get("a", "A")), "b": str(labels_in.get("b", "B"))}

        if keypath == "graph.compare.profiles":
            a, b = payload.get("a"), payload.get("b")
            if not isinstance(a, dict) or not isinstance(b, dict):
                return {"status": "error", "message": "a and b must be profile objects"}
            result = compare_profiles(a, b, mode=mode, labels=labels)
        elif keypath == "graph.compare.graphs":
            a, b = payload.get("a"), payload.get("b")
            if not isinstance(a, dict) or not isinstance(b, dict):
                return {"status": "error", "message": "a and b must be edgelist objects"}
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
            pa = self._profile_from_edgelist(a, params)
            pb = self._profile_from_edgelist(b, params)
            result = compare_profiles(pa, pb, mode=mode, labels=labels)
        else:
            return {"status": "error", "message": f"unknown operation {keypath}"}

        self._last = result
        self._emit_audit(result)
        return result

    def _profile_from_edgelist(self, payload: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        nodes, edges, types, graph_id = edgelist_from_payload(payload)
        return compute_profile(
            nodes, edges, types,
            nulls=_clamp_int(params.get("nulls", 100), 0, 1000),
            bootstrap=_clamp_int(params.get("bootstrap", 100), 0, 1000),
            drop=_clamp_float(params.get("drop", 0.1), 0.0, 0.9),
            seed=_clamp_int(params.get("seed", 7), 0, 2**31 - 1),
            usage=payload.get("usage"),
            graph_id=graph_id,
        )

    def _emit_audit(self, result: dict[str, Any]) -> None:
        self.push_flow_element(
            FlowElement(
                title="Graph metrics comparison",
                content={
                    "mode": result["mode"],
                    "labels": result["labels"],
                    "richness_leader": result["scorecard"]["structural_richness"]["leader"],
                    "padding_warning": result.get("growth", {}).get("padding_warning", False),
                },
                topic="graph.compare.completed",
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
