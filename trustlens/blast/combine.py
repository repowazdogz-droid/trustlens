"""Compose scanner + mapper + sandbox evidence into one provenance-labelled blast graph.

Each source contributes edges tagged with how it established them:

* mapper edges          → `configured` / `inferred` / `unknown` (from the edge's Reachability)
* scanner findings      → `statically_found`, or `declared` for declared capabilities
* sandbox findings      → `dynamically_observed`, or `dynamically_blocked` for a blocked attempt

Edges union on shared node identity — the same `namespace/name` convention the Phase 2
cross-component identity tests already guard, so a scanner capability, a mapper principal and a
sandbox observation about the same thing land on the same node rather than three disconnected
ones.

A dynamic observation does not silently overwrite a configured edge: both are kept, each with
its own provenance, so the record shows that a configured edge was *also* observed (or observed
to be blocked) rather than erasing how it was first established.
"""

from __future__ import annotations

from ..evidence.status import Status
from ..mapper.model import Graph as MapperGraph, Node, NodeKind, Reachability
from .model import BlastEdge, BlastGraph
from .provenance import EdgeProvenance

#: How a mapper edge's Reachability becomes a blast provenance label.
_REACHABILITY_TO_PROVENANCE = {
    Reachability.CONFIGURED: EdgeProvenance.CONFIGURED,
    Reachability.INFERRED: EdgeProvenance.INFERRED,
    Reachability.BLOCKED: EdgeProvenance.DYNAMICALLY_BLOCKED,
    Reachability.UNKNOWN: EdgeProvenance.UNKNOWN,
}


def edges_from_mapper(graph: MapperGraph) -> list[BlastEdge]:
    """Convert configured/inferred reachability edges into blast edges, provenance preserved."""
    out: list[BlastEdge] = []
    for edge in graph.sorted_edges():
        provenance = _REACHABILITY_TO_PROVENANCE.get(edge.reachability, EdgeProvenance.UNKNOWN)
        out.append(
            BlastEdge(
                source=edge.source,
                target=edge.target,
                relation=edge.kind.value,
                provenance=provenance,
                status=Status.FOUND,
                derived_from=(f"credential_mapper:{edge.rule_id}:{_short(edge.evidence_path, edge.evidence_pointer)}",),
                description_captured_at=edge.description_captured_at,
                evidence_detail=edge.evidence_excerpt or f"{edge.source.key} {edge.kind.value} {edge.target.key}",
                limitations=edge.limitations or ("Derived from configuration; not observed.",),
            )
        )
    return out


def edges_from_scanner(
    scan_record: dict,
    entry: Node,
    *,
    capability_targets: dict[str, Node],
    description_captured_at: str,
) -> list[BlastEdge]:
    """Edges from the artifact entry node to the capability nodes the scanner found.

    `capability_targets` maps a capability string to the node it reaches (supplied by the
    caller / environment description, because which principal a capability acts as is an
    operator fact, not something the scanner can know). A capability with no mapping is skipped
    and left to the coverage reconciliation, never silently dropped into a clean result.
    """
    out: list[BlastEdge] = []
    # declared_capabilities entries are dicts ({"capability": ..., "declaration": ...}), not
    # bare strings — verified against the real scanner record, not assumed.
    declared = {
        d["capability"] if isinstance(d, dict) else d
        for d in (scan_record.get("declared_capabilities") or [])
    }
    for finding in scan_record.get("findings", []):
        capability = finding.get("capability")
        target = capability_targets.get(capability)
        if target is None:
            continue
        status = _status(finding.get("status"))
        if capability in declared and finding.get("source_component") == "declared":
            provenance = EdgeProvenance.DECLARED
        else:
            provenance = EdgeProvenance.STATICALLY_FOUND
        out.append(
            BlastEdge(
                source=entry,
                target=target,
                relation="exercises_capability",
                provenance=provenance,
                status=status,
                derived_from=(finding.get("finding_id", f"scanner:{capability}"),),
                description_captured_at=description_captured_at,
                evidence_detail=_finding_detail(finding),
                limitations=tuple(finding.get("limitations") or (
                    "Static finding: the capability exists in code; execution was not observed.",
                )),
            )
        )
    return out


def edges_from_sandbox(
    sandbox_record: dict,
    *,
    capability_targets: dict[str, Node],
    entry: Node,
) -> list[BlastEdge]:
    """Dynamic edges. A blocked observation becomes a `dynamically_blocked` edge, not a gap.

    The sandbox record's findings carry `detection_method`; a blocked attempt
    (`dynamic_blocked_observation`) is the negative observation that cuts a path, and it is
    represented as an edge so the path shows as blocked rather than as merely unproven.
    """
    out: list[BlastEdge] = []
    for finding in sandbox_record.get("findings", []):
        capability = finding.get("capability")
        target = capability_targets.get(capability)
        if target is None:
            continue
        method = finding.get("detection_method", "")
        blocked = "blocked" in method
        provenance = (
            EdgeProvenance.DYNAMICALLY_BLOCKED if blocked else EdgeProvenance.DYNAMICALLY_OBSERVED
        )
        out.append(
            BlastEdge(
                source=entry,
                target=target,
                relation="exercises_capability",
                provenance=provenance,
                status=_status(finding.get("status")),
                derived_from=(finding.get("finding_id", f"sandbox:{capability}"),),
                description_captured_at=finding.get("environment_description_ref", {}).get(
                    "description_captured_at"
                ) if isinstance(finding.get("environment_description_ref"), dict) else _run_time(sandbox_record),
                evidence_detail=_finding_detail(finding),
                limitations=tuple(finding.get("limitations") or (
                    "Observed in one execution under one profile with one input.",
                )),
            )
        )
    return out


def build_graph(*edge_lists: list[BlastEdge]) -> BlastGraph:
    """Union edge lists into one graph. Nothing is deduplicated: two edges of different
    provenance between the same nodes are both real evidence and both kept."""
    graph = BlastGraph()
    for edges in edge_lists:
        for edge in edges:
            graph.add(edge)
    return graph


# --------------------------------------------------------------------------- helpers

def _status(value: str | None) -> Status:
    if value is None:
        return Status.UNKNOWN
    try:
        return Status(value)
    except ValueError:
        return Status.UNKNOWN


def _finding_detail(finding: dict) -> str:
    evidence = finding.get("evidence") or []
    if evidence and isinstance(evidence, list):
        detail = evidence[0].get("detail") or evidence[0].get("excerpt")
        if detail:
            return str(detail)[:200]
    return finding.get("confidence_basis", finding.get("capability", "?"))[:200]


def _run_time(record: dict) -> str:
    run = record.get("run") or {}
    return run.get("started_at") or ""


def _short(path: str, pointer: str | None) -> str:
    import hashlib

    return hashlib.sha256(f"{path}{pointer or ''}".encode()).hexdigest()[:16]
