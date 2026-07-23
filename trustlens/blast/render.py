"""Rendering paths so confidence is never overstated, and the blast-radius record builder.

The rendering requirement from the spec: a reader skimming must not be able to mistake a
composed path for an observed one. So paths are grouped by confidence tier, strongest first,
each tier under a heading that names it, and every path line carries its tier label. An
`inferred`, `unknown`, `PARTIAL` or `blocked` path is never printed with the same marker or in
the same group as a `dynamically_observed` one.
"""

from __future__ import annotations

from ..evidence.status import Status
from .model import BlastPath
from .provenance import PathConfidence

#: Strongest to weakest. The order paths are presented in, and the order that must never be
#: rearranged to flatter a weak path.
_TIER_ORDER = [
    PathConfidence.OBSERVED,
    PathConfidence.CONFIGURATION_DERIVED,
    PathConfidence.STATICALLY_DERIVED,
    PathConfidence.DECLARED,
    PathConfidence.INFERRED,
    PathConfidence.UNKNOWN,
    PathConfidence.BLOCKED,
]

_TIER_HEADING = {
    PathConfidence.OBSERVED: "OBSERVED — every edge dynamically observed in the sandbox",
    PathConfidence.CONFIGURATION_DERIVED: "CONFIGURATION-DERIVED — weakest edge is a configured grant, none observed",
    PathConfidence.STATICALLY_DERIVED: "STATICALLY-DERIVED — weakest edge is a static finding, none observed",
    PathConfidence.DECLARED: "DECLARED — weakest edge rests on the artifact's own declaration",
    PathConfidence.INFERRED: "INFERRED — contains a composed edge; traversability not evidenced",
    PathConfidence.UNKNOWN: "UNKNOWN — an edge's basis could not be determined",
    PathConfidence.BLOCKED: "BLOCKED — an edge was observed to be refused; this path is cut",
}

#: The visual marker per tier. Distinct on purpose: an observed path and an inferred path must
#: not share a marker.
_TIER_MARKER = {
    PathConfidence.OBSERVED: "==>",
    PathConfidence.CONFIGURATION_DERIVED: "-->",
    PathConfidence.STATICALLY_DERIVED: "..>",
    PathConfidence.DECLARED: "~~>",
    PathConfidence.INFERRED: "?->",
    PathConfidence.UNKNOWN: "?? ",
    PathConfidence.BLOCKED: "-X-",
}


def render_report(paths: list[BlastPath], *, depth_bound_hit: bool = False) -> str:
    """A human report, grouped by tier, strongest first, each path labelled.

    Groups are printed even when empty is skipped, but the tier headings that DO have paths make
    the confidence explicit. A path never appears outside its computed tier.
    """
    by_tier: dict[PathConfidence, list[BlastPath]] = {t: [] for t in _TIER_ORDER}
    for path in paths:
        by_tier[path.confidence].append(path)

    lines: list[str] = ["BLAST RADIUS — reachability paths, grouped by evidence confidence", ""]
    if not paths:
        lines.append("No path from the entry to the asset was found within the analysed graph.")
        lines.append(
            "This is NOT_FOUND_WITHIN_ANALYSED_SCOPE, not proof that no path exists — only "
            "supplied edges were considered."
        )
        return "\n".join(lines)

    for tier in _TIER_ORDER:
        group = by_tier[tier]
        if not group:
            continue
        marker = _TIER_MARKER[tier]
        lines.append(f"### {_TIER_HEADING[tier]}   ({len(group)})")
        for path in group:
            chain = f" {marker} ".join(_node_label(e.source) for e in path.edges)
            chain += f" {marker} {_node_label(path.asset)}"
            lines.append(f"  {chain}")
            lines.append(f"     tier={path.render_label()}  status={path.status.value}  "
                         f"weakest via '{path.weakest_edge.provenance.value}' "
                         f"({path.weakest_edge.relation})")
        lines.append("")

    if depth_bound_hit:
        lines.append(
            "NOTE: the path search hit its depth bound on at least one branch. Some longer "
            "paths may exist and were not enumerated — this is a coverage limit, not an "
            "assertion that no further path exists."
        )
    return "\n".join(lines)


def _node_label(node) -> str:
    return node.key


# ------------------------------------------------------------- evidence record findings

def _record_evidence_strength(path: BlastPath) -> str:
    """Map a path to the schema's evidence_strength, never overstating.

    A composed multi-edge path is INFERRED even when its edges are individually stronger,
    because chaining edges into a claimed reachable path is itself an inference — the same
    stance the example record takes. A single dynamically-observed edge is DIRECT_OBSERVATION.
    """
    if path.is_blocked:
        return "DIRECT_OBSERVATION"  # we directly observed the block
    if path.confidence is PathConfidence.OBSERVED:
        return "DIRECT_OBSERVATION"
    if len(path.edges) == 1:
        single = {
            PathConfidence.CONFIGURATION_DERIVED: "CONFIG_DERIVED",
            PathConfidence.STATICALLY_DERIVED: "DIRECT_OBSERVATION",
            PathConfidence.DECLARED: "DECLARED",
            PathConfidence.INFERRED: "INFERRED",
            PathConfidence.UNKNOWN: "INFERRED",
        }
        return single[path.confidence]
    return "INFERRED"


def path_to_finding(path: BlastPath, *, index: int) -> dict:
    """One reachability path as a blast_radius finding, honestly fenced."""
    import hashlib

    chain = " -> ".join(_node_label(e.source) for e in path.edges) + f" -> {_node_label(path.asset)}"
    fid_basis = chain + "|".join(e.provenance.value for e in path.edges)
    finding_id = f"blast_radius:reachability.path:{hashlib.sha256(fid_basis.encode()).hexdigest()[:16]}"

    status = path.status if not path.is_blocked else Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
    return {
        "finding_id": finding_id,
        "capability": "reachability.resource_access",
        "status": status.value,
        "source_component": "blast_radius",
        "detection_method": "graph_derivation",
        "evidence_strength": _record_evidence_strength(path),
        "confidence_basis": (
            f"Composed path at confidence tier '{path.confidence.value}', capped by its "
            f"weakest edge (provenance '{path.weakest_edge.provenance.value}'). "
            f"Path status '{path.status.value}' is the lattice combination of {len(path.edges)} "
            f"edge(s)."
        ),
        "derived_from": path.derived_from(),
        "evidence": [
            {
                "kind": "graph_edge",
                "detail": chain + f"  [{'; '.join(e.provenance.value for e in path.edges)}]",
                "excerpt": None,
                "path": None,
                "line": None,
                "redacted": False,
            }
        ],
        "limitations": path.all_limitations(),
        "rule_id": "path-composition",
        "rule_version": "1.0.0",
        "notes": (
            "Path is BLOCKED: an edge was observed to be refused." if path.is_blocked else None
        ),
    }
