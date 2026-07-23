"""Assemble a sealed `blast_radius` evidence record from composed paths.

Each path becomes one finding. The `detection_method` is chosen per path so the builder's
method↔strength binding does the honesty enforcement for free: a composed multi-edge path is
`graph_derivation` (→ `INFERRED`), a fully-observed path is `dynamic_observation`
(→ `DIRECT_OBSERVATION`), a blocked path is `dynamic_blocked_observation`. There is no path
shape that lets a composed guess acquire an observation's evidence_strength — the builder would
reject it.
"""

from __future__ import annotations

from ..evidence import make_finding, make_record, make_scope
from ..evidence.status import Status
from .model import BlastPath
from .provenance import PathConfidence

#: The permitted framing, verbatim. TrustLens never claims it prevented the July 2026 incident.
_CLAIMS = {
    "establishes": [
        "For each reported path, the edges that compose it and how each edge was established.",
        "Which paths are fully dynamically observed, which are composed from configuration or "
        "static findings, and which were observed to be blocked.",
    ],
    "does_not_establish": [
        "That any composed path is traversable end to end.",
        "That a path absent from this record does not exist — only supplied edges were "
        "considered.",
        "That the artifact caused, or that TrustLens prevented, any real-world incident.",
        "Anything about the environment after the capture time of the edges it rests on.",
    ],
}

_GENERIC_ADVICE = [
    "Treat every path at the confidence of its weakest edge, which is the label on each path. "
    "A path containing an inferred or PARTIAL edge is not an observed path.",
]


def _detection_method(path: BlastPath) -> str:
    """Pick the detection_method so the builder assigns the honest evidence_strength.

    The whole point: the method is derived from what the path actually is, and the builder then
    forces the matching strength. A composed path cannot be dressed as an observation.
    """
    if path.is_blocked:
        return "dynamic_blocked_observation"
    if path.confidence is PathConfidence.OBSERVED:
        return "dynamic_observation"
    if len(path.edges) == 1 and path.confidence is PathConfidence.CONFIGURATION_DERIVED:
        return "config_derivation"
    return "graph_derivation"


def path_to_finding(path: BlastPath) -> dict:
    """Build one sealed-schema finding for a path, via the evidence builder's guards."""
    chain = " -> ".join(e.source.key for e in path.edges) + f" -> {path.asset.key}"
    analysed = [e.source.key for e in path.edges] + [path.asset.key]

    # The path status is the weakest edge (model.weakest_status). Each of the five states needs
    # its own companion field, or the builder refuses it — that refusal is the honesty guard, so
    # we satisfy it rather than flatten every path to FOUND.
    failed: list[dict] = []
    status = path.status if not path.is_blocked else Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
    unknown_reason: str | None = None
    unsupported_construct: str | None = None

    weakest = path.weakest_edge
    if status is Status.PARTIAL:
        for edge in path.edges:
            if edge.is_partial:
                failed.append({
                    "path": f"{edge.source.key} -> {edge.target.key}",
                    "kind": "partial_edge",
                    "reason": "the analysis behind this edge did not complete; the path "
                              "cannot be fully established.",
                })
    elif status is Status.UNKNOWN:
        unknown_reason = (
            f"the edge {weakest.source.key} -> {weakest.target.key} has status UNKNOWN, so the "
            "path's traversability cannot be established."
        )
    elif status is Status.UNSUPPORTED:
        unsupported_construct = (
            f"an edge on this path ({weakest.source.key} -> {weakest.target.key}) rests on a "
            "finding the analysis could not support; the path cannot be established through it."
        )

    scope = make_scope(analysed=sorted(set(analysed)), languages=["graph"], failed=failed)

    # The derived_from ids are folded into the evidence detail so two paths that share a node
    # sequence but rest on DIFFERENT upstream findings get distinct finding_ids. Without this,
    # `worker->cred->s3` established by one scanner finding and by another would collide.
    evidence = [{
        "kind": "graph_edge",
        "path": None,
        "line": None,
        "excerpt": None,
        "redacted": False,
        "detail": chain + f"  [{'; '.join(e.provenance.value for e in path.edges)}]"
                  + f"  from:{','.join(path.derived_from())}",
    }]

    return make_finding(
        capability="reachability.resource_access",
        status=status,
        detection_method=_detection_method(path),
        rule_id="path-composition",
        rule_version="1.0.0",
        source_component="blast_radius",
        scope=scope,
        confidence_basis=(
            f"Path at confidence tier '{path.confidence.value}', capped by its weakest edge "
            f"(provenance '{path.weakest_edge.provenance.value}', relation "
            f"'{path.weakest_edge.relation}'). Composed from {len(path.edges)} edge(s)."
        ),
        limitations=path.all_limitations(),
        evidence=evidence,
        derived_from=path.derived_from(),
        unknown_reason=unknown_reason,
        unsupported_construct=unsupported_construct,
        notes="Path is BLOCKED: an edge was observed to be refused." if path.is_blocked else None,
    )


def mitigations_for(paths: list[BlastPath], *, environment_description_ref: dict) -> list[dict]:
    """One mitigation per LIVE path: cut its weakest edge to break the path.

    Blocked paths get no mitigation — they are already cut. Each mitigation names the edge to
    remove, the path it removes, and its residual risk (other paths were not exhaustively
    enumerated), and is `dynamically_verified` only when the path was fully observed. Each cites
    the environment description it rests on, so a mitigation carries the same staleness the
    edges it acts on carry.
    """
    out: list[dict] = []
    for i, path in enumerate(p for p in paths if not p.is_blocked):
        edge = path.weakest_edge
        chain = " -> ".join(e.source.key for e in path.edges) + f" -> {path.asset.key}"
        out.append({
            "mitigation_id": f"M-{i + 1:03d}",
            "affected_resource": edge.target.key,
            "proposed_change": (
                f"Remove or tighten the '{edge.relation}' edge {edge.source.key} -> "
                f"{edge.target.key} (established: {edge.provenance.value}), which this path "
                "traverses."
            ),
            "expected_path_removed": chain,
            "residual_risk": (
                "Other paths to the same asset were not exhaustively enumerated; removing this "
                "edge addresses this path only."
            ),
            "trade_offs": (
                "Any legitimate workflow that relies on this edge will stop working until it is "
                "re-granted with a narrower scope."
            ),
            "triggering_finding_ids": path.derived_from(),
            "dynamically_verified": path.confidence.value == "observed",
            "evidence_basis": (
                f"The weakest edge of a path at tier '{path.confidence.value}', established via "
                f"'{edge.provenance.value}'."
            ),
            "environment_description_ref": environment_description_ref,
        })
    return out


def build_record(
    paths: list[BlastPath],
    *,
    artifact: dict,
    input_records: list[dict],
    tool_version: str,
    commit: str | None,
    started_at: str,
    completed_at: str,
    invocation: str,
    environment_description_ref: dict | None = None,
    mitigations: list[dict] | None = None,
    depth_bound_hit: bool = False,
) -> dict:
    """Assemble and seal the full blast_radius record."""
    findings = [path_to_finding(p) for p in paths]
    if mitigations is None:
        mitigations = (
            mitigations_for(paths, environment_description_ref=environment_description_ref)
            if environment_description_ref else []
        )
    # Generic advice may only accompany specific mitigations, never stand in for them.
    generic_advice = _GENERIC_ADVICE if mitigations else []

    observed = sum(1 for p in paths if p.confidence is PathConfidence.OBSERVED)
    composed = sum(1 for p in paths if p.confidence is PathConfidence.INFERRED)
    blocked = sum(1 for p in paths if p.is_blocked)
    reasoning = [
        f"Composed {len(paths)} path(s): {observed} fully observed, {composed} inferred, "
        f"{blocked} blocked.",
        "Each path is recorded at the confidence of its weakest edge; blocked and partial "
        "paths are retained and labelled, never dropped.",
    ]
    if depth_bound_hit:
        reasoning.append(
            "The path search hit its depth bound on at least one branch; some longer paths may "
            "exist and were not enumerated (a coverage limit, not an absence claim)."
        )

    all_analysed = sorted({e.source.key for p in paths for e in p.edges} |
                          {p.asset.key for p in paths})

    return make_record(
        component="blast_radius",
        tool_version=tool_version,
        commit=commit,
        artifact=artifact,
        run={
            "started_at": started_at,
            "completed_at": completed_at,
            "execution_mode": "offline_modelling",
            "invocation": invocation,
            "config_hash": None,
            "reasoning_notes": reasoning,
        },
        scope=make_scope(analysed=all_analysed, languages=["graph"]),
        claims=_CLAIMS,
        residual_uncertainty=(
            "This record composes evidence records; it observes nothing itself. Composed paths "
            "are inferences about reachability, not demonstrations of it. A path shown here at "
            "any tier below OBSERVED was not watched to occur."
        ),
        findings=findings,
        mitigations=list(mitigations),
        generic_advice=generic_advice,
        environment_description_ref=environment_description_ref,
        input_records=input_records,
    )
