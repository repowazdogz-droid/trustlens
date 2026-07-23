"""Composing real source records into a blast graph, and enumerating paths honestly.

Uses the bundled example records where possible rather than hand-built fixtures, per the
standing rule to test against real tool-generated input before trusting a fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustlens.evidence.status import Status
from trustlens.mapper.model import Node, NodeKind
from trustlens.blast import combine
from trustlens.blast.model import BlastEdge, BlastGraph, BlastPath
from trustlens.blast.provenance import EdgeProvenance, PathConfidence
from trustlens.blast.render import render_report, path_to_finding

RECORDS = Path(__file__).resolve().parents[2] / "examples" / "records"


def _node(kind, name, ns=None):
    return Node(kind, name, namespace=ns)


def _edge(a, b, prov, status=Status.FOUND, relation="reaches"):
    return BlastEdge(
        source=a, target=b, relation=relation, provenance=prov, status=status,
        derived_from=(f"src:{a.key}->{b.key}",), description_captured_at="2026-06-01T00:00:00+00:00",
        evidence_detail=f"{a.key} {relation} {b.key}", limitations=("edge limitation",),
    )


# --------------------------------------------------------------- combine from real records

def test_sandbox_blocked_finding_becomes_a_blocked_edge():
    """The bundled sandbox record has a blocked metadata-endpoint finding.

    It must become a `dynamically_blocked` edge, not vanish. A blocked observation is evidence
    the path is cut, and dropping it would read as 'no such path was considered'.
    """
    sandbox = json.loads((RECORDS / "sandbox_record.json").read_text())
    worker = _node(NodeKind.SERVICE_ACCOUNT, "dataset-worker", "ml")
    targets = {"cloud.metadata_endpoint": _node(NodeKind.API_ENDPOINT, "169.254.169.254")}
    edges = combine.edges_from_sandbox(sandbox, capability_targets=targets, entry=worker)
    assert edges, "the blocked metadata finding should produce an edge"
    blocked = [e for e in edges if e.provenance is EdgeProvenance.DYNAMICALLY_BLOCKED]
    assert blocked, "a dynamic_blocked_observation must become a dynamically_blocked edge"


def test_sandbox_allowed_finding_becomes_an_observed_edge():
    sandbox = json.loads((RECORDS / "sandbox_record.json").read_text())
    worker = _node(NodeKind.SERVICE_ACCOUNT, "dataset-worker", "ml")
    targets = {"filesystem.write": _node(NodeKind.FILE, "/workspace/scratch")}
    edges = combine.edges_from_sandbox(sandbox, capability_targets=targets, entry=worker)
    observed = [e for e in edges if e.provenance is EdgeProvenance.DYNAMICALLY_OBSERVED]
    assert observed, "an allowed dynamic observation must become a dynamically_observed edge"


def test_scanner_findings_become_static_edges():
    scan = json.loads((RECORDS / "scanner_record.json").read_text())
    entry = _node(NodeKind.PROCESS, "artifact")
    # map whatever capabilities the example scanner reported to a shared credential node
    cred = _node(NodeKind.SECRET, "aws-credential")
    targets = {f["capability"]: cred for f in scan.get("findings", [])}
    if not targets:
        pytest.skip("example scanner record reported no findings to map")
    edges = combine.edges_from_scanner(
        scan, entry, capability_targets=targets, description_captured_at="2026-06-01T00:00:00+00:00"
    )
    assert edges
    assert all(e.provenance is EdgeProvenance.STATICALLY_FOUND for e in edges)


def test_a_capability_with_no_target_is_skipped_not_invented():
    """A capability the caller did not map is left out, never joined to a guessed node."""
    scan = {"findings": [{"capability": "unmapped.thing", "status": "FOUND", "finding_id": "x"}]}
    edges = combine.edges_from_scanner(
        scan, _node(NodeKind.PROCESS, "artifact"), capability_targets={},
        description_captured_at="2026-06-01T00:00:00+00:00",
    )
    assert edges == []


# ------------------------------------------------------------------ path enumeration

def test_paths_are_enumerated_and_blocked_ones_retained():
    entry = _node(NodeKind.PROCESS, "worker")
    cred = _node(NodeKind.SECRET, "cred")
    s3 = _node(NodeKind.STORAGE_RESOURCE, "prod-data")
    meta = _node(NodeKind.API_ENDPOINT, "metadata")

    g = BlastGraph()
    # a live configured path worker -> cred -> s3
    g.add(_edge(entry, cred, EdgeProvenance.STATICALLY_FOUND, relation="reads"))
    g.add(_edge(cred, s3, EdgeProvenance.CONFIGURED, relation="grants"))
    # a blocked path worker -> metadata
    g.add(_edge(entry, meta, EdgeProvenance.DYNAMICALLY_BLOCKED, relation="reaches"))

    live = g.enumerate_paths(entry, s3)
    assert len(live) == 1
    assert live[0].confidence is PathConfidence.STATICALLY_DERIVED

    blocked = g.enumerate_paths(entry, meta)
    assert len(blocked) == 1
    assert blocked[0].confidence is PathConfidence.BLOCKED, "the blocked path must be retained, labelled BLOCKED"


def test_render_groups_by_tier_and_never_mixes_observed_with_inferred():
    entry = _node(NodeKind.PROCESS, "worker")
    mid = _node(NodeKind.SECRET, "cred")
    a1 = _node(NodeKind.STORAGE_RESOURCE, "asset1")

    observed = BlastPath((_edge(entry, a1, EdgeProvenance.DYNAMICALLY_OBSERVED),))
    inferred = BlastPath((_edge(entry, mid, EdgeProvenance.DYNAMICALLY_OBSERVED),
                          _edge(mid, a1, EdgeProvenance.INFERRED)))
    report = render_report([observed, inferred])

    # The observed marker and the inferred marker must be different strings.
    from trustlens.blast.render import _TIER_MARKER
    assert _TIER_MARKER[PathConfidence.OBSERVED] != _TIER_MARKER[PathConfidence.INFERRED]
    assert "OBSERVED" in report and "INFERRED" in report
    # The inferred path is under its own heading, not the observed one.
    observed_idx = report.index("OBSERVED")
    inferred_idx = report.index("INFERRED — contains a composed edge")
    assert observed_idx < inferred_idx, "stronger tiers are presented first"


def test_empty_path_set_is_scoped_absence_not_a_clean_bill():
    report = render_report([])
    assert "NOT_FOUND_WITHIN_ANALYSED_SCOPE" in report
    assert "not proof that no path exists" in report


# ---------------------------------------------------------------- record findings

def test_composed_multiedge_path_records_as_inferred_even_with_strong_edges():
    """A composed path is INFERRED in the record even if its edges are configured/static —
    chaining is inference, and the example record takes exactly this stance."""
    entry = _node(NodeKind.PROCESS, "worker")
    cred = _node(NodeKind.SECRET, "cred")
    s3 = _node(NodeKind.STORAGE_RESOURCE, "prod-data")
    path = BlastPath((
        _edge(entry, cred, EdgeProvenance.STATICALLY_FOUND),
        _edge(cred, s3, EdgeProvenance.CONFIGURED),
    ))
    finding = path_to_finding(path, index=0)
    assert finding["evidence_strength"] == "INFERRED"
    assert "traversable end to end" in " ".join(finding["limitations"])
    assert finding["source_component"] == "blast_radius"
    assert finding["detection_method"] == "graph_derivation"


def test_fully_observed_path_records_as_direct_observation():
    entry = _node(NodeKind.PROCESS, "worker")
    a1 = _node(NodeKind.FILE, "scratch")
    path = BlastPath((_edge(entry, a1, EdgeProvenance.DYNAMICALLY_OBSERVED),))
    finding = path_to_finding(path, index=0)
    assert finding["evidence_strength"] == "DIRECT_OBSERVATION"


def test_blocked_path_records_its_block_in_notes():
    entry = _node(NodeKind.PROCESS, "worker")
    meta = _node(NodeKind.API_ENDPOINT, "metadata")
    path = BlastPath((_edge(entry, meta, EdgeProvenance.DYNAMICALLY_BLOCKED),))
    finding = path_to_finding(path, index=0)
    assert "BLOCKED" in (finding["notes"] or "")
    assert finding["status"] == Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE.value
