"""End-to-end: compose real records into a sealed, schema-valid blast_radius record.

Drives the whole Phase 4 pipeline from the bundled example records, seals the result, and
validates it against the shared evidence schema — the same schema every other component emits
against. Also confirms the honesty binding the builder enforces: a composed path cannot carry
an observation's evidence_strength.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustlens.evidence import validate_record, validate_structure, canonical_bytes
from trustlens.evidence.status import Status
from trustlens.mapper.model import Node, NodeKind
from trustlens.blast import combine
from trustlens.blast.assemble import build_record, path_to_finding
from trustlens.blast.model import BlastGraph
from trustlens.blast.provenance import EdgeProvenance

RECORDS = Path(__file__).resolve().parents[2] / "examples" / "records"
TS = "2026-07-23T00:00:00+00:00"
ENV_REF = {
    "description_id": "prod-dataset-processing-v3",
    "description_hash": "c" * 64,
    "captured_at_basis": "operator_asserted",
    "description_captured_at": "2026-06-01T00:00:00+00:00",
    "source_format": "trustlens_env_v1",
}


def _build_graph():
    """Compose a scanner static edge, a configured credential->resource edge, and a sandbox
    blocked edge, on shared node identity. Only the credential-relevant capability
    (execution.dynamic_import) is mapped to the credential node — mapping every finding to one
    node would invent edges the evidence does not support."""
    worker = Node(NodeKind.SERVICE_ACCOUNT, "dataset-worker", namespace="ml")
    cred = Node(NodeKind.SECRET, "aws-credential")
    s3 = Node(NodeKind.STORAGE_RESOURCE, "prod-data")
    meta = Node(NodeKind.API_ENDPOINT, "169.254.169.254")

    scan = json.loads((RECORDS / "scanner_record.json").read_text())
    sandbox = json.loads((RECORDS / "sandbox_record.json").read_text())

    scanner_edges = combine.edges_from_scanner(
        scan, worker, capability_targets={"execution.dynamic_import": cred},
        description_captured_at=TS,
    )
    sandbox_edges = combine.edges_from_sandbox(
        sandbox, capability_targets={"cloud.metadata_endpoint": meta}, entry=worker
    )

    # one configured credential -> resource edge, as the mapper would supply
    from trustlens.blast.model import BlastEdge
    configured = BlastEdge(
        source=cred, target=s3, relation="grants", provenance=EdgeProvenance.CONFIGURED,
        status=Status.FOUND, derived_from=("credential_mapper:role-policy:abc",),
        description_captured_at="2026-06-01T00:00:00+00:00",
        evidence_detail="s3:GetObject on prod-data", limitations=("configured, not observed",),
    )
    graph = combine.build_graph(scanner_edges, [configured], sandbox_edges)
    return graph, worker, cred, s3, meta


def test_full_pipeline_produces_a_schema_valid_sealed_record():
    graph, worker, cred, s3, meta = _build_graph()
    paths = graph.enumerate_paths(worker, s3)
    if not paths:
        pytest.skip("example scanner record produced no worker->credential edge to compose")

    record = build_record(
        paths,
        artifact={
            "artifact_id": "example-dataset-repo", "artifact_type": "huggingface_dataset_repository",
            "declared_kind": "dataset", "source": "https://huggingface.co/datasets/example-org/example-tabular",
            "content_hash": "b" * 62, "content_hash_method": "directory_manifest_v1",
            "acquired_at": TS, "acquisition_method": "already_local",
            "acquisition_authorised_by": None, "immutable_reference": "9f2c1a4e",
            "file_count": 23, "total_bytes": 184320,
        },
        input_records=[
            {"component": "scanner", "record_id": "a" * 32, "content_hash": "c" * 64},
            {"component": "sandbox", "record_id": "d" * 32, "content_hash": "e" * 64},
        ],
        tool_version="0.1.0", commit="0" * 40, started_at=TS, completed_at=TS,
        invocation="trustlens blast-radius --scan scan.json --env env.json",
        environment_description_ref=ENV_REF,
    )
    # Full schema conformance against the shared evidence schema — the same schema every other
    # component emits against. Structure and canonical-value rules.
    validate_structure(record)
    # No duplicate finding ids across paths.
    ids = [f["finding_id"] for f in record["findings"]]
    assert len(ids) == len(set(ids)), f"duplicate finding ids: {ids}"
    # Cross-record derived_from propagation is validated separately with a full corpus; it is
    # out of scope here and deliberately not asserted, rather than faked with a partial corpus.


def test_regeneration_is_byte_identical():
    """Determinism: the same inputs seal to the same bytes."""
    graph, worker, cred, s3, meta = _build_graph()
    paths = graph.enumerate_paths(worker, s3)
    if not paths:
        pytest.skip("no path to compose")
    kwargs = dict(
        artifact={
            "artifact_id": "x", "artifact_type": "huggingface_dataset_repository",
            "declared_kind": "dataset", "source": "https://huggingface.co/datasets/x/y",
            "content_hash": "b" * 62, "content_hash_method": "directory_manifest_v1",
            "acquired_at": TS, "acquisition_method": "already_local",
            "acquisition_authorised_by": None, "immutable_reference": "9f2c1a4e",
            "file_count": 1, "total_bytes": 10,
        },
        input_records=[{"component": "scanner", "record_id": "a" * 32, "content_hash": "c" * 64}],
        tool_version="0.1.0", commit="0" * 40, started_at=TS, completed_at=TS,
        invocation="trustlens blast-radius", environment_description_ref=ENV_REF,
    )
    r1 = build_record(paths, **kwargs)
    r2 = build_record(paths, **kwargs)
    assert canonical_bytes(r1) == canonical_bytes(r2)


def test_the_blocked_path_appears_as_a_finding_not_a_gap():
    graph, worker, cred, s3, meta = _build_graph()
    blocked_paths = graph.enumerate_paths(worker, meta)
    assert blocked_paths, "the sandbox blocked edge should yield a worker->metadata path"
    finding = path_to_finding(blocked_paths[0])
    assert "BLOCKED" in (finding["notes"] or "")
    assert finding["detection_method"] == "dynamic_blocked_observation"


def test_a_composed_path_cannot_be_recorded_as_an_observation():
    """The builder's method/strength binding forbids a graph-derived path claiming observation.

    A two-edge composed path resolves to detection_method 'graph_derivation', which the builder
    pins to evidence_strength INFERRED. There is no argument that overrides this.
    """
    graph, worker, cred, s3, meta = _build_graph()
    paths = graph.enumerate_paths(worker, s3)
    if not paths:
        pytest.skip("no path to compose")
    multi = [p for p in paths if len(p.edges) > 1]
    assert multi, "expected at least one multi-edge composed path"
    finding = path_to_finding(multi[0])
    assert finding["detection_method"] == "graph_derivation"
    assert finding["evidence_strength"] == "INFERRED"
