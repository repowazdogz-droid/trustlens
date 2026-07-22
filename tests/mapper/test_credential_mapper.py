"""Controls for the credential reachability mapper.

The seven inherited invariants each have a test here. None was relaxed to make Phase 2
ship; where the design pressured one, the design changed.

The Terraform fixture is a **real generated plan**, not hand-written — see
`tests/fixtures/mapper/real_terraform/PROVENANCE.md`. That choice caught two format facts
immediately (`format_version` is 1.2, and `policy` is a JSON string) that a hand-written
fixture would have encoded wrong, which is exactly how four bugs got past the
declared-surface parser earlier in this build.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from trustlens.evidence import Status, parse as parse_status
from trustlens.evidence.schema import validate_record
from trustlens.mapper import rbac as rbac_mod
from trustlens.mapper import terraform as tf_mod
from trustlens.mapper.assemble import (
    DECLARED_CAPABILITIES,
    DescriptionError,
    UNPRODUCIBLE_CAPABILITIES,
    _RULE_IDS,
    load_description,
    map_credentials,
)
from trustlens.mapper.model import Edge, EdgeKind, Node, NodeKind, Reachability

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mapper"
TS = {"started_at": "2026-07-22T00:00:00+00:00", "completed_at": "2026-07-22T00:00:01+00:00"}


def _run(name: str):
    return map_credentials(FIX / name / "env.yaml", **TS)


# ---------------------------------------------- invariant 2: captured_at is mandatory

def test_missing_captured_at_is_refused_outright():
    """Defaulting it would make a stale model indistinguishable from a current one."""
    with pytest.raises(DescriptionError, match="description_captured_at is REQUIRED"):
        load_description(FIX / "no_captured_at" / "env.yaml")


def test_non_iso_captured_at_is_refused(tmp_path):
    p = tmp_path / "env.yaml"
    p.write_text("description_id: x\ndescription_captured_at: 'last tuesday'\n", encoding="utf-8")
    with pytest.raises(DescriptionError, match="not an ISO 8601"):
        load_description(p)


def test_captured_at_reaches_every_edge():
    result = _run("complete_env")
    assert result.graph.edges
    assert result.graph.capture_times() == ["2026-07-20T09:00:00+00:00"]


def test_an_edge_cannot_be_built_without_a_capture_time():
    with pytest.raises(ValueError, match="no .*description_captured_at"):
        Edge(
            source=Node(NodeKind.SERVICE_ACCOUNT, "a"),
            target=Node(NodeKind.IAM_ROLE, "b"),
            kind=EdgeKind.CAN_ASSUME,
            reachability=Reachability.CONFIGURED,
            evidence_path="x", evidence_pointer=None, evidence_excerpt=None,
            description_captured_at="", captured_at_basis="operator_asserted",
            rule_id="r", limitations=("l",),
        )


def test_an_edge_cannot_be_built_without_a_limitation():
    with pytest.raises(ValueError, match="states no limitation"):
        Edge(
            source=Node(NodeKind.SERVICE_ACCOUNT, "a"),
            target=Node(NodeKind.IAM_ROLE, "b"),
            kind=EdgeKind.CAN_ASSUME,
            reachability=Reachability.CONFIGURED,
            evidence_path="x", evidence_pointer=None, evidence_excerpt=None,
            description_captured_at="2026-01-01T00:00:00+00:00",
            captured_at_basis="operator_asserted", rule_id="r",
        )


def test_capture_time_is_surfaced_in_the_report_not_buried():
    from trustlens.cli import main

    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["map-credentials", str(FIX / "complete_env" / "env.yaml")])
    text = buf.getvalue()
    assert "Description captured : 2026-07-20T09:00:00+00:00" in text
    assert text.index("Description captured") < text.index("[FOUND]"), (
        "the capture time must appear above the findings, not after them"
    )


# --------------------------------------------------- invariant 1: PARTIAL propagation

def test_malformed_inputs_never_produce_a_clean_result():
    result = _run("malformed")
    validate_record(result.record)
    assert result.record["scope"]["failed"], "the broken inputs must be recorded"
    assert not any(
        parse_status(f["status"]) is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
        for f in result.record["findings"]
    )


def test_a_missing_referenced_input_is_a_recorded_failure(tmp_path):
    p = tmp_path / "env.yaml"
    p.write_text(
        "description_id: x\ndescription_captured_at: '2026-01-01T00:00:00+00:00'\n"
        "terraform_plan: nope.json\n",
        encoding="utf-8",
    )
    result = map_credentials(p, **TS)
    assert [f["path"] for f in result.record["scope"]["failed"]] == ["nope.json"]


# --------------------------------- invariant 3: CONFIG_DERIVED strength binding

def test_every_finding_is_config_derived_never_observed():
    result = _run("complete_env")
    for finding in result.record["findings"]:
        assert finding["detection_method"] in ("config_derivation", "policy_evaluation")
        assert finding["evidence_strength"] == "CONFIG_DERIVED", (
            "a configured path must never carry an observation's weight"
        )
        assert finding["environment_description_ref"] is not None


# ------------------------------------- invariant 4: contradictions unreconciled

def test_operator_assertion_contradicted_by_configuration():
    result = _run("contradictory_env")
    validate_record(result.record)
    ids = {c["contradiction_id"] for c in result.record["contradictions"]}
    assert "ENV-no_cloud_role_assumption" in ids
    assert "ENV-no_secret_access" in ids
    for c in result.record["contradictions"]:
        assert c["reconciled"] is False
        assert {s["evidence_kind"] for s in c["between"]} == {"declared", "configured"}


def test_an_honest_description_produces_no_contradiction():
    assert _run("complete_env").record["contradictions"] == []


# ------------------------------------------ invariant 5: coverage reconciliation

def test_every_declared_capability_is_reported_on():
    result = _run("complete_env")
    reported = {f["capability"] for f in result.record["findings"]}
    assert set(DECLARED_CAPABILITIES) <= reported
    assert result.coverage_gaps == []


def test_capabilities_no_rule_can_produce_are_unsupported_not_clean():
    """The env.credential_pattern_read class of bug, checked in a new component.

    A capability that no rule can ever emit must not report clean; that is
    indistinguishable from one that ran and matched nothing.
    """
    result = _run("complete_env")
    for capability, reason in UNPRODUCIBLE_CAPABILITIES.items():
        finding = next(f for f in result.record["findings"] if f["capability"] == capability)
        assert parse_status(finding["status"]) is Status.UNSUPPORTED
        assert finding["unsupported_construct"]
        assert "absence of analysis" in " ".join(finding["limitations"])


def test_clean_findings_state_how_many_rules_ran(tmp_path):
    p = tmp_path / "env.yaml"
    p.write_text(
        "description_id: empty\ndescription_captured_at: '2026-01-01T00:00:00+00:00'\n",
        encoding="utf-8",
    )
    result = map_credentials(p, **TS)
    for finding in result.record["findings"]:
        if finding["status"] != "NOT_FOUND_WITHIN_ANALYSED_SCOPE":
            continue
        assert "edge rule(s)" in finding["confidence_basis"], (
            f"{finding['capability']} reports clean without stating how many rules ran"
        )


# ------------------------------------------------------- invariant 6: inertness

def test_mapping_spawns_nothing_and_contacts_nothing(monkeypatch):
    attempted: list[str] = []

    def _boom(name):
        def _f(*a, **k):
            attempted.append(name)
            raise AssertionError(f"mapper called {name} — it must be inert")
        return _f

    monkeypatch.setattr(subprocess, "run", _boom("subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", _boom("subprocess.Popen"))
    monkeypatch.setattr(os, "system", _boom("os.system"))
    monkeypatch.setattr(socket, "socket", _boom("socket.socket"))
    monkeypatch.setattr(socket, "create_connection", _boom("socket.create_connection"))

    result = _run("complete_env")
    assert attempted == []
    assert result.graph.edges


def test_unsafe_yaml_tag_in_a_manifest_is_not_constructed(tmp_path):
    """Manifest loading uses safe_load_all; a python tag is a failure, not an object."""
    canary = tmp_path / "CANARY"
    d = tmp_path / "k8s"
    d.mkdir()
    (d / "evil.yaml").write_text(
        f"kind: Role\nboom: !!python/object/apply:os.system ['touch {canary}']\n",
        encoding="utf-8",
    )
    result = rbac_mod.ingest(d, captured_at="2026-01-01T00:00:00+00:00",
                             captured_at_basis="operator_asserted")
    assert not canary.exists(), "the mapper constructed an untrusted YAML tag"
    assert result.failed, "the unsafe tag must be recorded as a parse failure"


# --------------------------------------------------- invariant 7: rule liveness

def test_every_rule_id_can_actually_fire():
    """No dead rules, the same standing check applied in Phase 1."""
    fired = set()
    for name in ("complete_env", "contradictory_env"):
        fired |= {e.rule_id for e in _run(name).graph.edges}
    missing = set(_RULE_IDS) - fired
    assert not missing, f"rules that never fired on any fixture: {sorted(missing)}"


def test_no_orphan_rule_ids():
    fired = {e.rule_id for e in _run("complete_env").graph.edges}
    assert fired <= set(_RULE_IDS), f"edges emitted with unregistered rule ids: {fired - set(_RULE_IDS)}"


# ------------------------------------------------- the real-plan format findings

def test_policy_is_a_json_string_in_a_real_plan():
    """Regression guard for the double-decode a hand-written fixture would have missed."""
    plan = json.loads((FIX / "real_terraform" / "plan.json").read_text())
    policy_change = next(
        c for c in plan["resource_changes"] if c["type"] == "aws_iam_policy"
    )
    assert isinstance(policy_change["change"]["after"]["policy"], str)


def test_real_plan_format_version_is_recognised():
    plan = json.loads((FIX / "real_terraform" / "plan.json").read_text())
    assert plan["format_version"] == "1.2"
    assert plan["format_version"] in tf_mod.KNOWN_FORMAT_VERSIONS


def test_unknown_plan_format_is_recorded_not_silently_parsed(tmp_path):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps({"format_version": "99.0", "resource_changes": []}), encoding="utf-8")
    result = tf_mod.ingest_plan(p, "plan.json", captured_at="2026-01-01T00:00:00+00:00",
                                captured_at_basis="operator_asserted")
    assert any("format version" in u["subject"] for u in result.unknowns)


# --------------------------------------------- cross-domain edge, the differentiator

def test_kubernetes_service_account_joins_to_the_iam_role():
    """The IRSA `:sub` condition is the K8s -> IAM link and must not be dropped."""
    result = _run("complete_env")
    sa = Node(NodeKind.SERVICE_ACCOUNT, "dataset-worker", namespace="ml")
    kinds = {(e.kind, e.target.kind) for e in result.graph.outgoing(sa)}
    assert (EdgeKind.CAN_ASSUME, NodeKind.IAM_ROLE) in kinds, "cross-domain edge missing"
    assert (EdgeKind.BOUND_TO, NodeKind.K8S_ROLE) in kinds, "in-cluster edge missing"


def test_graph_output_is_deterministic():
    """The rejected tools were non-deterministic; TrustLens sorts at every emit point."""
    a = _run("complete_env")
    b = _run("complete_env")
    assert [e.sort_key for e in a.graph.sorted_edges()] == [
        e.sort_key for e in b.graph.sorted_edges()
    ]
    assert a.record["content_hash"] == b.record["content_hash"]


def test_record_validates_for_every_fixture():
    for name in ("complete_env", "contradictory_env", "malformed"):
        validate_record(_run(name).record)
