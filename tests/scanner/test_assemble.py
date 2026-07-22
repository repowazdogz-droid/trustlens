"""Controls for the top-level assembler.

Aggregation is the next place the false-success pattern could recur: a family detects
something correctly, and the combined record reports clean anyway. That failure happened
twice this session at the individual-rule level, so these tests attack it directly at the
aggregation level by injecting families that drop findings, corrupt findings, and crash.

The property under test is one sentence: **the overall verdict cannot be clean unless every
declared capability was actually reported on.**
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path

import pytest

from trustlens.evidence import Status, make_finding, make_scope, parse as parse_status
from trustlens.evidence.schema import validate_record
from trustlens.scanner import assemble
from trustlens.scanner.assemble import CheckSpec, ScanResult, scan, summarise

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "python_surface"
CLEAN_REPO = FIXTURES / "clean_python"
UNSAFE_REPO = FIXTURES / "unsafe_deser"


@dataclass
class _Result:
    findings: list
    scope: dict


def _ok_finding(capability: str, status: str = "NOT_FOUND_WITHIN_ANALYSED_SCOPE") -> dict:
    return make_finding(
        capability=capability,
        status=status,
        detection_method="static_ast",
        rule_id="fake-family",
        rule_version="1.0.0",
        source_component="scanner",
        scope=make_scope(analysed=["a.py"], languages=["python"]),
        evidence=[
            {"kind": "file_line", "path": "a.py", "line": 1, "excerpt": "x", "redacted": False}
        ]
        if status == "FOUND"
        else [],
        confidence_basis="fixture",
        limitations=["fixture"],
    )


def _spec(name: str, capabilities: set[str], runner) -> CheckSpec:
    return CheckSpec(name=name, runner=runner, capabilities=frozenset(capabilities))


# --------------------------------------------------------------------- the happy path

def test_normal_scan_produces_a_valid_record():
    result = scan(CLEAN_REPO)
    validate_record(result.record)
    assert result.complete is True
    assert result.coverage_gaps == []


def test_normal_scan_detects_the_unsafe_repository():
    result = scan(UNSAFE_REPO)
    validate_record(result.record)
    statuses = {f["capability"]: f["status"] for f in result.record["findings"]}
    assert statuses["execution.deserialization"] == "FOUND"


def test_every_declared_capability_receives_an_explicit_status():
    """A clean repository must still make a statement about every capability."""
    result = scan(CLEAN_REPO)
    reported = {f["capability"] for f in result.record["findings"]}
    promised = set().union(*(s.capabilities for s in assemble.CHECKS))
    assert promised <= reported, f"never reported on: {sorted(promised - reported)}"


# ------------------------------------------------- a family that DROPS a finding

def test_dropped_finding_becomes_a_coverage_gap_not_silence():
    """The exact failure seen twice this session, now at the aggregation level."""

    def drops_one(root, **kwargs):
        # Promises two capabilities, delivers one.
        return _Result(
            findings=[_ok_finding("process.shell")],
            scope=make_scope(analysed=["a.py"], languages=["python"]),
        )

    checks = (_spec("dropper", {"process.shell", "execution.dynamic_eval"}, drops_one),)
    result = scan(CLEAN_REPO, checks=checks)

    assert result.complete is False
    assert result.coverage_gaps == ["dropper:execution.dynamic_eval"]

    dropped = next(
        f for f in result.record["findings"] if f["capability"] == "execution.dynamic_eval"
    )
    assert parse_status(dropped["status"]) is Status.UNKNOWN, (
        "a dropped capability must be UNKNOWN, never absent and never clean"
    )
    assert "did not report" in dropped["unknown_reason"]
    validate_record(result.record)


def test_dropped_finding_is_visible_in_the_summary():
    def drops_one(root, **kwargs):
        return _Result(findings=[], scope=make_scope(analysed=[], languages=[]))

    checks = (_spec("dropper", {"process.shell"}, drops_one),)
    summary = summarise(scan(CLEAN_REPO, checks=checks))
    assert summary["analysis_complete"] is False
    assert summary["coverage_gaps"] == ["dropper:process.shell"]
    assert "process.shell" in summary["incomplete"]
    assert "process.shell" not in summary["clean_within_scope"], (
        "an undelivered capability must never appear as clean"
    )


# ------------------------------------------------- a family that RAISES

def test_crashing_family_cannot_produce_a_clean_verdict():
    def explodes(root, **kwargs):
        raise RuntimeError("planted failure inside a check family")

    checks = (_spec("bomb", {"process.shell", "network.outbound"}, explodes),)
    result = scan(CLEAN_REPO, checks=checks)

    assert result.complete is False
    assert len(result.coverage_gaps) == 2
    assert any(o.error and "planted failure" in o.error for o in result.outcomes)

    reasons = [f["reason"] for f in result.record["scope"]["failed"]]
    assert any("check family raised RuntimeError" in r for r in reasons)

    for capability in ("process.shell", "network.outbound"):
        finding = next(
            f for f in result.record["findings"] if f["capability"] == capability
        )
        assert parse_status(finding["status"]) is Status.UNKNOWN
        assert "failed" in finding["unknown_reason"]
    validate_record(result.record)


def test_crashing_family_does_not_abort_the_other_families():
    """One broken family must not silence the ones that worked."""

    def explodes(root, **kwargs):
        raise ValueError("boom")

    checks = (
        _spec("bomb", {"process.shell"}, explodes),
        assemble.CHECKS[0],  # the real template-injection family
    )
    result = scan(UNSAFE_REPO, checks=checks)
    reported = {f["capability"] for f in result.record["findings"]}
    assert "template.injection_surface" in reported, "a working family was lost"
    assert result.complete is False


# ------------------------------------------------- a family that CORRUPTS a finding

def test_corrupted_finding_is_recorded_as_a_failure_not_accepted():
    """A finding that fails schema validation must not enter the record."""

    def corrupts(root, **kwargs):
        bad = _ok_finding("process.shell")
        del bad["limitations"]  # required by the schema
        return _Result(
            findings=[bad], scope=make_scope(analysed=["a.py"], languages=["python"])
        )

    checks = (_spec("corrupter", {"process.shell"}, corrupts),)
    result = scan(CLEAN_REPO, checks=checks)

    assert result.complete is False
    assert result.coverage_gaps == ["corrupter:process.shell"]
    reasons = " ".join(f["reason"] for f in result.record["scope"]["failed"])
    assert "failed schema validation" in reasons
    validate_record(result.record)


def test_finding_claiming_clean_over_a_failed_scope_is_rejected():
    """The Phase 0 invariant must hold through the assembler, not only at the check."""

    def liar(root, **kwargs):
        bad = _ok_finding("process.shell")
        # Hand-assemble the pairing the builder refuses to construct.
        bad["scope"]["failed"] = [
            {"path": "x.py", "reason": "SyntaxError: planted", "kind": "parse_error"}
        ]
        bad["status"] = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"
        return _Result(findings=[bad], scope=make_scope(analysed=["a.py"], languages=["python"]))

    checks = (_spec("liar", {"process.shell"}, liar),)
    result = scan(CLEAN_REPO, checks=checks)

    assert result.coverage_gaps == ["liar:process.shell"], (
        "a clean status over a failed scope must be rejected, leaving a coverage gap"
    )
    finding = next(
        f for f in result.record["findings"] if f["capability"] == "process.shell"
    )
    assert parse_status(finding["status"]) is Status.UNKNOWN


# ------------------------------------------------- record-level integrity

def test_assembled_record_never_claims_clean_over_a_failed_scope():
    """Scan a repo with an unparseable file; no finding may read clean."""
    result = scan(FIXTURES / "partial_python")
    assert result.record["scope"]["failed"], "the unparseable file must be recorded"
    for finding in result.record["findings"]:
        if finding["scope"]["failed"]:
            assert parse_status(finding["status"]) is not Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
    validate_record(result.record)


def test_record_content_hash_reproduces():
    result = scan(CLEAN_REPO, started_at="2026-07-22T00:00:00+00:00",
                  completed_at="2026-07-22T00:00:01+00:00")
    validate_record(result.record)


def test_two_scans_of_identical_input_agree_on_content_hash():
    a = scan(CLEAN_REPO, started_at="2026-07-22T00:00:00+00:00",
             completed_at="2026-07-22T00:00:01+00:00")
    b = scan(CLEAN_REPO, started_at="2026-07-22T00:00:00+00:00",
             completed_at="2026-07-22T00:00:09+00:00")
    assert a.record["content_hash"] == b.record["content_hash"], (
        "identical evidence must hash identically regardless of run duration"
    )


def test_artifact_hash_changes_when_a_file_changes(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("X = 1\n", encoding="utf-8")
    first = scan(repo).record["artifact"]["content_hash"]
    (repo / "a.py").write_text("X = 2\n", encoding="utf-8")
    assert scan(repo).record["artifact"]["content_hash"] != first


def test_summary_label_decomposes_into_findings():
    """The label must never replace the evidence it came from."""
    result = scan(UNSAFE_REPO)
    summary = summarise(result)
    ids = {f["finding_id"] for f in result.record["findings"]}
    for capability, contributing in summary["contributing_findings"].items():
        assert contributing, f"{capability} has no contributing finding ids"
        assert set(contributing) <= ids
