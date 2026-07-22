"""Controls for the human-readable report.

The report must be a projection of the record, not a second account of it. These tests
read facts back OUT of the rendered text and compare them to the record, so a report that
drifts from the evidence fails rather than merely looking plausible.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from trustlens.scanner.assemble import scan, summarise
from trustlens.scanner.report import discrepancy_level, render

REPOS = Path(__file__).resolve().parents[2] / "examples" / "repos"


@pytest.fixture(scope="module")
def unsafe():
    result = scan(REPOS / "unsafe_dataset_loader")
    return result, render(result.record, summarise(result))


@pytest.fixture(scope="module")
def clean():
    result = scan(REPOS / "clean_tabular")
    return result, render(result.record, summarise(result))


# --------------------------------------------------- the report cannot omit the record

def test_every_found_capability_appears_in_the_report(unsafe):
    result, text = unsafe
    for finding in result.record["findings"]:
        if finding["status"] == "FOUND":
            assert finding["capability"] in text, (
                f"{finding['capability']} was FOUND in the record but is absent from the report"
            )


def test_every_capability_appears_in_the_report_including_clean_ones(clean):
    result, text = clean
    for finding in result.record["findings"]:
        assert finding["capability"] in text, (
            f"{finding['capability']} is in the record but missing from the report; a "
            "capability silently dropped from the report reads as never checked"
        )


def test_every_contradiction_appears_in_the_report(unsafe):
    result, text = unsafe
    assert result.record["contradictions"], "precondition: this fixture must contradict"
    for c in result.record["contradictions"]:
        assert c["contradiction_id"] in text


def test_every_scope_failure_appears_in_the_report():
    result = scan(REPOS / "partial_encoding")
    text = render(result.record, summarise(result))
    assert result.record["scope"]["failed"], "precondition"
    for f in result.record["scope"]["failed"]:
        assert f["path"] in text, f"scope failure {f['path']} is absent from the report"
    assert "FAILED" in text


def test_every_unknown_appears_in_the_report():
    result = scan(REPOS / "clean_imagefolder")
    text = render(result.record, summarise(result))
    for u in result.record["unknowns"]:
        assert u["subject"] in text


def test_record_identity_appears_so_the_report_is_traceable(unsafe):
    result, text = unsafe
    assert result.record["record_id"] in text
    assert result.record["content_hash"] in text
    assert result.record["artifact"]["content_hash"] in text


def test_claims_are_carried_from_the_record_not_restated(unsafe):
    result, text = unsafe
    for line in result.record["claims"]["does_not_establish"]:
        assert line in text, "the report must carry the record's own non-claims verbatim"
    assert result.record["residual_uncertainty"] in text


# ------------------------------------------------ the report cannot invent what is absent

def test_clean_report_does_not_claim_safety(clean):
    _, text = clean
    lowered = text.lower()
    for forbidden in ("is safe", "no risk", "guaranteed", "certified", "verified safe"):
        assert forbidden not in lowered, f"report contains a safety claim: {forbidden!r}"


def test_report_states_that_absent_declarations_are_not_declarations_of_absence():
    result = scan(REPOS / "clean_imagefolder")
    text = render(result.record, summarise(result))
    if not result.record["declared_capabilities"]:
        assert "NOT a declaration of absence" in text


def test_report_never_reports_a_capability_the_record_does_not_contain(clean):
    result, text = clean
    known = {f["capability"] for f in result.record["findings"]}
    # Any capability-shaped token in the report must exist in the record.
    import re

    for token in set(re.findall(r"\b[a-z_]+\.[a-z_]+\b", text)):
        if token.count(".") == 1 and token.split(".")[0] in {
            "execution", "process", "network", "filesystem", "env", "template",
            "package", "cloud", "k8s", "container", "identity", "reachability",
        }:
            assert token in known, f"report mentions {token}, which is not in the record"


# ------------------------------------------------------- the label decomposes

def test_discrepancy_label_is_derived_from_named_identifiers(unsafe):
    result, text = unsafe
    disc = discrepancy_level(result.record)
    assert disc.level == "HIGH"
    assert disc.reasons, "a raised level must name what raised it"
    assert "Derived from:" in text
    for reason in disc.reasons:
        assert reason in text, f"the label cites {reason} but the report does not show it"


def test_label_never_replaces_the_evidence(unsafe):
    _, text = unsafe
    assert "does not replace them" in text


def test_clean_repository_is_low_with_no_reasons(clean):
    result, _ = clean
    disc = discrepancy_level(result.record)
    assert disc.level == "LOW"
    assert disc.reasons == ()


def test_incomplete_analysis_is_undetermined_not_low():
    """A scan that could not complete must not be labelled the same as a clean one."""
    result = scan(REPOS / "partial_encoding")
    disc = discrepancy_level(result.record)
    assert disc.level == "UNDETERMINED", (
        "an incomplete scan with no findings must not share a label with a complete clean scan"
    )
    assert disc.reasons


def test_declared_versus_observed_outranks_a_bare_finding():
    high = discrepancy_level(scan(REPOS / "unsafe_dataset_loader").record)
    assert high.level == "HIGH"
    assert "declares a capability it does not have" in high.basis


# --------------------------------------------------- the report tracks record changes

def test_report_changes_when_the_record_changes(clean):
    """A report written to 'look right' would not move when the evidence moves."""
    result, text = clean
    mutated = copy.deepcopy(result.record)
    target = next(f for f in mutated["findings"] if f["capability"] == "process.shell")
    target["status"] = "FOUND"
    target["evidence"] = [
        {
            "kind": "file_line",
            "path": "planted.py",
            "line": 42,
            "excerpt": "os.system(cmd)",
            "redacted": False,
        }
    ]
    new_text = render(mutated, None)
    assert new_text != text
    assert "planted.py:42" in new_text
    assert "[FOUND] process.shell" in new_text
    assert discrepancy_level(mutated).level == "MEDIUM"


def test_removing_a_finding_removes_it_from_the_report(unsafe):
    result, text = unsafe
    mutated = copy.deepcopy(result.record)
    removed = next(f for f in mutated["findings"] if f["capability"] == "network.outbound")
    mutated["findings"] = [f for f in mutated["findings"] if f is not removed]
    new_text = render(mutated, None)
    assert new_text.count("network.outbound") < text.count("network.outbound")


def test_report_is_deterministic(clean):
    result, text = clean
    assert render(result.record, summarise(result)) == text
