"""The load-bearing test file: PARTIAL must never become NOT_FOUND_WITHIN_ANALYSED_SCOPE.

A check that did not finish and a check that finished and saw nothing are different
claims. The first bounds nothing. Collapsing them is the single most consequential thing
this evidence model can get wrong, because the collapsed result is indistinguishable from
a real clean scan at the point where someone decides an artifact is fine.

Four independent barriers are tested here, because one barrier is one bug away from being
absent:

  1. Construction  — `make_finding` refuses to build the invalid combination.
  2. Structure     — the JSON Schema rejects a hand-assembled record carrying it.
  3. Aggregation   — `combine` cannot produce a clean result from a PARTIAL input.
  4. Consumption   — `FindingIndex` / `CapabilityView` refuse to hand a downstream
                     component an absence it has not earned.
"""

from __future__ import annotations

import copy

import pytest

from trustlens.evidence import (
    FindingIndex,
    IncompleteAnalysisError,
    Status,
    StatusComparisonError,
    absence_within_scope,
    combine,
    is_complete,
    make_finding,
    make_scope,
    require_complete_scope,
)
from trustlens.evidence.schema import (
    SchemaValidationError,
    validate_record,
    validate_semantics,
    validate_structure,
)

FAILED_ITEM = {
    "path": "config/legacy.yaml",
    "reason": "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0",
    "kind": "decode_error",
}


def _scope(*, with_failure: bool):
    return make_scope(
        analysed=["config/a.yaml", "config/b.yaml"],
        languages=["yaml"],
        failed=[FAILED_ITEM] if with_failure else [],
    )


# ---------------------------------------------------------------- barrier 1: construction

def test_builder_refuses_clean_status_over_incomplete_scope():
    with pytest.raises(ValueError) as exc:
        make_finding(
            capability="template.injection_surface",
            status="NOT_FOUND_WITHIN_ANALYSED_SCOPE",
            detection_method="static_ast",
            rule_id="template-jinja-config",
            rule_version="0.9.0",
            source_component="scanner",
            scope=_scope(with_failure=True),
            confidence_basis="two of three files parsed",
            limitations=["illustrative"],
        )
    assert "PARTIAL" in str(exc.value)
    assert "config/legacy.yaml" in str(exc.value)


def test_builder_refuses_partial_without_a_named_failure():
    """PARTIAL without a named failure is an unfalsifiable hedge, not a status."""
    with pytest.raises(ValueError, match="non-empty scope.failed"):
        make_finding(
            capability="template.injection_surface",
            status="PARTIAL",
            detection_method="static_ast",
            rule_id="template-jinja-config",
            rule_version="0.9.0",
            source_component="scanner",
            scope=_scope(with_failure=False),
            confidence_basis="something went wrong",
            limitations=["illustrative"],
        )


def test_builder_accepts_the_honest_pairing():
    finding = make_finding(
        capability="template.injection_surface",
        status="PARTIAL",
        detection_method="static_ast",
        rule_id="template-jinja-config",
        rule_version="0.9.0",
        source_component="scanner",
        scope=_scope(with_failure=True),
        confidence_basis="two of three config files parsed; the third could not be decoded",
        limitations=["config/legacy.yaml was not analysed at all"],
    )
    assert finding["status"] == Status.PARTIAL.value
    assert finding["scope"]["failed"] == [FAILED_ITEM]


# ------------------------------------------------------------------- barrier 2: structure

def test_schema_rejects_hand_assembled_clean_status_over_failed_scope(example_records):
    """Bypassing the builder must not bypass the invariant."""
    record = copy.deepcopy(example_records["scanner_record"])
    partial = next(f for f in record["findings"] if f["status"] == "PARTIAL")

    # The exact edit a well-meaning developer makes when a PARTIAL is inconvenient.
    partial["status"] = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

    problems = validate_structure(record)
    assert any("failed" in p for p in problems), (
        "the JSON Schema must reject a completed-clean status over a scope containing "
        f"failures; problems were: {problems}"
    )


def test_schema_rejects_partial_with_no_failures(example_records):
    record = copy.deepcopy(example_records["scanner_record"])
    clean = next(
        f for f in record["findings"] if f["status"] == "NOT_FOUND_WITHIN_ANALYSED_SCOPE"
    )
    clean["status"] = "PARTIAL"
    problems = validate_structure(record)
    assert problems, "PARTIAL with an empty scope.failed must not validate"


def test_semantic_validator_also_catches_it_independently(example_records):
    """Belt and braces: the semantic layer catches it even if the schema layer changed."""
    record = copy.deepcopy(example_records["scanner_record"])
    partial = next(f for f in record["findings"] if f["status"] == "PARTIAL")
    partial["status"] = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"
    with pytest.raises(SchemaValidationError) as exc:
        validate_record(record, check_ids=False)
    assert any("failed item" in p for p in exc.value.problems)


# ----------------------------------------------------------------- barrier 3: aggregation

def test_combine_never_launders_partial_into_clean():
    assert combine([Status.PARTIAL, Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE]) is Status.PARTIAL
    assert combine([Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE, Status.PARTIAL]) is Status.PARTIAL


def test_combine_is_clean_only_when_every_input_is_clean():
    clean = Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
    assert combine([clean, clean, clean]) is clean
    for contaminant in (Status.PARTIAL, Status.UNKNOWN, Status.UNSUPPORTED, Status.FOUND):
        assert combine([clean, clean, contaminant]) is not clean


def test_combine_of_nothing_is_unknown_not_clean():
    """An empty aggregate must not be a clean one; nobody looked."""
    assert combine([]) is Status.UNKNOWN


def test_combine_is_order_independent():
    import itertools

    for combo in itertools.permutations(
        [Status.PARTIAL, Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE, Status.UNSUPPORTED]
    ):
        assert combine(combo) is Status.PARTIAL


# ----------------------------------------------------------------- barrier 4: consumption

def _index_with(statuses):
    findings = []
    for i, status in enumerate(statuses):
        findings.append(
            make_finding(
                capability="process.shell",
                status=status,
                detection_method="static_ast",
                rule_id=f"process-shell-{i}",
                rule_version="1.2.0",
                source_component="scanner",
                scope=_scope(with_failure=status is Status.PARTIAL),
                evidence=(
                    [{"kind": "file_line", "path": "a.py", "line": 1, "excerpt": "x", "redacted": False}]
                    if status is Status.FOUND
                    else []
                ),
                confidence_basis="fixture",
                limitations=["fixture"],
                unknown_reason="fixture" if status is Status.UNKNOWN else None,
                unsupported_construct="fixture" if status is Status.UNSUPPORTED else None,
            )
        )
    return FindingIndex([{"findings": findings}])


def test_capability_view_refuses_absence_when_any_contributor_is_partial():
    index = _index_with([Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE, Status.PARTIAL])
    view = index.view("process.shell")
    assert view.status is Status.PARTIAL
    assert view.may_assume_absent is False
    with pytest.raises(IncompleteAnalysisError) as exc:
        view.require_absent(context="blast-radius path closure")
    assert "did not complete" in str(exc.value)


def test_capability_view_allows_absence_only_when_fully_clean():
    index = _index_with(
        [Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE, Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE]
    )
    view = index.view("process.shell")
    assert view.may_assume_absent is True
    view.require_absent(context="blast-radius path closure")  # must not raise


def test_unchecked_capability_is_unknown_not_absent():
    """The most dangerous default: a capability nobody looked for reading as clean."""
    index = _index_with([Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE])
    view = index.view("cloud.metadata_endpoint")
    assert view.status is Status.UNKNOWN
    assert view.may_assume_absent is False


def test_incomplete_capabilities_are_enumerable_for_reporting():
    index = _index_with([Status.PARTIAL])
    incomplete = index.incomplete()
    assert [v.capability for v in incomplete] == ["process.shell"]


# ------------------------------------------------------- the naive-consumer trap, directly

def test_string_comparison_against_status_raises_rather_than_silently_failing():
    """`status == "NOT_FOUND..."` is the bug. It must be loud, not False.

    A silent False here sends control into the else-branch, which in almost every
    downstream shape is the treat-as-absent branch.
    """
    with pytest.raises(StatusComparisonError):
        _ = Status.PARTIAL == "PARTIAL"
    with pytest.raises(StatusComparisonError):
        _ = Status.PARTIAL != "NOT_FOUND_WITHIN_ANALYSED_SCOPE"


def test_absence_predicate_is_true_for_exactly_one_status():
    truthy = [s for s in Status if absence_within_scope(s)]
    assert truthy == [Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE]


def test_require_complete_scope_rejects_the_three_incomplete_states():
    for status in (Status.PARTIAL, Status.UNKNOWN, Status.UNSUPPORTED):
        assert is_complete(status) is False
        with pytest.raises(IncompleteAnalysisError):
            require_complete_scope(status, context="downstream consumption")
    for status in (Status.FOUND, Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE):
        assert is_complete(status) is True
        require_complete_scope(status, context="downstream consumption")


def test_incompleteness_propagates_across_records(example_records, corpus):
    """A downstream record may not discharge an upstream PARTIAL by restating it.

    The parent finding lives in the scanner record, not in the blast-radius record, so
    this is specifically the cross-record case — the one where the code that knew the
    parse failed is furthest away from the code drawing the conclusion.
    """
    record = copy.deepcopy(example_records["blast_radius_record"])
    partial_path = next(f for f in record["findings"] if f["status"] == "PARTIAL")
    partial_path["status"] = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"
    partial_path["scope"]["failed"] = []

    problems = validate_semantics(record, check_ids=False, corpus=corpus)
    assert any(
        "PARTIAL parent" in p for p in problems
    ), f"cross-record propagation must be caught; problems were: {problems}"


def test_composing_record_without_corpus_reports_propagation_as_unverified(example_records):
    """Silence is not a pass.

    Validating a composing record with no corpus cannot check propagation, so it says
    so rather than returning clean. This keeps the limitation visible at the call site
    instead of only in a document.
    """
    record = copy.deepcopy(example_records["blast_radius_record"])
    problems = validate_semantics(record, check_ids=False, corpus=None)
    assert any("NOT verified" in p for p in problems), problems

    # With the corpus supplied, the same untouched record validates cleanly.
    assert validate_semantics(record, check_ids=False, corpus=_corpus_of(example_records)) == []


def _corpus_of(example_records):
    return {r["record_id"]: r for r in example_records.values()}
