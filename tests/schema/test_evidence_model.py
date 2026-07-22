"""Schema loading, example conformance, determinism, and the remaining enforced invariants."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from trustlens.evidence import (
    NonCanonicalValueError,
    SCHEMA_VERSION,
    Status,
    canonical_bytes,
    compute_content_hash,
    compute_finding_id,
    load_schemas,
    make_finding,
    make_record,
    make_scope,
    schema_set,
    seal,
)
from trustlens.evidence.schema import (
    SchemaValidationError,
    validate_record,
    validate_semantics,
    validate_structure,
)

EXPECTED_SCHEMA_IDS = {
    "urn:trustlens:1.0.0:common",
    "urn:trustlens:1.0.0:finding",
    "urn:trustlens:1.0.0:evidence_record",
    "urn:trustlens:1.0.0:enums:status",
    "urn:trustlens:1.0.0:enums:capability",
    "urn:trustlens:1.0.0:enums:detection_method",
    "urn:trustlens:1.0.0:enums:evidence_strength",
}


# --------------------------------------------------------------------------- schema loading

def test_every_schema_loads_and_is_addressable():
    loaded = schema_set()
    assert EXPECTED_SCHEMA_IDS <= set(loaded.schemas), (
        f"missing: {EXPECTED_SCHEMA_IDS - set(loaded.schemas)}"
    )


def test_schema_version_matches_schema_ids():
    """The version in records and the version in schema $ids must not drift apart."""
    version = SCHEMA_VERSION.split("/", 1)[1]
    for schema_id in EXPECTED_SCHEMA_IDS:
        assert f":{version}:" in schema_id, f"{schema_id} does not carry version {version}"


def test_status_enum_has_exactly_five_states():
    """Five states, not four. The taxonomy's whole point is the fifth one."""
    doc = schema_set().schemas["urn:trustlens:1.0.0:enums:status"]
    assert len(doc["enum"]) == 5
    assert set(doc["enum"]) == {s.value for s in Status}
    # Every state must carry its semantics, including what it does NOT mean.
    for state in doc["enum"]:
        semantics = doc["x-trustlens-semantics"][state]
        assert semantics["means"] and semantics["does_not_mean"]


def test_enums_contain_no_duplicate_values():
    for name in ("capability", "detection_method", "evidence_strength", "status"):
        values = schema_set().schemas[f"urn:trustlens:1.0.0:enums:{name}"]["enum"]
        assert len(values) == len(set(values)), f"duplicate values in {name}"


def test_builder_strength_map_covers_exactly_the_detection_method_enum():
    """The builder duplicates the method->strength rule; a drift would silently disagree."""
    from trustlens.evidence.builder import _DEFAULT_STRENGTH

    schema_methods = set(
        schema_set().schemas["urn:trustlens:1.0.0:enums:detection_method"]["enum"]
    )
    assert set(_DEFAULT_STRENGTH) == schema_methods, (
        "builder and schema disagree about the set of detection methods: "
        f"builder-only={set(_DEFAULT_STRENGTH) - schema_methods}, "
        f"schema-only={schema_methods - set(_DEFAULT_STRENGTH)}"
    )


def test_builder_strength_map_agrees_with_the_schema_conditionals():
    """Each method->strength pairing the builder applies must also validate structurally."""
    from trustlens.evidence.builder import _DEFAULT_STRENGTH

    for method, strength in _DEFAULT_STRENGTH.items():
        needs_env = method in ("config_derivation", "policy_evaluation")
        finding = make_finding(
            capability="process.shell",
            status="UNKNOWN",
            detection_method=method,
            rule_id="r",
            rule_version="1",
            source_component="scanner",
            scope=make_scope(analysed=["a.py"], languages=["python"]),
            confidence_basis="c",
            limitations=["l"],
            unknown_reason="drift check",
            derived_from=["scanner:process.shell:" + "0" * 16]
            if method == "graph_derivation"
            else None,
            environment_description_ref={
                "description_id": "d",
                "description_captured_at": "2026-06-01T00:00:00+00:00",
                "captured_at_basis": "operator_asserted",
                "description_hash": "c" * 64,
                "source_format": "trustlens_env_v1",
            }
            if needs_env
            else None,
        )
        assert finding["evidence_strength"] == strength
        record = _minimal_record(findings=[finding])
        problems = validate_structure(record)
        assert not problems, f"method {method} with strength {strength}: {problems}"


# ------------------------------------------------------------------- examples and coverage

def test_every_example_record_validates(example_records, corpus):
    for name, record in example_records.items():
        try:
            validate_record(record, corpus=corpus)
        except SchemaValidationError as exc:
            pytest.fail(f"{name} does not validate:\n{exc}")


def test_examples_cover_every_component(example_records):
    components = {r["tool"]["component"] for r in example_records.values()}
    assert components == {"scanner", "credential_mapper", "sandbox", "blast_radius"}, (
        "the schema must ship an example record from every component that will emit one"
    )


def test_at_least_one_example_carries_a_partial_result(example_records):
    partials = [
        (name, f["finding_id"])
        for name, record in example_records.items()
        for f in record["findings"]
        if f["status"] == "PARTIAL"
    ]
    assert partials, "at least one example must demonstrate a PARTIAL result"
    for name, _ in partials:
        record = example_records[name]
        finding = next(f for f in record["findings"] if f["status"] == "PARTIAL")
        assert finding["scope"]["failed"], "a PARTIAL example must name what failed"
        assert finding["scope"]["failed"][0]["reason"]


def test_examples_cover_every_status(example_records):
    """All five states must appear in the shipped examples, or the taxonomy is untested."""
    seen = {f["status"] for r in example_records.values() for f in r["findings"]}
    assert seen == {s.value for s in Status}, f"missing: {{s.value for s in Status}} - {seen}"


def test_regeneration_is_byte_identical(repo_root, tmp_path):
    """Reproducibility: the same inputs must yield the same bytes, or hashes prove nothing."""
    before = {
        p.name: p.read_bytes() for p in sorted((repo_root / "examples" / "records").glob("*.json"))
    }
    subprocess.run(
        [sys.executable, "examples/generate_examples.py"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        env={"PYTHONPATH": str(repo_root), "PATH": "/usr/bin:/bin"},
    )
    after = {
        p.name: p.read_bytes() for p in sorted((repo_root / "examples" / "records").glob("*.json"))
    }
    assert before == after, "regenerating the examples changed their bytes"


# ------------------------------------------------------------------- canonicalisation/hash

def test_canonical_form_is_key_order_independent():
    a = {"b": 1, "a": {"d": 2, "c": 3}}
    b = {"a": {"c": 3, "d": 2}, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_form_rejects_floats():
    """A float's shortest round-trip form is not identical across languages."""
    with pytest.raises(NonCanonicalValueError, match="Floating-point"):
        canonical_bytes({"timeout": 1.5})


def test_content_hash_detects_any_edit(example_records):
    record = copy.deepcopy(example_records["scanner_record"])
    assert record["content_hash"] == compute_content_hash(record)
    record["findings"][0]["confidence_basis"] += " "
    assert record["content_hash"] != compute_content_hash(record)


def test_content_hash_ignores_completion_time_only(example_records):
    """Identical evidence must hash identically even if the run took longer."""
    record = copy.deepcopy(example_records["scanner_record"])
    original = compute_content_hash(record)
    record["run"]["completed_at"] = "2027-01-01T00:00:00+00:00"
    assert compute_content_hash(record) == original
    record["run"]["started_at"] = "2027-01-01T00:00:00+00:00"
    assert compute_content_hash(record) != original


def test_finding_ids_are_deterministic_and_scope_sensitive():
    kwargs = dict(
        source_component="scanner",
        capability="process.shell",
        rule_id="process-shell",
        rule_version="1.2.0",
        evidence=[],
    )
    a = compute_finding_id(**kwargs, analysed=["a.py", "b.py"])
    b = compute_finding_id(**kwargs, analysed=["b.py", "a.py"])
    c = compute_finding_id(**kwargs, analysed=["a.py"])
    assert a == b, "finding ids must not depend on file enumeration order"
    assert a != c, (
        "a clean result over a narrower scope is a different finding; collapsing them "
        "would let a silently narrowed scope look like an unchanged result"
    )


def test_tampered_record_fails_validation(example_records):
    record = copy.deepcopy(example_records["scanner_record"])
    record["residual_uncertainty"] = "Nothing to worry about."
    with pytest.raises(SchemaValidationError, match="content_hash does not reproduce"):
        validate_record(record)


# ---------------------------------------------------------- remaining enforced invariants

def _minimal_record(**overrides):
    base = dict(
        component="scanner",
        tool_version="0.1.0",
        commit=None,
        artifact={
            "artifact_id": "x",
            "artifact_type": "local_directory",
            "declared_kind": None,
            "source": "/tmp/x",
            "immutable_reference": None,
            "acquisition_method": "user_supplied_path",
            "acquisition_authorised_by": None,
            "acquired_at": "2026-07-20T09:00:00+00:00",
            "content_hash": "a" * 64,
            "content_hash_method": "directory_manifest_v1",
            "file_count": 1,
            "total_bytes": 10,
        },
        run={
            "started_at": "2026-07-20T09:00:00+00:00",
            "completed_at": "2026-07-20T09:00:01+00:00",
            "execution_mode": "static_analysis",
            "invocation": "trustlens scan /tmp/x",
            "config_hash": None,
            "reasoning_notes": [],
        },
        scope=make_scope(analysed=["a.py"], languages=["python"]),
        claims={"establishes": ["ran"], "does_not_establish": ["safety"]},
        residual_uncertainty="illustrative",
    )
    base.update(overrides)
    return make_record(**base)


def test_vacuous_scope_is_flagged_not_hidden():
    """A check with nothing to examine carries no information and must say so."""
    empty = make_scope(analysed=[], languages=["yaml"])
    assert empty["vacuous"] is True
    non_empty = make_scope(analysed=["a.yaml"], languages=["yaml"])
    assert non_empty["vacuous"] is False


def test_schema_rejects_a_vacuous_scope_claiming_to_be_populated(example_records):
    record = copy.deepcopy(example_records["scanner_record"])
    record["findings"][0]["scope"]["analysed"] = []
    problems = validate_structure(record)
    assert any("vacuous" in p or "const" in p for p in problems), problems


def test_detection_method_and_evidence_strength_must_agree():
    with pytest.raises(ValueError, match="implies evidence_strength"):
        make_finding(
            capability="env.credential_pattern_read",
            status="FOUND",
            detection_method="config_derivation",
            evidence_strength="DIRECT_OBSERVATION",  # the overclaim
            rule_id="r",
            rule_version="1",
            source_component="credential_mapper",
            scope=make_scope(analysed=["env.yaml"], languages=["yaml"]),
            evidence=[{"kind": "config_key", "path": "env.yaml", "line": None, "excerpt": None, "redacted": True}],
            confidence_basis="c",
            limitations=["l"],
        )


def test_found_without_evidence_is_refused():
    with pytest.raises(ValueError, match="evidence location"):
        make_finding(
            capability="process.shell",
            status="FOUND",
            detection_method="static_ast",
            rule_id="r",
            rule_version="1",
            source_component="scanner",
            scope=make_scope(analysed=["a.py"], languages=["python"]),
            confidence_basis="c",
            limitations=["l"],
        )


def test_finding_without_limitations_is_refused():
    with pytest.raises(ValueError, match="limitations must be non-empty"):
        make_finding(
            capability="process.shell",
            status="UNKNOWN",
            detection_method="static_ast",
            rule_id="r",
            rule_version="1",
            source_component="scanner",
            scope=make_scope(analysed=["a.py"], languages=["python"]),
            confidence_basis="c",
            limitations=[],
            unknown_reason="not attempted",
        )


def test_generic_advice_cannot_replace_specific_mitigations():
    with pytest.raises(ValueError, match="may never stand in for them"):
        _minimal_record(generic_advice=["Apply least privilege."])


def test_blast_radius_record_must_declare_its_inputs():
    with pytest.raises(ValueError, match="must declare the records it composed"):
        _minimal_record(component="blast_radius")


def test_credential_mapper_record_must_carry_a_capture_timestamp(example_records):
    record = copy.deepcopy(example_records["credential_mapper_record"])
    record["environment_description_ref"] = None
    problems = validate_structure(record)
    assert problems, "a credential-mapper record without a dated description must not validate"


def test_config_derived_finding_carries_the_capture_timestamp(example_records):
    record = example_records["credential_mapper_record"]
    for finding in record["findings"]:
        if finding["detection_method"] in ("config_derivation", "policy_evaluation"):
            ref = finding["environment_description_ref"]
            assert ref is not None, (
                f"{finding['finding_id']} is configuration-derived but carries no capture "
                "timestamp; staleness must travel with the finding, not only the header"
            )
            assert ref["description_captured_at"]
            assert ref["captured_at_basis"] in ("operator_asserted", "exported_by_tool", "unknown")


# ------------------------------------------------------------------------ sandbox gating

def test_experimental_sandbox_must_carry_the_banner_in_the_evidence(example_records):
    record = example_records["sandbox_record"]
    sandbox = record["sandbox"]
    assert sandbox["sandbox_status"] == "EXPERIMENTAL"
    assert sandbox["banner"] == (
        "EXPERIMENTAL — DO NOT USE FOR SUSPECTED ZERO-DAY OR HOSTILE ARTIFACTS"
    )
    assert sandbox["approved_profiles"] == []
    assert sandbox["security_review_complete"] is False
    assert sandbox["review_record_hash"] is None


def test_experimental_sandbox_cannot_declare_approved_profiles(example_records):
    record = copy.deepcopy(example_records["sandbox_record"])
    record["sandbox"]["approved_profiles"] = ["hostile-input"]
    problems = validate_structure(record)
    assert problems, "an EXPERIMENTAL sandbox must not be able to list approved profiles"


def test_reviewed_status_requires_a_review_record_hash(example_records):
    """Changing the label alone must not change what the sandbox is permitted to do."""
    record = copy.deepcopy(example_records["sandbox_record"])
    record["sandbox"]["sandbox_status"] = "REVIEWED"
    problems = validate_structure(record)
    assert problems, (
        "flipping the status to REVIEWED without a review record hash, a completed "
        "review flag and an approved profile must not validate"
    )


def test_only_a_sandbox_record_may_claim_sandboxed_execution(example_records):
    record = copy.deepcopy(example_records["scanner_record"])
    record["run"]["execution_mode"] = "sandboxed_execution"
    problems = validate_structure(record)
    assert problems, "a non-sandbox component must not claim sandboxed execution"


# ----------------------------------------------------------------- contradictions and refs

def test_contradictions_are_never_marked_reconciled(example_records):
    for record in example_records.values():
        for c in record["contradictions"]:
            assert c["reconciled"] is False


def test_contradiction_with_a_dangling_reference_is_rejected(example_records):
    record = copy.deepcopy(example_records["scanner_record"])
    record["contradictions"][0]["between"][1]["ref"] = "scanner:process.shell:" + "0" * 16
    problems = validate_semantics(record, check_ids=False)
    assert any("not a finding_id" in p for p in problems), problems


def test_input_record_hash_mismatch_is_detected(example_records, corpus):
    record = copy.deepcopy(example_records["blast_radius_record"])
    record["input_records"][0]["content_hash"] = "0" * 64
    problems = validate_semantics(record, check_ids=False, corpus=corpus)
    assert any("content_hash does not match the corpus copy" in p for p in problems), problems
