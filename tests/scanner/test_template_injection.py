"""Controls for the template-injection-in-configuration check.

Structure follows the rule in CONTRIBUTING.md: positive controls, negative controls,
false-positive controls, a PARTIAL control, and a test that each control actually
executes rather than merely existing in the repository.

The most important test in this file is `test_dangerous_yaml_tag_is_not_executed`, which
demonstrates non-execution with an observable side effect rather than asserting it. Every
other guarantee here is about what the check *reports*; that one is about what the check
*does*, and it is the only one whose failure would make TrustLens itself the vulnerability.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustlens.evidence import Status, make_record, make_scope, parse as parse_status
from trustlens.evidence.schema import validate_record
from trustlens.scanner.checks import template_injection as ti
from trustlens.scanner.config_parse import is_nonstandard_tag, parse_config

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "template_injection"

CAP = {
    "surface": "template.injection_surface",
    "eval": "template.expression_evaluation",
    "deser": "execution.deserialization",
}

CLEAN = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

#: The full expected behaviour of the check, per fixture. This table IS the control set.
EXPECTED = {
    # --- negative controls: must produce no findings
    "clean_dataset": {"surface": CLEAN, "eval": CLEAN, "deser": CLEAN},
    # --- false-positive controls: constructs that look dangerous and are not
    "clean_chat_template": {"surface": CLEAN, "eval": CLEAN, "deser": CLEAN},
    "fp_lookalikes": {"surface": CLEAN, "eval": CLEAN, "deser": CLEAN},
    # --- positive controls: each must be caught, by the specific mechanism
    "unsafe_resolver_eval": {"surface": "FOUND", "eval": "FOUND", "deser": CLEAN},
    "unsafe_ssti_gadget": {"surface": CLEAN, "eval": "FOUND", "deser": CLEAN},
    "unsafe_yaml_tag": {"surface": CLEAN, "eval": CLEAN, "deser": "FOUND"},
    "unsafe_flow": {"surface": "FOUND", "eval": "FOUND", "deser": CLEAN},
    # --- PARTIAL control
    "partial_config": {"surface": "PARTIAL", "eval": "PARTIAL", "deser": "PARTIAL"},
}


def _run(name: str) -> ti.CheckResult:
    return ti.run(FIXTURES / name)


def _statuses(result: ti.CheckResult) -> dict[str, str]:
    inv = {v: k for k, v in CAP.items()}
    return {inv[f["capability"]]: f["status"] for f in result.findings}


# --------------------------------------------------------------------- the control table

@pytest.mark.parametrize("fixture", sorted(EXPECTED))
def test_fixture_produces_expected_statuses(fixture):
    assert _statuses(_run(fixture)) == EXPECTED[fixture]


def test_every_fixture_directory_is_covered_by_the_table():
    """A fixture that exists but is never asserted on is not a control."""
    on_disk = {d.name for d in FIXTURES.iterdir() if d.is_dir()}
    assert on_disk == set(EXPECTED), (
        f"fixtures without expectations: {on_disk - set(EXPECTED)}; "
        f"expectations without fixtures: {set(EXPECTED) - on_disk}"
    )


# ------------------------------------------------------------- proof of non-execution

def test_dangerous_yaml_tag_is_not_executed(tmp_path):
    """Demonstrate, not assert, that parsing never constructs the object.

    The tag below names `os.system` with a command that would create an observable file.
    It is harmless — it writes an empty file into pytest's temp directory and contacts
    nothing — but if TrustLens ever parsed with `yaml.load` or a constructing loader, the
    file would appear and this test would fail. That is the point: non-execution is
    demonstrated by an effect that would occur, not by reading the code.
    """
    canary = tmp_path / "canary_must_not_exist"
    doc = tmp_path / "evil.yaml"
    doc.write_text(
        "# TrustLens SYNTHETIC UNSAFE FIXTURE - proves non-execution\n"
        f"payload: !!python/object/apply:os.system ['touch {canary}']\n",
        encoding="utf-8",
    )

    parsed = parse_config(doc, "evil.yaml")

    assert not canary.exists(), (
        "TrustLens CONSTRUCTED an untrusted YAML tag. Parsing must never execute; this is "
        "the tool becoming the vulnerability."
    )
    # And it must still have been detected, not merely survived.
    assert parsed.ok, "the document should parse, with the tag recorded rather than resolved"
    assert parsed.dangerous_tags, "the dangerous tag must be detected"
    assert "os.system" in parsed.dangerous_tags[0].tag


def test_standard_yaml_types_are_not_flagged_as_tags():
    """The allowlist must not fire on ordinary YAML."""
    for tag in ("tag:yaml.org,2002:str", "tag:yaml.org,2002:int", "tag:yaml.org,2002:map"):
        assert is_nonstandard_tag(tag) is False


def test_python_object_tag_carries_the_standard_prefix_and_is_still_caught():
    """Regression: the first version tested the prefix and missed this exact tag."""
    tag = "tag:yaml.org,2002:python/object/apply:os.system"
    assert tag.startswith("tag:yaml.org,2002:"), "precondition of the original bug"
    assert is_nonstandard_tag(tag) is True


# ----------------------------------------------------------- false-positive accounting

def test_chat_template_suppression_is_recorded_not_silent():
    """A suppressed match must remain visible; a silent drop reads as 'nothing there'."""
    result = _run("clean_chat_template")
    assert result.suppressions, "conventional chat-template Jinja should be suppressed"
    assert {s.rule_id for s in result.suppressions} == {"jinja-block", "jinja-expression"}
    surface = next(f for f in result.findings if f["capability"] == CAP["surface"])
    assert "suppressed" in surface["confidence_basis"], (
        "the count of suppressed matches must appear in the finding, not only in a log"
    )


def test_gadget_still_fires_inside_a_suppressed_template_field():
    """Suppression must not become a blanket exemption for the field."""
    result = _run("unsafe_ssti_gadget")
    assert result.suppressions, "conventional syntax in the same field is still suppressed"
    assert any(m.detector.rule_id == "ssti-gadget" for m in result.matches)


def test_prose_backticks_do_not_fire():
    """Regression: '`--verbose`' in a description matched shell-substitution in v0."""
    result = _run("fp_lookalikes")
    assert result.matches == [], f"false positives: {[m.detector.rule_id for m in result.matches]}"


def test_format_braces_in_prose_do_not_fire():
    result = _run("fp_lookalikes")
    assert not any(m.detector.rule_id.startswith("jinja") for m in result.matches)


# ------------------------------------------------------------------ PARTIAL enforcement

def test_partial_names_the_file_it_could_not_read():
    result = _run("partial_config")
    for finding in result.findings:
        assert parse_status(finding["status"]) is Status.PARTIAL
        failed = finding["scope"]["failed"]
        assert failed, "PARTIAL must name what failed"
        assert failed[0]["path"].endswith("legacy.yaml")
        assert failed[0]["kind"] == "decode_error"
        assert "UnicodeDecodeError" in failed[0]["reason"]


def test_partial_is_not_reported_as_clean():
    """The whole point of the taxonomy, exercised end to end through a real check."""
    result = _run("partial_config")
    assert not any(
        parse_status(f["status"]) is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
        for f in result.findings
    )


def test_clean_fixture_has_an_empty_failed_list():
    result = _run("clean_dataset")
    assert result.scope["failed"] == []
    assert result.scope["vacuous"] is False


# ------------------------------------------------------------------- evidence quality

def test_every_found_finding_has_located_evidence():
    for name, expected in EXPECTED.items():
        result = _run(name)
        for finding in result.findings:
            if finding["status"] != "FOUND":
                continue
            assert finding["evidence"], f"{name}: FOUND with no evidence"
            for ev in finding["evidence"]:
                assert ev["path"], f"{name}: evidence with no path"
                assert ev["line"] is not None, f"{name}: evidence with no line"


def test_evidence_excerpt_shows_context_not_just_the_match():
    """A bare 'cycler' is not reviewable; the excerpt must carry surrounding value."""
    result = _run("unsafe_ssti_gadget")
    gadget = next(m for m in result.matches if m.detector.rule_id == "ssti-gadget")
    assert len(gadget.excerpt) > len("cycler")
    assert "__globals__" in gadget.excerpt


def test_flow_is_reported_once_not_once_per_scope():
    result = _run("unsafe_flow")
    keys = [(f.path, f.line, f.sink, f.source_name) for f in result.flows]
    assert len(keys) == len(set(keys)), f"duplicate flows: {keys}"
    assert len(keys) == 1


def test_flow_detection_requires_a_config_source():
    """A render sink with no configuration input is not a finding."""
    src = (
        "from jinja2 import Template\n"
        "def build():\n"
        "    return Template('hello {{ x }}').render(x=1)\n"
    )
    assert ti.find_config_to_sink_flows(src, "a.py") == []


def test_flow_detection_is_intra_function_only():
    """Cross-function flow is a known miss and must not be silently claimed."""
    src = (
        "import yaml\n"
        "from jinja2 import Template\n"
        "def load(p):\n"
        "    return yaml.safe_load(open(p).read())\n"
        "def render(cfg):\n"
        "    return Template(cfg['t']).render()\n"
    )
    assert ti.find_config_to_sink_flows(src, "a.py") == [], (
        "interprocedural flow must not be claimed; it is out of scope and documented as such"
    )


# ------------------------------------------------------------- shared-schema conformance

def test_findings_validate_inside_a_phase0_evidence_record():
    """Phase 1 output must be a valid Phase 0 record, or the components cannot compose."""
    result = _run("unsafe_resolver_eval")
    record = make_record(
        component="scanner",
        tool_version="0.1.0",
        commit=None,
        artifact={
            "artifact_id": "fixture-unsafe-resolver-eval",
            "artifact_type": "local_directory",
            "declared_kind": None,
            "source": "tests/fixtures/template_injection/unsafe_resolver_eval",
            "immutable_reference": None,
            "acquisition_method": "already_local",
            "acquisition_authorised_by": None,
            "acquired_at": "2026-07-22T00:00:00+00:00",
            "content_hash": "a" * 64,
            "content_hash_method": "directory_manifest_v1",
            "file_count": 1,
            "total_bytes": 128,
        },
        run={
            "started_at": "2026-07-22T00:00:00+00:00",
            "completed_at": "2026-07-22T00:00:01+00:00",
            "execution_mode": "static_analysis",
            "invocation": "pytest",
            "config_hash": None,
            "reasoning_notes": ["template-injection check only"],
        },
        scope=result.scope,
        findings=result.findings,
        claims={
            "establishes": ["The template-injection check ran over the recorded scope."],
            "does_not_establish": ["That any matched expression is rendered at runtime."],
        },
        residual_uncertainty="Only the template-injection check ran; other checks did not.",
    )
    validate_record(record)


def test_every_finding_declares_a_nonempty_limitation():
    result = _run("unsafe_flow")
    for finding in result.findings:
        assert finding["limitations"], f"{finding['capability']} has no stated blind spot"


def test_detection_method_matches_the_claim():
    """Dataflow strength may only be claimed where a flow was actually found."""
    with_flow = _run("unsafe_flow")
    ev = next(f for f in with_flow.findings if f["capability"] == CAP["eval"])
    assert ev["detection_method"] == "static_ast_dataflow"
    assert ev["evidence_strength"] == "STATIC_DATAFLOW"

    no_flow = _run("unsafe_resolver_eval")
    ev2 = next(f for f in no_flow.findings if f["capability"] == CAP["eval"])
    assert ev2["detection_method"] == "static_ast"
    assert ev2["evidence_strength"] == "STATIC_MATCH"
