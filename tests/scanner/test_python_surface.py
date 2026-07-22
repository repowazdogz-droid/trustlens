"""Controls for the Python-surface checks (dynamic execution, process/shell, deserialization)."""

from __future__ import annotations

from pathlib import Path

import pytest

from trustlens.evidence import Status, make_record, parse as parse_status
from trustlens.evidence.schema import validate_record
from trustlens.scanner.checks import python_surface as ps
from trustlens.scanner.pysource import parse_source, resolve

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "python_surface"
CLEAN = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

EXPECTED: dict[str, dict[str, str]] = {
    "clean_python": {},
    "fp_lookalikes": {},
    "unsafe_exec": {
        "execution.dynamic_eval": "FOUND",
        "execution.dynamic_import": "FOUND",
    },
    "unsafe_shell": {"process.subprocess": "FOUND", "process.shell": "FOUND"},
    "unsafe_deser": {"execution.deserialization": "FOUND"},
    "alias_bypass": {
        "process.subprocess": "FOUND",
        "process.shell": "FOUND",
        "execution.deserialization": "FOUND",
    },
    "unsafe_network": {
        "network.outbound": "FOUND",
        "network.dns": "FOUND",
        "network.package_fetch": "FOUND",
    },
    "unsafe_env": {
        "env.named_read": "FOUND",
        "env.enumeration": "FOUND",
        "env.credential_pattern_read": "FOUND",
    },
    "unsafe_cloud": {
        "cloud.metadata_endpoint": "FOUND",
        "k8s.serviceaccount_token_access": "FOUND",
        "container.docker_socket": "FOUND",
        "cloud.credential_file_access": "FOUND",
        "cloud.sdk_credential_discovery": "FOUND",
        "network.outbound": "FOUND",
    },
    "unsafe_filesystem": {
        "filesystem.write": "FOUND",
        "filesystem.delete": "FOUND",
        "filesystem.permission_change": "FOUND",
        "filesystem.archive_extraction": "FOUND",
        "filesystem.read_sensitive_path": "FOUND",
        "filesystem.path_traversal": "FOUND",
    },
    "unsafe_package": {
        "package.install_at_runtime": "FOUND",
        "process.subprocess": "FOUND",
        "process.shell": "FOUND",
    },
    "partial_python": "ALL_PARTIAL",
}


def _statuses(name: str) -> dict[str, str]:
    result = ps.run(FIXTURES / name)
    return {f["capability"]: f["status"] for f in result.findings}


@pytest.mark.parametrize("fixture", sorted(EXPECTED))
def test_fixture_statuses(fixture):
    statuses = _statuses(fixture)
    expected = EXPECTED[fixture]
    if expected == "ALL_PARTIAL":
        # One unparseable file contaminates every capability's scope, by design.
        assert set(statuses.values()) == {"PARTIAL"}, statuses
        return
    for capability, want in expected.items():
        assert statuses[capability] == want, f"{fixture}/{capability}"
    for capability, got in statuses.items():
        if capability not in expected:
            assert got == CLEAN, f"{fixture}/{capability} unexpectedly {got}"


def test_every_fixture_is_covered_by_the_table():
    on_disk = {d.name for d in FIXTURES.iterdir() if d.is_dir()}
    assert on_disk == set(EXPECTED)


# ------------------------------------------------------------------- bypass controls

def test_renamed_imports_do_not_evade_detection():
    """`import subprocess as sp` is a one-line bypass unless aliases are resolved."""
    result = ps.run(FIXTURES / "alias_bypass")
    resolved = {h.matched_name for h in result.hits}
    assert "subprocess.Popen" in resolved
    assert "os.system" in resolved
    assert "pickle.loads" in resolved, "from pickle import loads as unpack was not resolved"


def test_alias_resolution_unit():
    pf = parse_source(
        "import subprocess as sp\nfrom pickle import loads as unpack\nimport os.path as osp\n",
        "a.py",
    )
    assert resolve("sp.Popen", pf.aliases) == "subprocess.Popen"
    assert resolve("unpack", pf.aliases) == "pickle.loads"
    assert resolve("osp.join", pf.aliases) == "os.path.join"
    assert resolve("unrelated.thing", pf.aliases) == "unrelated.thing"


def test_relative_imports_are_not_falsely_resolved():
    """A relative import's target is outside this file's knowledge; do not guess it."""
    pf = parse_source("from . import loads\n", "a.py")
    assert pf.aliases == {}


# ------------------------------------------------------- conditional-rule discipline

@pytest.mark.parametrize(
    "source,capability,should_fire",
    [
        ("import yaml\ndef f(t): return yaml.safe_load(t)\n", "execution.deserialization", False),
        ("import yaml\ndef f(t): return yaml.load(t, Loader=yaml.SafeLoader)\n", "execution.deserialization", False),
        ("import yaml\ndef f(t): return yaml.load(t)\n", "execution.deserialization", True),
        ("import yaml\ndef f(t): return yaml.load(t, Loader=yaml.FullLoader)\n", "execution.deserialization", True),
        ("import torch\ndef f(p): return torch.load(p)\n", "execution.deserialization", False),
        ("import torch\ndef f(p): return torch.load(p, weights_only=True)\n", "execution.deserialization", False),
        ("import torch\ndef f(p): return torch.load(p, weights_only=False)\n", "execution.deserialization", True),
        ("import numpy as np\ndef f(p): return np.load(p)\n", "execution.deserialization", False),
        ("import numpy as np\ndef f(p): return np.load(p, allow_pickle=True)\n", "execution.deserialization", True),
        ("import subprocess\ndef f(c): subprocess.run(c)\n", "process.shell", False),
        ("import subprocess\ndef f(c): subprocess.run(c, shell=True)\n", "process.shell", True),
    ],
)
def test_conditional_rules_fire_only_under_their_condition(source, capability, should_fire):
    pf = parse_source(source, "a.py")
    hits = ps.scan_file(pf)
    fired = {h.rule.capability for h in hits}
    assert (capability in fired) is should_fire, (
        f"{source!r} -> fired={sorted(fired)}; expected {capability} fire={should_fire}"
    )


def test_imports_without_calls_do_not_fire():
    pf = parse_source("import pickle\nimport subprocess\nimport os\nX = 1\n", "a.py")
    assert ps.scan_file(pf) == []


def test_strings_and_comments_do_not_fire():
    pf = parse_source(
        'X = "call subprocess.Popen and os.system and eval"\n'
        "# eval(x) exec(y) pickle.loads(z)\n",
        "a.py",
    )
    assert ps.scan_file(pf) == []


# ---------------------------------------------------------------- parse-failure policy

def test_parse_failure_forces_partial_and_names_the_file():
    result = ps.run(FIXTURES / "partial_python")
    failed = result.scope["failed"]
    assert [f["path"] for f in failed] == ["broken.py"]
    assert failed[0]["kind"] == "parse_error"
    assert "SyntaxError" in failed[0]["reason"]
    assert all(parse_status(f["status"]) is Status.PARTIAL for f in result.findings)


def test_null_byte_source_is_a_recorded_failure():
    pf = parse_source("x = 1\x00\n", "a.py")
    assert not pf.ok
    assert pf.failed_item["kind"] == "parse_error"


def test_deeply_nested_source_is_fenced_not_crashed():
    """The documented ast.parse interpreter-crash vector must become a recorded failure."""
    pf = parse_source("x = " + "[" * 20000 + "]" * 20000 + "\n", "deep.py")
    assert not pf.ok, "deeply nested input must not be reported as parsed"
    assert pf.failed_item["kind"] in {"parse_error", "resource_limit"}


# ------------------------------------------------------------------ evidence quality

def test_found_findings_carry_line_and_resolved_name():
    result = ps.run(FIXTURES / "alias_bypass")
    for finding in result.findings:
        if finding["status"] != "FOUND":
            continue
        for ev in finding["evidence"]:
            assert ev["path"] and ev["line"]
            assert "resolved=" in (ev["detail"] or ""), "evidence must show the resolved callee"
            assert "rule=" in (ev["detail"] or ""), "evidence must name the rule that fired"


def test_every_finding_states_a_blind_spot():
    result = ps.run(FIXTURES / "unsafe_deser")
    for finding in result.findings:
        assert finding["limitations"]


def test_findings_validate_inside_a_phase0_record():
    result = ps.run(FIXTURES / "unsafe_shell")
    record = make_record(
        component="scanner",
        tool_version="0.1.0",
        commit=None,
        artifact={
            "artifact_id": "fixture-unsafe-shell",
            "artifact_type": "local_directory",
            "declared_kind": None,
            "source": "tests/fixtures/python_surface/unsafe_shell",
            "immutable_reference": None,
            "acquisition_method": "already_local",
            "acquisition_authorised_by": None,
            "acquired_at": "2026-07-22T00:00:00+00:00",
            "content_hash": "a" * 64,
            "content_hash_method": "directory_manifest_v1",
            "file_count": 1,
            "total_bytes": 256,
        },
        run={
            "started_at": "2026-07-22T00:00:00+00:00",
            "completed_at": "2026-07-22T00:00:01+00:00",
            "execution_mode": "static_analysis",
            "invocation": "pytest",
            "config_hash": None,
            "reasoning_notes": ["python-surface checks only"],
        },
        scope=result.scope,
        findings=result.findings,
        claims={
            "establishes": ["The python-surface checks ran over the recorded scope."],
            "does_not_establish": ["That any matched call executes at runtime."],
        },
        residual_uncertainty="Only three check families ran.",
    )
    validate_record(record)


def test_rule_ids_are_unique():
    ids = [r.rule_id for r in ps.RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_declares_a_blind_spot():
    for rule in ps.RULES:
        assert rule.blind_spot, f"{rule.rule_id} has no stated blind spot"
        assert rule.what, f"{rule.rule_id} has no description"
        if rule.predicate is not None:
            assert rule.predicate_note, f"{rule.rule_id} is conditional but says no condition"
