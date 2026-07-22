"""Controls for the bundled example repositories, at the full-scanner level.

The individual check families each have their own detonate-then-defuse control. This file
raises that to the level the user actually operates at: the whole scanner, over a whole
repository. A negative control that has never been shown to be capable of firing proves
nothing, so the unsafe examples are first **materialised as live payloads and detonated**,
then scanned fresh.

Expectations here are the brief's controls: three known-clean examples that must produce no
findings, two synthetic unsafe examples that must produce a clear declared-versus-reachable
discrepancy, and one example that must produce PARTIAL.
"""

from __future__ import annotations

import json
import os
import pickle
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from trustlens.evidence import Status, parse as parse_status
from trustlens.evidence.schema import validate_record
from trustlens.scanner.assemble import scan, summarise

ROOT = Path(__file__).resolve().parents[2]
REPOS = ROOT / "examples" / "repos"
CONTROL_RUNS = ROOT / "examples" / "control_runs"

CLEAN = ("clean_tabular", "clean_jsonl", "clean_imagefolder")
UNSAFE = ("unsafe_dataset_loader", "unsafe_model_repo")
PARTIAL = ("partial_encoding",)


# ------------------------------------------------------------------ negative controls

@pytest.mark.parametrize("name", CLEAN)
def test_clean_examples_produce_no_findings(name):
    result = scan(REPOS / name)
    validate_record(result.record)
    summary = summarise(result)
    assert summary["found"] == [], f"{name} produced findings: {summary['found']}"
    assert summary["analysis_complete"] is True
    assert result.record["scope"]["failed"] == []


@pytest.mark.parametrize("name", CLEAN)
def test_clean_examples_still_state_every_capability(name):
    """Clean must mean 'checked and nothing matched', not 'nothing was said'."""
    result = scan(REPOS / name)
    statuses = {f["capability"]: f["status"] for f in result.record["findings"]}
    assert statuses, f"{name} produced no findings at all"
    assert set(statuses.values()) == {"NOT_FOUND_WITHIN_ANALYSED_SCOPE"}


# ------------------------------------------------------------------ positive controls

EXPECTED_UNSAFE = {
    "unsafe_dataset_loader": {
        "execution.loader_script",
        "execution.dynamic_import",
        "execution.deserialization",
        "process.shell",
        "network.outbound",
        "template.expression_evaluation",
        "cloud.metadata_endpoint",
    },
    "unsafe_model_repo": {
        "execution.dynamic_import",
        "execution.deserialization",
        "process.shell",
        "env.credential_pattern_read",
        "k8s.serviceaccount_token_access",
        "template.expression_evaluation",
    },
}


@pytest.mark.parametrize("name", UNSAFE)
def test_unsafe_examples_are_detected(name):
    result = scan(REPOS / name)
    validate_record(result.record)
    found = set(summarise(result)["found"])
    missing = EXPECTED_UNSAFE[name] - found
    assert not missing, f"{name} missed: {sorted(missing)}"


def test_unsafe_dataset_loader_shows_a_declared_versus_reachable_discrepancy():
    """The card says passive data; the repository executes, fetches and deserialises."""
    result = scan(REPOS / "unsafe_dataset_loader")
    found = set(summarise(result)["found"])
    executes = found & {
        "execution.dynamic_import",
        "execution.deserialization",
        "process.shell",
    }
    reaches = found & {"network.outbound", "cloud.metadata_endpoint"}
    assert executes and reaches, (
        "an artifact presented as a dataset must be shown to both execute and reach out"
    )


# ------------------------------------------------------------------- PARTIAL control

@pytest.mark.parametrize("name", PARTIAL)
def test_partial_example_is_partial_not_clean(name):
    result = scan(REPOS / name)
    validate_record(result.record)
    failed = result.record["scope"]["failed"]
    assert [Path(f["path"]).name for f in failed] == ["legacy.yaml"]
    assert failed[0]["kind"] == "decode_error"
    # A finding may legitimately be clean over a NARROWER scope than the record's — the
    # loader-scripts family only reads .py and .json, so an undecodable .yaml is genuinely
    # outside its scope. What must never happen is a finding claiming clean over a scope
    # that DOES contain the failure, and the record hiding the failure at the top level.
    for finding in result.record["findings"]:
        if finding["scope"]["failed"]:
            assert parse_status(finding["status"]) is not Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE

    summary = summarise(result)
    assert summary["scope_complete"] is False
    assert [f["path"] for f in summary["scope_failures"]] == ["legacy.yaml"]
    assert summary["incomplete"], "capabilities whose scope included the file must be incomplete"


# ------------------------------------------- detonate-then-defuse at full-scanner level

def _materialise_live(src: Path, dest: Path, canaries: dict[str, Path]) -> None:
    """Copy an example repo and arm it with payloads that really fire.

    The committed repositories keep every dangerous call inside a function, so they are
    inert on disk. This adds the module-level trigger, a malicious pickle and an unsafe
    YAML tag, all pointed at temp-directory canaries, producing a genuinely live artifact
    to scan.
    """
    shutil.copytree(src, dest)
    (dest / "sitecustomize_payload.py").write_text(
        "# TrustLens SYNTHETIC UNSAFE - fires at import time\n"
        "import os\n"
        f"os.system('touch {canaries['import']}')\n",
        encoding="utf-8",
    )

    class _Detonator:
        def __reduce__(self):
            return (os.system, (f"touch {canaries['pickle']}",))

    (dest / "payload.pkl").write_bytes(pickle.dumps(_Detonator()))
    (dest / "armed.yaml").write_text(
        "# TrustLens SYNTHETIC UNSAFE - fires under a constructing loader\n"
        f"boom: !!python/object/apply:os.system ['touch {canaries['yaml']}']\n",
        encoding="utf-8",
    )


@pytest.fixture
def armed_repo(tmp_path, request):
    name = getattr(request, "param", "unsafe_dataset_loader")
    canaries = {
        "import": tmp_path / "CANARY_IMPORT",
        "pickle": tmp_path / "CANARY_PICKLE",
        "yaml": tmp_path / "CANARY_YAML",
    }
    dest = tmp_path / "armed"
    _materialise_live(REPOS / name, dest, canaries)
    return dest, canaries


@pytest.mark.parametrize("armed_repo", UNSAFE, indirect=True)
def test_armed_example_payloads_are_actually_live(armed_repo, tmp_path):
    """Detonate. Without this, the inertness result below would prove nothing."""
    repo, canaries = armed_repo

    # import-time payload
    sys.path.insert(0, str(repo))
    try:
        __import__("sitecustomize_payload")
    finally:
        sys.path.remove(str(repo))
        sys.modules.pop("sitecustomize_payload", None)

    pickle.loads((repo / "payload.pkl").read_bytes())
    yaml.unsafe_load((repo / "armed.yaml").read_text())

    for kind, canary in canaries.items():
        assert canary.exists(), f"the {kind} payload did not fire; the control would be vacuous"


@pytest.mark.parametrize("armed_repo", UNSAFE, indirect=True)
def test_full_scanner_over_an_armed_example_fires_nothing(armed_repo, monkeypatch):
    """Defuse: scan the same live artifact with the whole scanner and prove it is inert."""
    repo, canaries = armed_repo
    attempted: list[str] = []

    def _boom(name):
        def _f(*a, **k):
            attempted.append(name)
            raise AssertionError(f"scanner called {name} — the full scan must be inert")

        return _f

    monkeypatch.setattr(subprocess, "Popen", _boom("subprocess.Popen"))
    monkeypatch.setattr(subprocess, "run", _boom("subprocess.run"))
    monkeypatch.setattr(os, "system", _boom("os.system"))
    monkeypatch.setattr(socket, "socket", _boom("socket.socket"))

    before = set(sys.modules)
    result = scan(repo)

    for kind, canary in canaries.items():
        assert not canary.exists(), f"the full scan fired the {kind} payload"
    assert attempted == [], f"scanner attempted: {attempted}"
    assert "sitecustomize_payload" not in set(sys.modules) - before

    # and it still detected the artifact rather than achieving inertness by not looking
    found = set(summarise(result)["found"])
    assert "execution.deserialization" in found, "the armed YAML tag was not detected"


# ------------------------------------------------------------- stored control evidence

def test_control_run_evidence_exists_for_every_example():
    stored = {p.stem for p in CONTROL_RUNS.glob("*.json")}
    on_disk = {d.name for d in REPOS.iterdir() if d.is_dir()}
    assert stored == on_disk, (
        f"missing stored evidence: {sorted(on_disk - stored)}; "
        f"orphaned: {sorted(stored - on_disk)}"
    )


@pytest.mark.parametrize("name", CLEAN + UNSAFE + PARTIAL)
def test_stored_control_run_matches_a_fresh_scan(name):
    """Stored evidence must be what the scanner actually produces today."""
    stored = json.loads((CONTROL_RUNS / f"{name}.json").read_text())
    fresh = scan(
        REPOS / name,
        started_at="2026-07-22T00:00:00+00:00",
        completed_at="2026-07-22T00:00:01+00:00",
        artifact_source=f"examples/repos/{name}",
    )
    assert stored["record"]["content_hash"] == fresh.record["content_hash"], (
        f"stored control-run evidence for {name} is stale; regenerate with "
        "examples/generate_control_runs.py"
    )
    assert stored["summary"]["found"] == summarise(fresh)["found"]


@pytest.mark.parametrize("name", CLEAN + UNSAFE + PARTIAL)
def test_stored_control_run_records_validate(name):
    stored = json.loads((CONTROL_RUNS / f"{name}.json").read_text())
    validate_record(stored["record"])
