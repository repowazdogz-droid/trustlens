"""Controls for the optional Go RBAC helper and its boundary.

Verified against **real** manifests: cert-manager v1.16.2's shipped RBAC, kube-prometheus's
ClusterRole with real `nonResourceURLs`, and kubectl v1.33.9 `--dry-run=client` output.
See `tests/fixtures/mapper/real_k8s/PROVENANCE.md`. Hand-written manifests have twice
missed real-world format details in this build, so they are not used here.

The boundary tests matter as much as the functional ones: this binary's existence must not
create any implicit path from the core scan path to a subprocess.
"""

from __future__ import annotations

import inspect
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from trustlens.mapper import rbac_helper

REAL = Path(__file__).resolve().parents[1] / "fixtures" / "mapper" / "real_k8s"

BINARY = rbac_helper.resolve_binary()
needs_binary = pytest.mark.skipif(
    BINARY is None,
    reason="optional trustlens-rbac helper not built; its absence is a supported state",
)


# ------------------------------------------------------ the boundary must not have drifted

def test_core_scan_path_cannot_reach_the_helper():
    """Nothing in scan() or map-credentials imports the helper."""
    from trustlens.scanner import assemble as scanner_assemble
    from trustlens.mapper import assemble as mapper_assemble

    for module in (scanner_assemble, mapper_assemble):
        source = inspect.getsource(module)
        assert "rbac_helper" not in source, (
            f"{module.__name__} references the optional helper; it must stay out of the "
            "core path per the 2026-07-22 placement decision"
        )


def test_core_modules_import_nothing_that_spawns():
    for name in ("model", "terraform", "rbac", "assemble"):
        source = (Path(rbac_helper.__file__).parent / f"{name}.py").read_text()
        for banned in ("import subprocess", "os.system", "import socket"):
            assert banned not in source, f"mapper/{name}.py contains {banned!r}"


def test_helper_is_the_only_mapper_module_that_spawns():
    source = Path(rbac_helper.__file__).read_text()
    assert "import subprocess" in source, "the helper is expected to spawn; that is its job"


# -------------------------------------------------------------- absence is a valid state

def test_absent_binary_is_a_recorded_state_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTLENS_RBAC_BIN", str(tmp_path / "nope"))
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.setattr(
        rbac_helper, "resolve_binary", lambda explicit=None: None
    )
    result = rbac_helper.run_helper(REAL)
    assert result.available is False
    assert "does not make" in result.unavailable_reason
    assert "UNSUPPORTED" in result.unavailable_reason


def test_only_the_allowlisted_name_is_ever_executed(tmp_path):
    """A binary under any other name is refused even when pointed at explicitly."""
    impostor = tmp_path / "not-trustlens-rbac"
    impostor.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    impostor.chmod(0o755)
    assert rbac_helper.resolve_binary(str(impostor)) != str(impostor)


def test_external_tool_block_is_empty_when_unavailable():
    result = rbac_helper.HelperResult(
        available=False, binary_path=None, version=None, version_source="unknown"
    )
    assert rbac_helper.external_tool_block(result, REAL) == []


# ------------------------------------------------------------------- real-manifest runs

@needs_binary
def test_helper_runs_against_real_manifests():
    result = rbac_helper.run_helper(REAL)
    assert result.available, result.unavailable_reason
    assert result.exit_code == 0, result.stderr
    assert result.failed == [], "the real manifests should all parse"
    assert len(result.analysed) >= 4
    assert result.service_accounts, "cert-manager ships ServiceAccounts"


@needs_binary
def test_upstream_authorizer_reasons_are_carried_through():
    """The value of reusing upstream is its reason string; it must not be discarded."""
    result = rbac_helper.run_helper(REAL)
    allowed = [d for d in result.decisions if d["allowed"]]
    assert allowed, "cert-manager's controller genuinely can read secrets"
    assert any("RBAC: allowed by" in d["reason"] for d in allowed), (
        "the upstream authorizer's own reason must be preserved"
    )


@needs_binary
def test_secret_access_is_detected_on_real_rbac():
    result = rbac_helper.run_helper(REAL)
    secret_reads = [
        d for d in result.decisions
        if d["allowed"] and d["resource"] == "secrets" and d["verb"] in ("get", "list")
    ]
    assert secret_reads, "cert-manager's RBAC does grant secret access; it must be found"


@needs_binary
def test_output_is_deterministic_across_runs():
    """The rejected graph tools were not. This one sorts every collection before emitting."""
    outputs = set()
    for _ in range(5):
        proc = subprocess.run(
            [BINARY, "--dir", str(REAL)], capture_output=True, text=True, timeout=120
        )
        outputs.add(proc.stdout)
    assert len(outputs) == 1, f"{len(outputs)} distinct outputs across 5 identical runs"


@needs_binary
def test_version_is_reported_by_the_tool_not_assumed():
    result = rbac_helper.run_helper(REAL)
    block = rbac_helper.external_tool_block(result, REAL)
    assert block and block[0]["name"] == "trustlens-rbac"
    assert block[0]["version_source"] in ("reported_by_tool", "unknown")
    if block[0]["version_source"] == "reported_by_tool":
        assert block[0]["version"] != "unknown"


@needs_binary
def test_kubernetes_semantics_version_is_recorded():
    """A decision is only meaningful alongside the semantics that produced it."""
    result = rbac_helper.run_helper(REAL)
    assert result.kubernetes_module, "the pinned Kubernetes minor must be recorded"


@needs_binary
def test_malformed_manifest_is_a_failure_not_a_clean_run(tmp_path):
    """Exit 1 plus a recorded failure; never a clean evaluation over unread input."""
    (tmp_path / "ok.yaml").write_text(
        "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: a, namespace: n}\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.yaml").write_text("kind: Role\nmetadata: {name: x\n  broken\n", encoding="utf-8")
    result = rbac_helper.run_helper(tmp_path)
    assert result.exit_code == 1, "a parse failure must not exit 0"
    assert result.failed, "the unparseable manifest must be recorded"


@needs_binary
def test_helper_contacts_no_cluster(tmp_path, monkeypatch):
    """It must work with no kubeconfig and no network reachable."""
    env = dict(os.environ)
    env["KUBECONFIG"] = str(tmp_path / "nonexistent-kubeconfig")
    env["HOME"] = str(tmp_path)
    proc = subprocess.run(
        [BINARY, "--dir", str(REAL)], capture_output=True, text=True, timeout=120, env=env
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["decisions"], "it must still evaluate with no kubeconfig"


@needs_binary
def test_requires_an_explicit_directory():
    proc = subprocess.run([BINARY], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "never contacts a cluster" in proc.stderr


# --------------------------------------------------- coverage audit for this component

@needs_binary
def test_every_declared_helper_capability_is_reachable():
    """The standing check: no declared capability may be structurally unreachable.

    This is the audit that caught identity.token_use in map-credentials. Applied here
    before calling the helper done.
    """
    result = rbac_helper.run_helper(REAL)
    resources = {d["resource"] for d in result.decisions}
    # k8s.api_access is produced by any probe; k8s.serviceaccount_token_access by the
    # secret probes. Both must have at least one probe that can produce them.
    assert resources, "no probe produced any decision"
    assert "secrets" in resources, (
        "k8s.serviceaccount_token_access is declared but no probe targets secrets, so it "
        "could never be reported — the env.credential_pattern_read failure shape"
    )
    assert len(resources) > 1, "k8s.api_access needs a probe beyond the secret ones"


def test_explicit_binary_path_never_falls_back(tmp_path):
    """Regression: an explicit --binary that does not resolve must NOT silently run another.

    The first version fell through to the repo-local build, so `--binary /nonexistent`
    quietly executed a different binary than the one named. That is the same
    silent-substitution shape as an explicitly requested git ref falling back to HEAD,
    already fixed once in scanner/acquire.py.
    """
    assert rbac_helper.resolve_binary(str(tmp_path / "nonexistent")) is None
    wrong_name = tmp_path / "something-else"
    wrong_name.write_text("#!/bin/sh\n", encoding="utf-8")
    wrong_name.chmod(0o755)
    assert rbac_helper.resolve_binary(str(wrong_name)) is None
