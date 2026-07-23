"""The conformance harness: grading, never-silent parsing, and the probe negative control.

The load-bearing test in this file is the negative control. A conformance suite whose probes
can only ever report `CONFORMS` proves nothing — it is the sandbox-scale version of the
"silent on clean result" bug the project treats as a standing check. So several tests here
drive the probes into their `DEVIATES` branch and confirm they fire, because a probe that has
never reported a deviation is not evidence of containment.
"""

from __future__ import annotations

import json

import pytest

from trustlens.sandbox import conformance, probes
from trustlens.evidence.status import Status


# --------------------------------------------------------------------- grading lattice

def test_all_conforming_grades_to_the_weakest_state():
    """All-green conformance is NOT_FOUND_WITHIN_ANALYSED_SCOPE — the weakest of the five.

    This asymmetry is the point: passing the suite bounds the probed scope and nothing beyond.
    """
    results = [{"verdict": probes.CONFORMS} for _ in range(12)]
    assert conformance.grade(results) is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE


def test_a_single_deviation_grades_to_found():
    """One containment gap fails the whole suite, and it is FOUND — a positive finding."""
    results = [{"verdict": probes.CONFORMS}] * 11 + [{"verdict": probes.DEVIATES}]
    assert conformance.grade(results) is Status.FOUND


def test_an_inconclusive_probe_makes_the_run_partial():
    """A probe that could not complete did not finish looking; the run is PARTIAL, not clean."""
    results = [{"verdict": probes.CONFORMS}] * 11 + [{"verdict": probes.INCONCLUSIVE}]
    assert conformance.grade(results) is Status.PARTIAL


def test_deviation_outranks_inconclusive():
    """A real gap dominates an unfinished probe: FOUND beats PARTIAL in the lattice."""
    results = [
        {"verdict": probes.DEVIATES},
        {"verdict": probes.INCONCLUSIVE},
        {"verdict": probes.CONFORMS},
    ]
    assert conformance.grade(results) is Status.FOUND


def test_an_unrecognised_verdict_is_not_a_pass():
    """Defensive: a garbled verdict must not grade as clean."""
    results = [{"verdict": "SOMETHING_ELSE"}]
    assert conformance.grade(results) is Status.UNKNOWN


# ------------------------------------------------------------- never silent on unreadable

def test_parse_results_raises_when_the_marker_is_absent():
    """A run whose results cannot be read is a failure to observe, never empty-and-clean."""
    with pytest.raises(ValueError, match="did not run to completion"):
        conformance.parse_results("some unrelated output\nno marker here\n")


def test_parse_results_reads_a_valid_line():
    payload = [{"probe_id": "x", "verdict": probes.CONFORMS}]
    stdout = f"noise\n{conformance.RESULT_MARKER}{json.dumps(payload)}\nmore noise\n"
    assert conformance.parse_results(stdout) == payload


# ------------------------------------------------- the probes can detect absent containment

def test_negative_control_env_sanitisation_deviates_when_uncontained():
    """Run the env probe in THIS (uncontained) process: it must report a deviation.

    The pytest process carries far more than the PATH/HOME/LANG allowlist, so a probe that
    genuinely inspects the environment must fire here. If this ever passes as CONFORMS, the
    probe has stopped looking — which is exactly the failure mode a conformance suite must not
    have.
    """
    result = probes.probe_environment_sanitisation()
    assert result["verdict"] == probes.DEVIATES, (
        "the environment-sanitisation probe did not fire in an uncontained process, where "
        "the environment plainly exceeds the allowlist — it cannot detect a real leak"
    )


def test_negative_control_suite_as_a_whole_detects_no_containment():
    """The whole suite, run uncontained, must surface at least one deviation."""
    results = probes.run_all()
    assert len(results) == len(probes.PROBES)
    assert any(r["verdict"] == probes.DEVIATES for r in results), (
        "run uncontained, not a single probe deviated — the suite cannot detect the absence "
        "of a sandbox"
    )


def test_outbound_probe_deviates_on_a_successful_connection(monkeypatch):
    """Positive control for the network probe, without needing real network.

    Simulate an unblocked connection and confirm the probe classifies it as a deviation.
    """
    monkeypatch.setattr(probes, "_connect_blocked", lambda *a, **k: (False, "connected"))
    assert probes.probe_blocked_outbound()["verdict"] == probes.DEVIATES
    assert probes.probe_cloud_metadata()["verdict"] == probes.DEVIATES


def test_dns_probe_conforms_only_when_resolution_fails(monkeypatch):
    def _raise(*a, **k):
        raise OSError("Name or service not known")

    monkeypatch.setattr(probes.socket, "getaddrinfo", _raise)
    assert probes.probe_dns_policy()["verdict"] == probes.CONFORMS


def test_mount_probe_deviates_on_an_unexpected_mount(monkeypatch):
    """A host bind mount appearing in the table is the GHSA-7fhf-v3p3-rp56 shape, observed."""
    fake = (
        "/proc/self/mountinfo",
        "1 1 0:1 / / rw - rootfs rootfs rw\n"
        "2 1 0:2 / /proc rw - proc proc rw\n"
        "3 1 0:3 / /host-secrets rw - bind /host/secrets rw\n",   # the deviation
    )
    monkeypatch.setattr(probes, "_read_mounts", lambda: fake)
    result = probes.probe_mount_isolation()
    assert result["verdict"] == probes.DEVIATES
    assert "/host-secrets" in result["observed"]


def test_mount_probe_conforms_on_the_expected_set(monkeypatch):
    fake = (
        "/proc/self/mountinfo",
        "1 1 0:1 / / rw - rootfs rootfs rw\n"
        "2 1 0:2 / /proc rw - proc proc rw\n"
        "3 1 0:3 / /tmp rw - tmpfs tmpfs rw\n"
        "4 1 0:4 / /artifact ro - bind /artifact ro\n",
    )
    monkeypatch.setattr(probes, "_read_mounts", lambda: fake)
    assert probes.probe_mount_isolation()["verdict"] == probes.CONFORMS


def test_privilege_probe_deviates_when_a_privileged_syscall_succeeds(monkeypatch):
    """If mknod (which needs CAP_MKNOD) succeeds, that is a real capability leak → DEVIATES.

    Simulates the syscall succeeding, without actually creating a device node, so the positive
    control does not depend on the test runner's own privilege.
    """
    monkeypatch.setattr(probes.os, "mknod", lambda *a, **k: None)
    monkeypatch.setattr(probes.os, "unlink", lambda *a, **k: None)
    assert probes.probe_privilege_confinement()["verdict"] == probes.DEVIATES


def test_privilege_probe_conforms_when_the_privileged_syscall_is_refused(monkeypatch):
    """The clean case: a confined sandbox denies mknod with EPERM → CONFORMS, no false alarm.

    This is the regression guard for the false positive found against real gVisor: a
    correctly-contained sandbox must not be flagged.
    """
    def _deny(*a, **k):
        raise PermissionError(13, "Operation not permitted")

    monkeypatch.setattr(probes.os, "mknod", _deny)
    assert probes.probe_privilege_confinement()["verdict"] == probes.CONFORMS


# --------------------------------------------------- probe/launch consistency

def test_probe_expectations_match_the_launch_configuration():
    """The env-allowlist the probe checks must equal the profile's, or the probe lies.

    If `probes.EXPECTED_ENV_NAMES` drifts from the conformance profile's allowlist, the
    env-sanitisation probe would flag legitimate variables or miss real leaks. This ties them.
    """
    profile = conformance.conformance_profile()
    assert set(profile.environment_allowlist) == probes.EXPECTED_ENV_NAMES


def test_every_probe_returns_a_wellformed_result():
    """Structural: each probe result carries the fields the harness and record depend on."""
    required = {"probe_id", "category", "attempted", "expectation", "observed", "verdict"}
    for result in probes.run_all():
        assert required <= set(result), f"probe result missing fields: {result}"
        assert result["verdict"] in (probes.CONFORMS, probes.DEVIATES, probes.INCONCLUSIVE)


def test_the_suite_covers_the_full_phase3_probe_list():
    """All twelve spec categories are present, so none is silently dropped."""
    categories = {p()["category"] for p in probes.PROBES}
    expected = {
        "host_filesystem_read", "host_filesystem_write", "host_pid_visibility",
        "signal_host_process", "privilege_escalation", "blocked_outbound_connection",
        "cloud_metadata_access", "device_access", "resource_limit_enforcement",
        "dns_policy", "mount_isolation", "environment_sanitisation",
    }
    assert categories == expected, f"probe list drifted from the spec: {categories ^ expected}"
