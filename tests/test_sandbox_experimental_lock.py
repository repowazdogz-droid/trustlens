"""The EXPERIMENTAL lock, tested as a lock rather than as a default.

`SANDBOX_THREAT_MODEL.md` §2.1 states that the sandbox may not be promoted to "trusted for
hostile input" while running on gVisor, because gVisor was never signed off for that case.
That sentence is only worth anything if code refuses the promotion, and code only stays
refusing if a test fails when it stops.

The distinction this file exists to hold: `EXPERIMENTAL` being the *current value* is not the
same as `EXPERIMENTAL` being *locked*. A default can be changed by a one-line edit and every
test still passes. So these tests attack the promotion path directly, with a valid review
record and valid approved profiles — the exact inputs a future session would use if it
believed promotion was now permitted.
"""

from __future__ import annotations

import pytest

from trustlens.sandbox import status


VALID_HASH = "a" * 64


def test_gvisor_promotion_is_refused_even_with_a_valid_review_record():
    """The core lock. Everything else about the request is well-formed; the mechanism is not.

    This is the test that must fail if someone relaxes the boundary, so it supplies the
    strongest possible promotion request rather than a malformed one. A test that only ever
    passes bad input cannot tell you whether good input would be refused.
    """
    with pytest.raises(status.PromotionRefused) as exc:
        status.promote(
            mechanism="gvisor",
            review_record_hash=VALID_HASH,
            approved_profiles=("import-only",),
        )
    message = str(exc.value)
    assert "never signed off" in message.lower() or "NOT signed off" in message
    assert "Firecracker" in message, (
        "the refusal must name what would actually be required, or it is a dead end rather "
        "than a redirection"
    )


def test_the_refusal_is_case_insensitive_on_the_mechanism_name():
    """`gVisor`, `GVISOR` and `gvisor` are the same mechanism.

    A case-sensitive check would be bypassable by spelling, which is not a security boundary.
    """
    for spelling in ("gVisor", "GVISOR", "GvIsOr"):
        with pytest.raises(status.PromotionRefused):
            status.promote(
                mechanism=spelling,
                review_record_hash=VALID_HASH,
                approved_profiles=("import-only",),
            )


def test_the_lock_can_actually_pass_for_a_mechanism_that_was_signed_off():
    """Positive control. A lock that refuses everything proves nothing about the lock.

    If `promote()` raised unconditionally, every test above would pass while the function was
    simply broken. So this exercises the success path with a hypothetical mechanism, showing
    the refusal above is specific to gVisor rather than universal.
    """
    result = status.promote(
        mechanism="firecracker",
        review_record_hash=VALID_HASH,
        approved_profiles=("import-only",),
    )
    assert result is status.SandboxStatus.REVIEWED


def test_promotion_still_requires_a_review_record_and_a_profile():
    """The other two refusals, so relaxing the mechanism check alone would not open the gate."""
    with pytest.raises(status.PromotionRefused):
        status.promote(mechanism="firecracker", review_record_hash=None,
                       approved_profiles=("p",))
    with pytest.raises(status.PromotionRefused):
        status.promote(mechanism="firecracker", review_record_hash="not-a-hash",
                       approved_profiles=("p",))
    with pytest.raises(status.PromotionRefused):
        status.promote(mechanism="firecracker", review_record_hash=VALID_HASH,
                       approved_profiles=())


def test_current_status_is_experimental():
    assert status.current_status() is status.SandboxStatus.EXPERIMENTAL


def test_sandbox_status_refuses_string_comparison():
    """Same reasoning as `Status`: a silent False here is the 'treat as reviewed' branch."""
    with pytest.raises(TypeError):
        _ = status.current_status() == "EXPERIMENTAL"


def test_no_code_path_produces_a_reviewed_record_for_gvisor():
    """The record-building path, not just the enum.

    `sandbox_block()` could in principle hardcode a status independently of `promote()`. It
    is checked here against the real profile so the two cannot drift apart.
    """
    from trustlens.sandbox import profile as profile_mod
    from trustlens.sandbox import runsc

    prof = profile_mod.get("inert-probe")
    fake = runsc.SandboxRun(
        completed=True, termination_reason="completed", exit_code=0,
        stdout="4.19.0-gvisor\n", stderr="", launch_config=_stub_config(prof),
        isolation_version="release-20260714.0", isolation_hash="b" * 64,
    )
    block = runsc.sandbox_block(fake, prof)
    assert block["sandbox_status"] == "EXPERIMENTAL"
    assert block["security_review_complete"] is False
    assert block["review_record_hash"] is None
    assert block["approved_profiles"] == []
    assert block["banner"] == status.BANNER


def test_the_recorded_command_round_trips_to_the_argv_that_ran():
    """The `command` field must reconstruct the exact argv, not a lossy space-join.

    Caught by eye in the first end-to-end run: a profile command of
    ('/bin/sh', '-c', 'uname -r; id -u') serialised as '/bin/sh -c uname -r; id -u', which
    reads as two shell statements rather than one -c argument. An evidence record that cannot
    round-trip to what ran is not evidence of what ran.
    """
    import shlex

    from trustlens.sandbox import profile as profile_mod
    from trustlens.sandbox import runsc

    prof = profile_mod.get("inert-probe")
    fake = runsc.SandboxRun(
        completed=True, termination_reason="completed", exit_code=0,
        stdout="4.19.0-gvisor\n", stderr="", launch_config=_stub_config(prof),
        isolation_version="release-20260714.0", isolation_hash="b" * 64,
    )
    recorded = runsc.sandbox_block(fake, prof)["command"]
    assert tuple(shlex.split(recorded)) == prof.command, (
        f"recorded command {recorded!r} does not round-trip to argv {prof.command!r}"
    )


def test_the_residual_uncertainty_states_the_kernel_exploitation_limit():
    """A clean run must never read as a clean bill of health."""
    text = status.residual_uncertainty()
    assert "NOT signed off" in text
    assert "kernel" in text.lower()
    assert "does not establish that the artifact is safe" in text.lower()


def _stub_config(prof):
    from pathlib import Path

    from trustlens.sandbox import launch

    return launch.LaunchConfig(
        profile_name=prof.name,
        oci_spec={"mounts": [{"destination": "/artifact"}]},
        argv=("runsc", "run", "x"),
        bundle_dir=Path("/tmp/bundle"),
        container_id="x",
    )
