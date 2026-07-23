"""Execution of a built launch configuration via gVisor's `runsc`.

The only module in this package that spawns a process. Listed in the `SPAWN_ALLOWLIST` of
`tests/test_process_boundary.py`, deliberately, so that the set of things able to start a
process stays small and reviewed.

Two behaviours inherited from earlier phases, both of which were bugs before they were rules:

* **No silent substitution.** An explicitly supplied `--runsc` path that does not exist is an
  error, never a fall back to one found on `PATH`. This bit twice in Phase 1 and Phase 2
  (`acquire.py` falling back to HEAD, `rbac_helper` falling back to a repo-local build), and
  the same shape here would mean a record naming a binary that was not the one that ran.
* **Fail closed on timeout.** Expiry yields `PARTIAL` with the timeout in `scope.failed`,
  never a clean result. A sandbox that was killed did not finish looking.
"""

from __future__ import annotations

import hashlib
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import launch, status
from .profile import SandboxProfile


class RunscUnavailable(RuntimeError):
    """Raised when the isolation binary cannot be located or verified."""


@dataclass
class SandboxRun:
    """The outcome of one execution. Deliberately not a bare (stdout, returncode) tuple."""

    completed: bool
    termination_reason: str
    exit_code: int | None
    stdout: str
    stderr: str
    launch_config: launch.LaunchConfig
    isolation_version: str
    isolation_hash: str
    failed: list[dict] = field(default_factory=list)

    @property
    def observed_kernel(self) -> str | None:
        """The kernel the sandboxed process reported, when the profile asked for it.

        This is how the boundary is demonstrated rather than asserted: a gVisor sandbox
        reports its own Sentry kernel (`4.19.0-gvisor`), not the host's.
        """
        for line in self.stdout.splitlines():
            if "gvisor" in line.lower():
                return line.strip()
        return None


def resolve_binary(explicit: Path | str | None = None) -> Path:
    """Locate `runsc`. An explicit path that does not exist is an error, not a fallback."""
    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            raise RunscUnavailable(
                f"the runsc binary explicitly supplied at {path} does not exist. "
                "Refusing to fall back to a different binary: the evidence record names the "
                "isolation binary that ran, and silently substituting one would make that "
                "record wrong."
            )
        return path
    found = shutil.which("runsc")
    if not found:
        raise RunscUnavailable(
            "runsc was not found on PATH. gVisor requires Linux; on macOS this package can "
            "build and check launch configurations but cannot execute them "
            "(docs/PHASE3_PLATFORM_CONSTRAINT.md)."
        )
    return Path(found)


def binary_identity(runsc_path: Path) -> tuple[str, str]:
    """Return `(version, sha256)` for the isolation binary.

    Both go into the record. A containment claim about an unpinned, unhashed binary is not a
    claim about anything (`SANDBOX_THREAT_MODEL.md` §3).
    """
    digest = hashlib.sha256(runsc_path.read_bytes()).hexdigest()
    try:
        proc = subprocess.run(
            [str(runsc_path), "--version"], capture_output=True, text=True, timeout=30,
        )
        version = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else "unknown"
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunscUnavailable(f"could not execute {runsc_path}: {exc}") from exc
    return version, digest


def run(
    profile: SandboxProfile,
    *,
    artifact_dir: Path,
    rootfs_dir: Path,
    bundle_dir: Path,
    container_id: str,
    runsc_path: Path | str | None = None,
    environ: dict[str, str] | None = None,
    ignore_cgroups: bool = False,
) -> SandboxRun:
    """Build a launch configuration, then execute it.

    The build step is not optional and not bypassable: `launch.build()` runs its
    contamination check before any process is started, so a contaminated configuration fails
    before `runsc` is invoked rather than after.
    """
    binary = resolve_binary(runsc_path)
    version, digest = binary_identity(binary)

    if not profile.network_is_signed_off:
        # §6: needing network is a re-review trigger, not a configuration change. Refusing
        # rather than warning, because a warning in a log is not a gate.
        raise RunscUnavailable(
            f"profile {profile.name!r} requests network mode {profile.network!r}. Only "
            "--network=none was signed off (docs/SIGN_OFF.md SO-1). Enabling network removes "
            "rootless mode and changes the privilege model, which SANDBOX_THREAT_MODEL.md §6 "
            "records as a re-review trigger."
        )

    config = launch.build(
        profile,
        rootfs_dir=rootfs_dir,
        artifact_dir=artifact_dir,
        bundle_dir=bundle_dir,
        runsc_path=binary,
        container_id=container_id,
        environ=environ,
        ignore_cgroups=ignore_cgroups,
    )
    config.write_bundle()

    failed: list[dict] = []
    try:
        proc = subprocess.run(
            list(config.argv),
            capture_output=True,
            text=True,
            timeout=profile.timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        # Fail closed. A killed sandbox did not finish looking, and the record must say so.
        failed.append(
            {
                "path": str(artifact_dir),
                "kind": "timeout",
                "reason": (
                    f"the sandbox exceeded the profile timeout of {profile.timeout_seconds}s "
                    "and was terminated. Observation is incomplete: this is PARTIAL, not a "
                    "clean result."
                ),
            }
        )
        return SandboxRun(
            completed=False,
            termination_reason="timeout",
            exit_code=None,
            stdout=(exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            launch_config=config,
            isolation_version=version,
            isolation_hash=digest,
            failed=failed,
        )
    except OSError as exc:
        raise RunscUnavailable(f"could not start {binary}: {exc}") from exc
    finally:
        subprocess.run(
            [str(binary), "delete", "--force", container_id],
            capture_output=True, text=True, timeout=60, check=False,
        )

    if proc.returncode != 0:
        failed.append(
            {
                "path": str(artifact_dir),
                "kind": "nonzero_exit",
                "reason": f"the sandboxed command exited {proc.returncode}: "
                          f"{proc.stderr.strip()[:200]}",
            }
        )

    return SandboxRun(
        completed=proc.returncode == 0,
        termination_reason="completed" if proc.returncode == 0 else "error",
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        launch_config=config,
        isolation_version=version,
        isolation_hash=digest,
        failed=failed,
    )


def sandbox_block(run_result: SandboxRun, profile: SandboxProfile) -> dict:
    """The `sandbox` block of an evidence record, built from what actually ran.

    `sandbox_status` is `EXPERIMENTAL` and cannot be otherwise: `status.promote()` refuses
    gVisor unconditionally, so there is no code path that produces `REVIEWED` here.
    """
    return {
        "sandbox_status": status.current_status().value,
        "security_review_complete": False,
        "review_record_hash": None,
        "approved_profiles": [],
        "profile_used": profile.name,
        "isolation_mechanism": status.ISOLATION_MECHANISM,
        "isolation_version": run_result.isolation_version,
        "image_or_vm_hash": run_result.isolation_hash,
        "host_kernel": run_result.observed_kernel or "unset",
        "policy_hashes": {},
        "network_rules": [f"gvisor --network={profile.network}"],
        "environment_allowlist": list(profile.environment_allowlist),
        "mounted_paths": run_result.launch_config.mounted_paths(),
        "resource_limits": profile.resource_limits(),
        "timeout_seconds": profile.timeout_seconds,
        # `shlex.join`, not `" ".join`: the command is an argv, and a plain-space join is
        # lossy — "/bin/sh -c uname -r; id -u" reads as two shell statements when it was one
        # -c argument. shlex.join quotes each element so the record round-trips to the exact
        # argv that ran, which is the point of an evidence record.
        "command": shlex.join(profile.command),
        "termination_reason": run_result.termination_reason,
        "banner": status.BANNER,
    }
