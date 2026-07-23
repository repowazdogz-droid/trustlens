"""Conformance harness — runs the probe payload in the sandbox and grades the result.

Runs OUTSIDE the sandbox. It assembles an operator-controlled rootfs containing a Python
interpreter and `probes.py`, launches it through the same `runsc.run` machinery the artifact
path uses, reads back the structured probe results, and grades them against the five-state
taxonomy.

The grading is deliberately conservative, in the direction the whole project points:

* Any probe `DEVIATES`      → the sandbox **fails** conformance. Reported as `FOUND` (a
                              containment gap was found), because a boundary that let a
                              prohibited operation through is a positive finding, not a clean
                              result.
* Any probe `INCONCLUSIVE`  → the run is `PARTIAL`. A probe that could not complete did not
                              finish looking, and `scope.failed` records it.
* All probes `CONFORMS`     → `NOT_FOUND_WITHIN_ANALYSED_SCOPE`. No gap was found *among these
                              probed classes, in this environment*. This is never rendered as
                              "the sandbox is secure" and never lifts `EXPERIMENTAL`
                              (`SANDBOX_THREAT_MODEL.md` §2.1, §7; and `status.promote()`
                              refuses gVisor regardless).

Note the asymmetry, which is the point: an all-green conformance run is the *weakest* of the
five states, not the strongest. It bounds the probed scope and nothing beyond it.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import probes, runsc
from .profile import SandboxProfile
from ..evidence.status import Status, combine

#: Where probes.py is placed inside the rootfs, and the marker the payload prints.
PROBE_PATH_IN_ROOTFS = "/probes/probes.py"
RESULT_MARKER = "TRUSTLENS_PROBE_RESULTS "


@dataclass
class ConformanceResult:
    """The graded outcome of one conformance run."""

    status: Status
    probe_results: list[dict]
    deviations: list[dict]
    inconclusive: list[dict]
    conforming: list[dict]
    sandbox_block: dict
    raw_stdout: str

    @property
    def passed(self) -> bool:
        """True only when every probe conformed. A single deviation or inconclusive is not a pass."""
        return self.status is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE

    def summary(self) -> str:
        return (
            f"{len(self.conforming)} conform, {len(self.deviations)} DEVIATE, "
            f"{len(self.inconclusive)} inconclusive → {self.status.value}"
        )


def grade(probe_results: list[dict]) -> Status:
    """Map probe verdicts to a single analysis status via the project's precedence lattice.

    Uses `combine()` so the aggregation obeys the same lattice as everything else: a clean
    aggregate is reachable only when every probe is clean.
    """
    per_probe: list[Status] = []
    for result in probe_results:
        verdict = result.get("verdict")
        if verdict == probes.DEVIATES:
            per_probe.append(Status.FOUND)
        elif verdict == probes.INCONCLUSIVE:
            per_probe.append(Status.PARTIAL)
        elif verdict == probes.CONFORMS:
            per_probe.append(Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE)
        else:
            # An unrecognised verdict is not a pass.
            per_probe.append(Status.UNKNOWN)
    return combine(per_probe)


def parse_results(stdout: str) -> list[dict]:
    """Extract the probe result list from sandbox stdout.

    Raises if the marker is absent: a conformance run whose results cannot be read is not a
    pass, it is a failure to observe, and must not be silently treated as empty-and-clean.
    """
    for line in stdout.splitlines():
        if line.startswith(RESULT_MARKER):
            return json.loads(line[len(RESULT_MARKER):])
    raise ValueError(
        "no TRUSTLENS_PROBE_RESULTS line in sandbox output; the probe payload did not run to "
        "completion. This is a failure to observe, not a clean result."
    )


def prepare_rootfs(dest: Path, base_rootfs: Path, *, interpreter: str) -> None:
    """Overlay the probe payload onto a prepared, working base rootfs.

    **The base rootfs must already be a working userland containing the interpreter** named by
    `interpreter`. This function does not synthesise one: an earlier version copied a single
    `python3` binary into a bare directory, which cannot run — a dynamically linked interpreter
    needs its shared libraries, and a rootfs is not a bag of one executable. That defect was
    found by running the suite in real gVisor (docs/COVERAGE_GAPS.md CG-2); the honest contract
    is that the operator supplies a real minimal image (a distroless/slim Python, an exported
    container filesystem) and this function only adds the payload and mount points to it.

    The base rootfs is operator-controlled. Nothing from any artifact is placed in it, and the
    probe payload is copied from this package, not from anything scanned.
    """
    interp = Path(interpreter)
    base_interp = base_rootfs / interp.relative_to(interp.anchor)
    if not base_interp.exists():
        raise FileNotFoundError(
            f"base rootfs {base_rootfs} has no interpreter at {interpreter}. prepare_rootfs "
            "overlays the probe payload onto a working userland; it does not build one. Supply "
            "a base image (distroless/slim Python or an exported container filesystem) that "
            "contains the interpreter."
        )
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(base_rootfs, dest, symlinks=True, ignore_dangling_symlinks=True)
    (dest / "probes").mkdir(parents=True, exist_ok=True)
    for virt in ("proc", "tmp", "artifact"):
        (dest / virt).mkdir(exist_ok=True)
    shutil.copy2(Path(probes.__file__), dest / "probes" / "probes.py")


def conformance_profile(base_timeout: int = 60, *, interpreter: str = "/usr/local/bin/python3") -> SandboxProfile:
    """The profile the conformance suite runs under.

    `--network=none` (signed off) — which is also what several probes test. The command runs
    the probe payload, not any artifact code, and is a fixed argv containing no artifact data.
    The interpreter path is operator/harness configuration (which base image is used), never
    artifact-derived, so supplying it here does not breach §4.
    """
    return SandboxProfile(
        name="conformance",
        timeout_seconds=base_timeout,
        memory_bytes=256 * 1024 * 1024,
        pids=64,
        network="none",
        command=(interpreter, PROBE_PATH_IN_ROOTFS),
        notes=(
            "Runs the conformance probe payload, not artifact code. Every probe is "
            "non-destructive and non-weaponized as written (trustlens/sandbox/probes.py).",
        ),
    )


def run_conformance(
    *,
    rootfs_dir: Path,
    bundle_dir: Path,
    artifact_dir: Path,
    runsc_path: Path | str | None = None,
    container_id: str = "trustlens-conformance",
    ignore_cgroups: bool = False,
    profile: SandboxProfile | None = None,
) -> ConformanceResult:
    """Run the probe suite in the sandbox and grade it.

    The caller supplies an already-assembled rootfs (see `assemble_rootfs`). The environment
    is deliberately empty except what the profile allows, so the env-sanitisation probe has a
    clean baseline.
    """
    profile = profile or conformance_profile()
    run = runsc.run(
        profile,
        artifact_dir=artifact_dir,
        rootfs_dir=rootfs_dir,
        bundle_dir=bundle_dir,
        container_id=container_id,
        runsc_path=runsc_path,
        environ={},                     # nothing from the host environment
        ignore_cgroups=ignore_cgroups,
    )
    block = runsc.sandbox_block(run, profile)

    if not run.completed and run.termination_reason == "timeout":
        # Fail-closed: a timed-out conformance run is PARTIAL, never a pass.
        return ConformanceResult(
            status=Status.PARTIAL, probe_results=[], deviations=[], inconclusive=[],
            conforming=[], sandbox_block=block, raw_stdout=run.stdout,
        )

    results = parse_results(run.stdout)
    status = grade(results)
    return ConformanceResult(
        status=status,
        probe_results=results,
        deviations=[r for r in results if r["verdict"] == probes.DEVIATES],
        inconclusive=[r for r in results if r["verdict"] == probes.INCONCLUSIVE],
        conforming=[r for r in results if r["verdict"] == probes.CONFORMS],
        sandbox_block=block,
        raw_stdout=run.stdout,
    )
