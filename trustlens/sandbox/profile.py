"""Operator-supplied sandbox profiles. The only permitted source of launch configuration.

`SANDBOX_THREAT_MODEL.md` §4: launch configuration is built **only** from operator-supplied
profile values, and the artifact enters as opaque bytes at a fixed, pre-declared path.

That constraint is why profiles are a closed registry of frozen dataclasses defined in this
file rather than anything parsed at run time. There is no profile loader, no profile file
format, and no way to supply a profile by path — because every one of those would be a
channel through which a scanned artifact could influence its own sandbox, which is exactly
the failure mode of Kata's `CVE-2026-50540` (arbitrary TOML config → host RCE) and
`GHSA-7fhf-v3p3-rp56` (annotation-supplied bind mount).

If a new profile is needed, it is added here, in a commit, by a person.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class UnknownProfile(KeyError):
    """Raised when a profile name is not in the closed registry."""


@dataclass(frozen=True)
class SandboxProfile:
    """A complete, immutable sandbox launch profile.

    Frozen because a mutable profile could be adjusted between validation and use, which is
    the shape of a time-of-check/time-of-use bug in exactly the place §4 protects.
    """

    name: str
    #: Wall-clock limit. Integer, not float: the canonical record hash rejects floats so
    #: record hashes stay reproducible across languages.
    timeout_seconds: int
    memory_bytes: int
    pids: int
    #: gVisor network mode. `none` is the signed-off configuration; see `network_is_signed_off`.
    network: str = "none"
    rootless: bool = True
    #: Environment variables passed into the sandbox. Names only — values come from the
    #: operator's environment, never from the artifact.
    environment_allowlist: tuple[str, ...] = ("PATH", "HOME", "LANG")
    #: Extra runsc flags. Fixed strings only; nothing is interpolated into these.
    runtime_flags: tuple[str, ...] = ()
    #: The command run inside the sandbox. A fixed argv, not a shell string, and not
    #: assembled from anything read out of the artifact.
    command: tuple[str, ...] = ("/usr/bin/env", "python3", "-I", "-c", "pass")
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or not isinstance(self.timeout_seconds, int):
            raise ValueError(f"timeout_seconds must be a positive int, got {self.timeout_seconds!r}")
        if self.memory_bytes <= 0 or self.pids <= 0:
            raise ValueError("resource limits must be positive")
        if self.network not in ("none", "host", "sandbox"):
            raise ValueError(f"unknown gVisor network mode {self.network!r}")
        if not self.command:
            raise ValueError("a profile with no command would sandbox nothing")

    @property
    def network_is_signed_off(self) -> bool:
        """`--network=none` is what SO-1 approved.

        §6 of the threat model records that needing network is a **re-review trigger**, not a
        configuration change: it removes rootless mode and changes the privilege model. This
        property exists so a caller can check rather than assume, and so any future profile
        with network gets flagged at the point of use instead of passing quietly.
        """
        return self.network == "none"

    def resource_limits(self) -> dict[str, int]:
        return {"memory_bytes": self.memory_bytes, "pids": self.pids}


#: The closed registry. Adding an entry is a reviewable code change.
PROFILES: dict[str, SandboxProfile] = {
    # The minimal profile: proves the sandbox boundary exists and reports what it is. Runs no
    # artifact code at all, so it is safe to run anywhere, including in the test suite.
    "inert-probe": SandboxProfile(
        name="inert-probe",
        timeout_seconds=30,
        memory_bytes=256 * 1024 * 1024,
        pids=32,
        command=("/bin/sh", "-c", "uname -r; id -u"),
        notes=(
            "Executes no artifact code. Reports the sandbox kernel identity, which is how the "
            "boundary is demonstrated rather than asserted: a gVisor sandbox reports its own "
            "Sentry kernel version, not the host's.",
        ),
    ),
    # Imports the artifact's Python entry point and stops. This is the first profile that runs
    # attacker-controlled code, and it is EXPERIMENTAL-locked like everything else here.
    "import-only": SandboxProfile(
        name="import-only",
        timeout_seconds=60,
        memory_bytes=512 * 1024 * 1024,
        pids=64,
        command=(
            "/usr/bin/env",
            "python3",
            "-I",  # isolated mode: ignore PYTHON* env vars and the user site directory
            "-c",
            # NOTE: this string is a fixed literal. Nothing from the artifact is interpolated
            # into it. The module name is not read from the artifact's metadata — a
            # metadata-supplied module name would be artifact data reaching the command line,
            # which §4 forbids and `LaunchConfig` refuses.
            "import runpy, sys; sys.path.insert(0, '/artifact'); "
            "runpy.run_module('trustlens_entry', run_name='__main__')",
        ),
        notes=(
            "Runs artifact-controlled code. Observes what an import does, which static "
            "analysis of Python cannot decide in general.",
            "Requires the artifact to expose a module named `trustlens_entry`. That name is "
            "fixed by us, not read from the artifact.",
        ),
    ),
}


def get(name: str) -> SandboxProfile:
    """Look up a profile by name. Never constructs one from caller-supplied values."""
    try:
        return PROFILES[name]
    except KeyError:
        raise UnknownProfile(
            f"unknown profile {name!r}; known profiles are {sorted(PROFILES)}. "
            "Profiles are a closed registry defined in trustlens/sandbox/profile.py — "
            "they are not loadable from a file, by design (SANDBOX_THREAT_MODEL.md §4)."
        ) from None
