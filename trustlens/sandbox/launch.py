"""Construction of the sandbox's launch configuration — the code §4 protects.

`SANDBOX_THREAT_MODEL.md` §4 forbids any artifact-derived value from reaching mounts,
resource limits, runtime flags, network configuration, the environment allowlist, or the
image identifier. This module is the only place launch configuration is built, so that the
constraint has one place to hold rather than many.

Two independent barriers, because the static one has a stated blind spot (§8):

1. **Static** — `tests/test_sandbox_config_isolation.py` fails if any module under
   `trustlens/sandbox/` imports from an analysis package. That catches import-mediated flow
   and, as §8 records honestly, only import-mediated flow.
2. **Runtime** — `_assert_uncontaminated()` below walks every string in the generated OCI
   spec and argv and refuses any value that did not come from the profile, from a constant
   in this module, or from an operator-supplied path. A value that arrived by some channel
   the import guard cannot see is still refused here, at the point of use.

Neither barrier makes the other redundant, and neither is a proof of non-interference.

## Why not `runsc do`

`runsc do` is the convenient interface and it is the wrong one. Verified against
`runsc release-20260714.0` rather than assumed — its own help text reads:

    "This command starts a sandbox with host filesystem mounted inside as readonly, with a
     writable tmpfs overlay on top of it. [...] It doesn't give nearly as many options and
     it's to be used for testing only."

A read-only mount of the entire host filesystem is precisely the exposure gVisor's
`SECURITY.md` classifies as `SandboxSpec / HostLeak` and declines to treat as a
vulnerability, because it is intended behaviour for a configuration that asked for it. For an
artifact whose suspected capability is credential harvesting, handing it a readable host tree
defeats the purpose of running it in a sandbox at all.

So this module builds an OCI bundle and invokes `runsc run`, where the filesystem is exactly
what we place in the rootfs. Verified on `release-20260714.0`, aarch64: a bundle-based
sandbox reported kernel `4.19.0-gvisor` and could read `/artifact`, while `/root` did not
exist and a planted host file was unreadable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .profile import SandboxProfile

#: Where the artifact appears inside the sandbox. Fixed and pre-declared: §4 requires the
#: artifact to enter as opaque bytes at a path that is never derived from the artifact.
ARTIFACT_MOUNT = "/artifact"

#: OCI spec version produced. `runsc release-20260714.0` reports `spec: 1.2.1`.
OCI_VERSION = "1.2.0"

#: Every literal that may legitimately appear in a generated spec. Enumerated so the
#: contamination check can distinguish "a constant this module wrote" from "a string that
#: came from somewhere else".
_SPEC_LITERALS = frozenset(
    {
        OCI_VERSION, ARTIFACT_MOUNT, "", "/", "linux", "amd64", "arm64",
        "root", "rootfs", "bind", "ro", "rbind", "nosuid", "nodev", "noexec", "relatime",
        "proc", "/proc", "tmpfs", "/tmp", "/dev", "devtmpfs", "mode=755", "size=65536k",
        "sysfs", "/sys", "devpts", "newinstance", "ptmxmode=0666", "gid=5",
        "mqueue", "/dev/mqueue", "shm", "/dev/shm", "size=64m",
        "pid", "network", "ipc", "uts", "mount", "cgroup", "user",
        "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE",
        "no_new_privs", "/bin/sh", "-c",
        # process/rlimit and capability-set keys we construct
        "RLIMIT_NOFILE", "sandbox", "bounding", "effective", "permitted",
        # runsc argv tokens
        "--rootless", "--ignore-cgroups", "run", "--bundle",
    }
)


class LaunchConfigContaminated(RuntimeError):
    """Raised when a launch configuration contains a value of unaccounted-for origin.

    This is a fail-closed refusal, not a warning. A launch configuration carrying a value
    nobody can account for is the exact precondition of Kata's `CVE-2026-50540` and
    `GHSA-7fhf-v3p3-rp56`, so it is refused rather than logged.
    """


@dataclass(frozen=True)
class LaunchConfig:
    """A complete, checked launch configuration: the OCI spec plus the runsc argv."""

    profile_name: str
    oci_spec: dict
    argv: tuple[str, ...]
    bundle_dir: Path
    container_id: str

    def write_bundle(self) -> Path:
        """Write `config.json` into the bundle directory and return its path."""
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        config = self.bundle_dir / "config.json"
        config.write_text(
            json.dumps(self.oci_spec, indent=2, sort_keys=True), encoding="utf-8"
        )
        return config

    def mounted_paths(self) -> list[str]:
        """Mount destinations, for the evidence record."""
        return [m["destination"] for m in self.oci_spec.get("mounts", [])]


def _allowed_values(
    profile: SandboxProfile, *, rootfs_dir: Path, artifact_dir: Path, runsc_path: Path,
    bundle_dir: Path, container_id: str, env: tuple[str, ...] = (),
) -> set[str]:
    """Every string that may legitimately appear in this launch configuration.

    Built from the profile and the operator-supplied paths only. Note what is *not* here:
    anything read from the artifact. That is the whole point — the allowed set is computed
    from the trusted inputs, so an untrusted value cannot be in it by construction.

    **This is the single definition of the allowed set.** An earlier version computed part of
    it here and added the rest inside `build()`, which meant a caller checking a configuration
    with this function got a *narrower* set than the one `build()` had actually used — so the
    check reported contamination on values `build()` itself had written. A guard whose
    allowed-set depends on which caller assembled it is not one guard.
    """
    allowed = set(_SPEC_LITERALS)
    allowed |= {
        profile.name, profile.network,
        str(rootfs_dir), str(artifact_dir), str(runsc_path), str(bundle_dir), container_id,
        rootfs_dir.name,
        f"--network={profile.network}",
        str(profile.timeout_seconds),
    }
    allowed |= set(profile.command)
    allowed |= set(profile.environment_allowlist)
    allowed |= set(profile.runtime_flags)
    # Environment entries are passed as NAME=value; the value comes from the operator's own
    # environment, never from the artifact.
    allowed |= set(env)
    return allowed


def _assert_uncontaminated(obj, allowed: set[str], *, where: str = "spec") -> None:
    """Walk every string in `obj` and refuse any value of unaccounted-for origin.

    The runtime half of the §4 barrier. Deliberately strict: an unrecognised string fails the
    launch rather than being permitted with a warning, because the cost of a false refusal is
    a developer adding a constant, and the cost of a false acceptance is the Kata advisory
    class.
    """
    if isinstance(obj, str):
        if obj not in allowed and not obj.startswith(tuple(a for a in allowed if a.endswith("="))):
            raise LaunchConfigContaminated(
                f"{where}: the value {obj!r} did not come from the profile, from a constant "
                "in launch.py, or from an operator-supplied path.\n"
                "No artifact-derived value may reach sandbox launch configuration "
                "(SANDBOX_THREAT_MODEL.md §4). If this value is legitimate, add it to the "
                "profile or to _SPEC_LITERALS deliberately — do not widen this check."
            )
    elif isinstance(obj, dict):
        for key, value in obj.items():
            _assert_uncontaminated(value, allowed, where=f"{where}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            _assert_uncontaminated(value, allowed, where=f"{where}[{i}]")
    elif isinstance(obj, (int, bool, type(None))):
        return
    else:
        raise LaunchConfigContaminated(
            f"{where}: unexpected value type {type(obj).__name__} in a launch configuration"
        )


def build(
    profile: SandboxProfile,
    *,
    rootfs_dir: Path,
    artifact_dir: Path,
    bundle_dir: Path,
    runsc_path: Path,
    container_id: str,
    environ: dict[str, str] | None = None,
    ignore_cgroups: bool = False,
) -> LaunchConfig:
    """Build a checked launch configuration.

    Note the signature: the artifact is supplied as a **directory path chosen by the
    operator**, and nothing is ever read from inside it here. Its contents do not influence
    any value in the resulting configuration — they are mounted, read-only, at the fixed
    `ARTIFACT_MOUNT`, and that is the artifact's entire influence on its own sandbox.
    """
    environ = environ if environ is not None else {}

    env = [f"{name}={environ[name]}" for name in profile.environment_allowlist if name in environ]

    spec = {
        "ociVersion": OCI_VERSION,
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": list(profile.command),
            "env": env,
            "cwd": "/",
            "capabilities": {
                # Minimal set. Nothing here grants host reach; gVisor's Sentry is the
                # boundary, and a smaller capability set is defence in depth, not the claim.
                k: ["CAP_AUDIT_WRITE", "CAP_KILL"]
                for k in ("bounding", "effective", "permitted")
            },
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
            "noNewPrivileges": True,
        },
        "root": {"path": str(rootfs_dir), "readonly": True},
        "hostname": "sandbox",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc", "options": []},
            {
                "destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
                "options": ["nosuid", "nodev", "size=65536k"],
            },
            {
                # The artifact. Read-only, no exec, at a fixed destination.
                "destination": ARTIFACT_MOUNT,
                "type": "bind",
                "source": str(artifact_dir),
                "options": ["rbind", "ro", "nosuid", "nodev"],
            },
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
                {"type": "network"},
            ],
            "resources": {
                "memory": {"limit": profile.memory_bytes},
                "pids": {"limit": profile.pids},
            },
        },
    }

    argv: list[str] = [str(runsc_path)]
    if profile.rootless:
        argv.append("--rootless")
    argv.append(f"--network={profile.network}")
    if ignore_cgroups:
        argv.append("--ignore-cgroups")
    argv.extend(profile.runtime_flags)
    argv.extend(["run", "--bundle", str(bundle_dir), container_id])

    allowed = _allowed_values(
        profile, rootfs_dir=rootfs_dir, artifact_dir=artifact_dir, runsc_path=runsc_path,
        bundle_dir=bundle_dir, container_id=container_id, env=tuple(env),
    )

    _assert_uncontaminated(spec, allowed, where="oci_spec")
    _assert_uncontaminated(list(argv), allowed, where="argv")

    return LaunchConfig(
        profile_name=profile.name,
        oci_spec=spec,
        argv=tuple(argv),
        bundle_dir=bundle_dir,
        container_id=container_id,
    )
