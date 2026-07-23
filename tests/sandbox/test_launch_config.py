"""The runtime half of the §4 barrier: no artifact-derived value reaches launch config.

`tests/test_sandbox_config_isolation.py` holds the static half (no analysis-package imports
under `trustlens/sandbox/`). That guard is honestly scoped in `SANDBOX_THREAT_MODEL.md` §8 as
catching import-mediated flow and **not** proving non-interference.

This file tests the second, independent barrier: `launch.build()` refuses any value in the
generated OCI spec or argv that did not come from the profile, from a constant in `launch.py`,
or from an operator-supplied path. A value that arrived through a channel the import guard
cannot see is still refused, at the point of use.

The attack these tests simulate is the Kata advisory class, ported to this codebase: an
artifact whose *own contents* influence its sandbox — `GHSA-7fhf-v3p3-rp56` (annotation
bind-mounts an arbitrary host path), `CVE-2026-50540` (arbitrary TOML config → host RCE),
`CVE-2026-44210` (virtiofsd argument injection through a default-enabled annotation).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustlens.sandbox import launch, profile as profile_mod


@pytest.fixture
def paths(tmp_path):
    rootfs = tmp_path / "rootfs"
    artifact = tmp_path / "artifact"
    bundle = tmp_path / "bundle"
    for p in (rootfs, artifact, bundle):
        p.mkdir()
    return {"rootfs_dir": rootfs, "artifact_dir": artifact, "bundle_dir": bundle,
            "runsc_path": tmp_path / "runsc", "container_id": "tl-test"}


def test_a_clean_build_succeeds(paths):
    """Negative control. If this failed, every refusal below would be meaningless."""
    config = launch.build(profile_mod.get("inert-probe"), **paths)
    assert config.argv[-3:] == ("--bundle", str(paths["bundle_dir"]), "tl-test")
    assert "--network=none" in config.argv
    assert "--rootless" in config.argv


def test_the_artifact_is_mounted_read_only_at_the_fixed_path(paths):
    """§4: the artifact enters as opaque bytes at a fixed, pre-declared path."""
    config = launch.build(profile_mod.get("inert-probe"), **paths)
    mounts = {m["destination"]: m for m in config.oci_spec["mounts"]}
    assert launch.ARTIFACT_MOUNT in mounts
    artifact_mount = mounts[launch.ARTIFACT_MOUNT]
    assert artifact_mount["source"] == str(paths["artifact_dir"])
    assert "ro" in artifact_mount["options"]
    assert "nosuid" in artifact_mount["options"]
    assert config.oci_spec["root"]["readonly"] is True


def test_no_host_path_other_than_the_artifact_is_mounted(paths):
    """§6: no writable host mount, and no host path mounted by an artifact-derived name."""
    config = launch.build(profile_mod.get("inert-probe"), **paths)
    bind_sources = [
        m["source"] for m in config.oci_spec["mounts"] if m["type"] == "bind"
    ]
    assert bind_sources == [str(paths["artifact_dir"])], (
        f"exactly one bind mount is permitted — the artifact. Found: {bind_sources}"
    )


# --------------------------------------------------------- the guard must be able to fire

def test_an_artifact_supplied_mount_path_is_refused(paths):
    """The `GHSA-7fhf-v3p3-rp56` shape: artifact metadata naming a host path to mount.

    This is the positive control for the runtime guard. A guard that has never fired proves
    nothing, so a real contaminated configuration is constructed and must be refused.
    """
    config = launch.build(profile_mod.get("inert-probe"), **paths)
    contaminated = dict(config.oci_spec)
    contaminated["mounts"] = list(contaminated["mounts"]) + [
        {
            "destination": "/host",
            "type": "bind",
            # As if read from the artifact's own metadata.
            "source": "/etc",
            "options": ["rbind", "ro"],
        }
    ]
    allowed = launch._allowed_values(
        profile_mod.get("inert-probe"),
        rootfs_dir=paths["rootfs_dir"], artifact_dir=paths["artifact_dir"],
        runsc_path=paths["runsc_path"], bundle_dir=paths["bundle_dir"],
        container_id="tl-test",
    )
    with pytest.raises(launch.LaunchConfigContaminated) as exc:
        launch._assert_uncontaminated(contaminated, allowed)
    assert "/etc" in str(exc.value) or "/host" in str(exc.value)


def test_an_artifact_supplied_runtime_flag_is_refused(paths):
    """The `CVE-2026-44210` shape: argument injection into the runtime's own command line."""
    allowed = launch._allowed_values(
        profile_mod.get("inert-probe"),
        rootfs_dir=paths["rootfs_dir"], artifact_dir=paths["artifact_dir"],
        runsc_path=paths["runsc_path"], bundle_dir=paths["bundle_dir"],
        container_id="tl-test",
    )
    argv = ["runsc", "--network=host", "run", "x"]
    with pytest.raises(launch.LaunchConfigContaminated):
        launch._assert_uncontaminated(argv, allowed)


def test_an_artifact_supplied_config_path_is_refused(paths):
    """The `CVE-2026-50540` shape: a workload-specified configuration file on the host."""
    allowed = launch._allowed_values(
        profile_mod.get("inert-probe"),
        rootfs_dir=paths["rootfs_dir"], artifact_dir=paths["artifact_dir"],
        runsc_path=paths["runsc_path"], bundle_dir=paths["bundle_dir"],
        container_id="tl-test",
    )
    with pytest.raises(launch.LaunchConfigContaminated):
        launch._assert_uncontaminated(
            {"config": "/tmp/attacker-supplied.toml"}, allowed
        )


def test_a_contaminated_command_is_refused(paths):
    """A profile command is fixed; a module name read from artifact metadata is not."""
    allowed = launch._allowed_values(
        profile_mod.get("inert-probe"),
        rootfs_dir=paths["rootfs_dir"], artifact_dir=paths["artifact_dir"],
        runsc_path=paths["runsc_path"], bundle_dir=paths["bundle_dir"],
        container_id="tl-test",
    )
    with pytest.raises(launch.LaunchConfigContaminated):
        launch._assert_uncontaminated(
            {"process": {"args": ["/bin/sh", "-c", "import evil_module_from_metadata"]}},
            allowed,
        )


# ------------------------------------------------------------------ profile discipline

def test_profiles_cannot_be_loaded_from_a_file():
    """§4: there is no profile file format, deliberately.

    A loader would be a channel through which a scanned artifact could influence its own
    sandbox — the Kata `CVE-2026-50540` shape exactly.
    """
    assert not hasattr(profile_mod, "load")
    assert not hasattr(profile_mod, "from_file")
    assert not hasattr(profile_mod, "parse")
    with pytest.raises(profile_mod.UnknownProfile):
        profile_mod.get("../../etc/passwd")


def test_profiles_are_frozen():
    """A mutable profile could be adjusted between validation and use."""
    prof = profile_mod.get("inert-probe")
    with pytest.raises(Exception):
        prof.timeout_seconds = 9999


def test_every_registered_profile_uses_the_signed_off_network_mode():
    """Only `--network=none` was signed off (SO-1); §6 makes anything else a re-review."""
    for name, prof in profile_mod.PROFILES.items():
        assert prof.network_is_signed_off, (
            f"profile {name!r} uses network={prof.network!r}, which SO-1 did not approve"
        )


def test_timeout_is_an_integer_for_hash_reproducibility():
    """The canonical record hash rejects floats so hashes reproduce across languages."""
    for prof in profile_mod.PROFILES.values():
        assert isinstance(prof.timeout_seconds, int)
        assert not isinstance(prof.timeout_seconds, bool)
