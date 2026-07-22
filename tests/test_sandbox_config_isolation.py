"""No artifact-derived data may reach the sandbox's own launch configuration.

This is a structural constraint with a specific evidentiary basis, not a stylistic
preference, and it is written **before** any sandbox code exists so that the code is built
against it rather than audited for it afterwards.

## Why

gVisor's own security policy draws its protection line by *what the attacker controls*, and
draws it below the sandbox configuration. From `google/gvisor` `SECURITY.md` (master,
retrieved 2026-07-22), a CVE is only assigned when:

    "The issue occurs in a context where the attacker does not initially control the
     sandbox configuration."

and its worked example is explicit that the other side of that line is not a defect:

    "An attacker can configure a sandbox to mount an arbitrary directory on the host, then
     read its files from inside the sandbox. Classification: SandboxSpec / HostLeak.
     CVE: No. Exposing host files to the sandbox via configured mounts and the sandbox
     being able to read them is intended behavior."

So a deployment where untrusted input influences mounts, limits or runtime flags is outside
gVisor's protected range **by the project's own definition**, and no amount of correct
gVisor operation compensates.

Kata Containers supplies the empirical demonstration. Three of its four host-compromise
advisories in the twelve months to 2026-07-22 are configuration-injection paths:

* `GHSA-7fhf-v3p3-rp56` — "Untrusted pod annotation bind-mounts any host path into the Kata
  guest, bypassing the operator allowlist" (affects `<= 3.32.0`)
* `CVE-2026-50540` (CVSS 9.1) — "allowing a pod user to specify an arbitrary TOML
  configuration file on the host, leading to host-level RCE" (affects `<= 3.32.0`)
* `CVE-2026-44210` — "VM Escape via virtiofsd Argument Injection through **Default-Enabled**
  Pod Annotations", serving "the entire host root filesystem into the guest VM"

The last one is the sharpest: the dangerous annotation was enabled *by default*. The failure
mode is not exotic; it is what happens when workload-supplied data reaches sandbox
configuration.

## The constraint

**No value derived from a scanned artifact may reach the code that constructs the sandbox's
launch configuration.** "Derived from a scanned artifact" includes, without limit: declared
metadata, dataset/model card contents, filenames and paths inside the artifact,
configuration file contents, any string read during static analysis, and any finding,
evidence excerpt or record field computed from those.

Launch configuration means: mount specifications, resource limits, runtime flags, network
configuration, environment allowlists, and the image or VM identifier.

Sandbox launch configuration is built **only** from operator-supplied profile values, and
the artifact is delivered to the sandbox as opaque bytes at a fixed, pre-declared path.

## How this is enforced

`find_analysis_imports()` below is a static check that fires on any import from the analysis
packages into a sandbox module. `test_the_guard_can_actually_fire` proves it works by
running it against a synthetic violating module — because a guard that has never fired
proves nothing, which is the lesson this project has relearned at every level.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "trustlens"

#: Packages that read untrusted artifacts. Nothing under a sandbox module may import from
#: them, because anything they return is artifact-derived by construction.
ANALYSIS_PACKAGES = ("trustlens.scanner", "trustlens.mapper", "scanner", "mapper")

#: Fields of a sandbox launch configuration. Listed so the constraint names what it covers
#: rather than gesturing at "configuration".
LAUNCH_CONFIG_FIELDS = (
    "mounts",
    "resource_limits",
    "runtime_flags",
    "network",
    "environment_allowlist",
    "image_or_vm",
    "timeout_seconds",
)


def find_analysis_imports(source: str) -> list[str]:
    """Return every import of an analysis package found in `source`.

    Used by the guard below and by its own positive control. Deliberately a plain function
    over source text so it can be pointed at a synthetic violating module to prove it fires.
    """
    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(alias.name.startswith(p) for p in ANALYSIS_PACKAGES):
                    violations.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            # A relative import from a sandbox module reaching up into a sibling analysis
            # package presents as level>0 with a bare module name.
            if any(module.startswith(p) for p in ANALYSIS_PACKAGES):
                violations.append(f"from {module} import ...")
            elif node.level and module in ("scanner", "mapper"):
                violations.append(f"from {'.' * node.level}{module} import ...")
    return violations


def _sandbox_modules() -> list[Path]:
    return [
        p
        for p in PACKAGE.rglob("*.py")
        if "__pycache__" not in p.parts
        and ("sandbox" in p.stem.lower() or "sandbox" in p.parent.name.lower())
    ]


# --------------------------------------------------------- the guard must be able to fire

def test_the_guard_can_actually_fire(tmp_path):
    """Positive control. A guard that has never fired is not evidence of anything.

    This project has found, repeatedly, that a check which cannot fire is indistinguishable
    from one that ran and found nothing. So the checker is pointed at a module that really
    does violate the constraint.
    """
    violating = (
        "from trustlens.scanner.assemble import scan\n"
        "import trustlens.mapper.model\n"
        "def build_launch_config(artifact):\n"
        "    record = scan(artifact)\n"
        "    return {'mounts': record['declared_capabilities']}\n"
    )
    found = find_analysis_imports(violating)
    assert len(found) == 2, f"the guard failed to detect an obvious violation: {found}"
    assert any("trustlens.scanner.assemble" in f for f in found)
    assert any("trustlens.mapper.model" in f for f in found)


def test_the_guard_detects_a_relative_import_violation():
    """Reaching sideways with a relative import is the same violation."""
    violating = "from ..scanner.assemble import scan\nfrom ..mapper import model\n"
    found = find_analysis_imports(violating)
    assert found, "a relative import into an analysis package must be detected"


def test_the_guard_does_not_fire_on_a_compliant_module():
    """Negative control: a sandbox module using only stdlib and its own profile is clean."""
    compliant = (
        "import json\nimport shutil\nfrom dataclasses import dataclass\n"
        "from .profile import SandboxProfile\n"
        "def build_launch_config(profile: SandboxProfile):\n"
        "    return {'mounts': profile.mounts, 'runtime_flags': profile.flags}\n"
    )
    assert find_analysis_imports(compliant) == []


# ------------------------------------------------------------- the constraint itself

def test_no_sandbox_module_imports_an_analysis_package():
    """The live constraint. Vacuous today because no sandbox module exists yet — by design.

    `test_the_guard_can_actually_fire` is what stops this vacuity from being silent: the
    checker is proven to work, so when a sandbox module does appear this assertion has
    teeth on day one.
    """
    modules = _sandbox_modules()
    if not modules:
        pytest.skip(
            "no sandbox module exists yet (Phase 3 is gated on Warren's sign-off). "
            "The checker itself is exercised by test_the_guard_can_actually_fire, so this "
            "constraint is enforceable the moment such a module appears."
        )
    offenders = {}
    for path in modules:
        found = find_analysis_imports(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(PACKAGE))] = found
    assert not offenders, (
        f"sandbox module(s) import an analysis package: {offenders}.\n"
        "No artifact-derived value may reach sandbox launch configuration. gVisor's own "
        "policy places an attacker who controls the sandbox spec OUTSIDE its protected "
        "range, and three of Kata's four host-compromise advisories in the last year were "
        "configuration-injection paths — one through a default-enabled annotation."
    )


def test_the_constraint_is_recorded_where_it_will_be_read():
    """The rule must live in the threat model, not only in a test file.

    Reads the declared status *line* rather than searching the whole document for
    "NOT WRITTEN". The substring form skipped spuriously the moment the threat model was
    drafted, because the drafted document names all three of its possible states in a
    table — so the guard switched itself off at exactly the point it became live. Same
    defect as the one corrected in `test_process_boundary.py`; found by checking whether
    the skip was still honest after the document changed.
    """
    doc = (ROOT / "SANDBOX_THREAT_MODEL.md").read_text(encoding="utf-8")
    status = next(
        (ln for ln in doc.splitlines() if ln.startswith("## Status:")), ""
    ).removeprefix("## Status:").strip()
    if status.startswith("NOT WRITTEN"):
        pytest.skip("threat model not yet drafted; this becomes live when it is")

    assert "sandbox configuration" in doc.lower(), (
        "the threat model must state the constraint in its own words, not delegate it"
    )
    assert "does not initially control" in doc, (
        "the gVisor SECURITY.md precondition is the evidence for the constraint and must "
        "be quoted, so a future reader can check it rather than trust it"
    )
    for advisory in ("GHSA-7fhf-v3p3-rp56", "CVE-2026-50540", "CVE-2026-44210"):
        assert advisory in doc, f"{advisory} is load-bearing evidence and must be cited"


def test_launch_config_fields_are_enumerated_not_gestured_at():
    """The constraint must name what it covers, or it cannot be checked."""
    assert len(LAUNCH_CONFIG_FIELDS) >= 6
    for field in ("mounts", "resource_limits", "runtime_flags", "network"):
        assert field in LAUNCH_CONFIG_FIELDS
