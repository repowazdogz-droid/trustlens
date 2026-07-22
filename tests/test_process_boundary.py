"""Which modules may spawn a process, enforced as an allowlist.

Written **before** Phase 3 exists, deliberately. Phase 3 is the first component whose whole
purpose is to execute untrusted code, and it is the highest-risk thing in this project. The
guard against it being reachable from an analysis path should be in place before the code
it guards, not added afterwards when there is already something to grandfather in.

The rule: exactly one module per spawning capability, each named here with a reason. A new
module that imports `subprocess` fails this test until someone adds it to the allowlist,
which forces the decision to be made explicitly rather than discovered later.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "trustlens"

#: Modules permitted to spawn a process, each with the reason it is allowed.
#:
#: `sandbox` is listed with `allowed=False` on purpose: Phase 3 has not been built, and
#: until its isolation-mechanism review, threat model and human sign-off are complete it may
#: not exist. If a sandbox module appears before then, this test fails — which is the point.
SPAWN_ALLOWLIST: dict[str, str] = {
    "scanner/acquire.py": (
        "remote acquisition; explicitly initiated, never reachable from scan()"
    ),
    "mapper/rbac_helper.py": (
        "optional Go RBAC helper; explicitly initiated, never reachable from "
        "map-credentials()"
    ),
}

#: Paths that must never spawn, and must never import anything that does. These are the
#: analysis paths a user runs against untrusted input.
CORE_ANALYSIS_MODULES = (
    "scanner/assemble.py",
    "scanner/report.py",
    "scanner/pysource.py",
    "scanner/config_parse.py",
    "mapper/assemble.py",
    "mapper/model.py",
    "mapper/terraform.py",
    "mapper/rbac.py",
)

SPAWNING_IMPORTS = {"subprocess", "os.system", "pty", "multiprocessing"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _python_modules() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def test_only_allowlisted_modules_import_subprocess():
    """A new spawning module must be added to the allowlist with a reason, deliberately."""
    offenders = {}
    for path in _python_modules():
        rel = str(path.relative_to(PACKAGE))
        if "subprocess" in _imports(path) and rel not in SPAWN_ALLOWLIST:
            offenders[rel] = sorted(_imports(path) & SPAWNING_IMPORTS)
    assert not offenders, (
        f"module(s) import subprocess without being on the allowlist: {offenders}. "
        "Add an entry to SPAWN_ALLOWLIST with the reason it is permitted, so the decision "
        "is explicit rather than discovered later."
    )


def test_allowlist_has_no_stale_entries():
    for rel in SPAWN_ALLOWLIST:
        assert (PACKAGE / rel).is_file(), f"allowlist names a module that does not exist: {rel}"


def test_core_analysis_modules_never_import_a_spawning_module():
    """The paths a user points at untrusted input must not be able to spawn anything."""
    forbidden = {"subprocess", "pty", "multiprocessing"}
    for rel in CORE_ANALYSIS_MODULES:
        path = PACKAGE / rel
        if not path.is_file():
            continue
        found = _imports(path) & forbidden
        assert not found, f"{rel} imports {sorted(found)}; it is a core analysis path"


def test_core_analysis_modules_never_import_the_spawning_modules_either():
    """Indirect reach is still reach."""
    banned_names = {"acquire", "rbac_helper", "sandbox"}
    for rel in CORE_ANALYSIS_MODULES:
        path = PACKAGE / rel
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                leaf = node.module.rsplit(".", 1)[-1]
                assert leaf not in banned_names, f"{rel} imports {node.module}"
                for alias in node.names:
                    assert alias.name not in banned_names, (
                        f"{rel} imports {alias.name} from {node.module}"
                    )


# ----------------------------------------------------- the Phase 3 guard, ahead of time

def test_no_sandbox_module_exists_yet():
    """Phase 3 is gated on three things, none of which the agent can self-certify.

    An isolation-mechanism review, a written threat model, and Warren's own sign-off on the
    conformance-probe suite. Until all three are in place, sandbox execution code must not
    exist. This test is the mechanical form of that gate: it fails the moment such a module
    appears, so the gate cannot be passed by simply starting to write code.
    """
    sandbox_modules = [
        str(p.relative_to(PACKAGE))
        for p in _python_modules()
        if "sandbox" in p.stem.lower() or "sandbox" in str(p.parent.name).lower()
    ]
    assert not sandbox_modules, (
        f"sandbox module(s) present: {sandbox_modules}. Phase 3 is gated on an "
        "isolation-mechanism review, a written threat model, and Warren's human sign-off "
        "on the conformance-probe suite. If those are complete, remove this test in the "
        "same commit that records them — deliberately, not incidentally."
    )


#: The only states SANDBOX_THREAT_MODEL.md may declare. `SIGNED OFF` is a claim about a
#: human action; nothing in this repository may set it, and no test may infer it.
THREAT_MODEL_STATES = (
    "NOT WRITTEN",
    "DRAFT — AWAITING SIGN-OFF",
    "SIGNED OFF",
)


def test_sandbox_threat_model_declares_exactly_one_known_state():
    """The document must say which of three states it is in, on a parseable line.

    Corrects a real defect in the first version of this test, which asserted
    `"NOT WRITTEN" in doc or "REVIEWED" in doc` over the whole file. That passed for the
    wrong reason: the placeholder happened to contain the word "REVIEWED" in an unrelated
    sentence about schema enforcement, so the second branch was satisfied by prose rather
    than by any recorded review. A substring search over a whole document is not a state
    check.

    It was also wrongly binary. A drafted-but-unapproved threat model is a legitimate third
    state, not the "ambiguous middle" the old test forbade — the ambiguity it was really
    guarding against is a document that does not say where it stands. So the fix is to
    require an explicit status line, not to forbid the state.
    """
    doc = (PACKAGE.parent / "SANDBOX_THREAT_MODEL.md").read_text(encoding="utf-8")
    status_lines = [ln for ln in doc.splitlines() if ln.startswith("## Status:")]
    assert len(status_lines) == 1, (
        f"expected exactly one '## Status:' line, found {len(status_lines)}: {status_lines}"
    )
    declared = status_lines[0].removeprefix("## Status:").strip()
    assert any(declared.startswith(s) for s in THREAT_MODEL_STATES), (
        f"threat model declares an unrecognised state {declared!r}; it must be one of "
        f"{THREAT_MODEL_STATES}"
    )


def test_sign_off_is_not_claimed_while_the_phase_3_gate_still_holds():
    """`SIGNED OFF` may only be set by Warren, never by an implementing session.

    This cannot detect who edited the file. What it can do is refuse the combination that
    would matter: a document claiming sign-off while the rest of the gate is untouched is
    far more likely to be a session that wrote the words than a human who reviewed them.
    """
    doc = (PACKAGE.parent / "SANDBOX_THREAT_MODEL.md").read_text(encoding="utf-8")
    status = next(ln for ln in doc.splitlines() if ln.startswith("## Status:"))
    if not status.removeprefix("## Status:").strip().startswith("SIGNED OFF"):
        return
    assert (PACKAGE.parent / "docs" / "SIGN_OFF.md").exists(), (
        "the threat model claims SIGNED OFF but no docs/SIGN_OFF.md records who signed it, "
        "when, and on what. Sign-off is a human act with a record, not a status string."
    )
