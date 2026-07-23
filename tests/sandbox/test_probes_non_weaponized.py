"""The probe payload must be non-weaponized AND non-destructive *as written*.

SO-1's second constraint, and the Phase 3 spec's: probes may not contain sandbox-escape
exploits, and must be safe as written, not merely as intended. This file is a structural audit
of `probes.py` — it is not a substitute for Warren's human review (that gate is non-delegable
and separate), but it mechanically forbids the specific dangerous shapes a reviewer would look
for, so that a later edit reintroducing one fails here rather than passing quietly.

The audit is deliberately conservative: it flags patterns that *could* be weaponized or
destructive, and the fix for a false flag is to keep the probe benign, not to widen the audit.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROBES = Path(__file__).resolve().parents[2] / "trustlens" / "sandbox" / "probes.py"
SOURCE = PROBES.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


#: Destructive or host-affecting targets a probe must never name in *executable* code. Writing
#: sysrq-trigger can reboot a host; writing under /proc/sys/kernel reconfigures it; overwriting
#: the runc binary is the CVE-2019-5736 mechanism.
#:
#: `/dev/mem` is deliberately NOT here: the device probe legitimately *opens* it read-only to
#: test that the node is absent or refused, which is a benign access check. The real concern —
#: reading its contents — is guarded separately by
#: `test_device_probe_opens_read_only_and_never_reads_contents`.
#:
#: Checked against executable string constants only, never the module or function docstrings:
#: a docstring that explains which dangerous operations the payload avoids is honest
#: documentation, not a violation, and must not be forbidden.
FORBIDDEN_WRITE_TARGETS = (
    "/proc/sysrq-trigger",
    "/proc/sys/kernel",
    "sysrq",
    "runc",
)


def _executable_string_constants(tree: ast.AST) -> list[str]:
    """Every string literal in `tree` except module/class/function docstrings.

    Docstrings are excluded on purpose: the audit is about what the code *does*, and this
    payload documents what it refuses to do. Flagging that documentation would punish honesty.
    """
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and node.value not in docstrings
    ]

#: Modules/functions that would let a probe execute arbitrary code or an actual exploit
#: payload. A conformance probe attempts benign operations and reports; it never runs a
#: subprocess or compiles code.
FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "exec"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "popen"),
    ("os", "fork"),         # no fork-bomb, even a bounded one
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("ctypes", "CDLL"),     # no raw libc calls to hand-roll a syscall exploit
}

FORBIDDEN_IMPORTS = {"subprocess", "ctypes", "mmap", "fcntl"}


def test_probes_do_not_import_weaponizable_modules():
    """No subprocess, ctypes, mmap or fcntl. A probe needs none of them to observe a boundary."""
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in FORBIDDEN_IMPORTS, (
                    f"probes.py imports {alias.name!r}, which a benign probe does not need and "
                    "which enables weaponization"
                )
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in FORBIDDEN_IMPORTS, (
                f"probes.py imports from {node.module!r}"
            )


def test_probes_do_not_spawn_or_exec():
    """No process spawning and no code execution anywhere in the payload."""
    for node in ast.walk(TREE):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name):
                pair = (value.id, node.func.attr)
                # match on prefix so os.execv, os.execve etc are all caught
                for mod, fn in FORBIDDEN_CALLS:
                    if pair[0] == mod and pair[1].startswith(fn):
                        pytest.fail(f"probes.py calls {mod}.{node.func.attr} — forbidden")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("eval", "exec", "compile", "__import__"), (
                f"probes.py calls {node.func.id}() — forbidden in a probe payload"
            )


def test_probes_never_reference_a_destructive_target_in_executable_code():
    """No sysrq-trigger, kernel-sysctl, or runc overwrite named in executable string literals.

    Docstrings are excluded: the payload's docstring names these targets precisely to state
    that it avoids them, which is documentation to keep, not a violation to punish.
    """
    literals = _executable_string_constants(TREE)
    for target in FORBIDDEN_WRITE_TARGETS:
        offenders = [lit for lit in literals if target in lit]
        assert not offenders, (
            f"probes.py names the dangerous target {target!r} in executable code ({offenders}); "
            "a probe must not touch host control files even as a test"
        )


def test_device_probe_opens_read_only_and_never_reads_contents():
    """The device probe may open device nodes to test access, but must not read their bytes.

    Opening /dev/kvm read-only to observe EPERM is benign; reading /dev/mem's contents is not.
    This checks the source of the device probe specifically.
    """
    func = _function_source("probe_device_access")
    assert "O_RDONLY" in func
    assert "O_WRONLY" not in func and "O_RDWR" not in func, (
        "the device probe must open read-only"
    )
    # It closes the fd; it must not call read() on a device fd.
    assert ".read(" not in func, "the device probe must not read device contents"


def test_signal_probe_uses_only_the_null_signal():
    """os.kill must be called with signal 0, which delivers nothing."""
    func_tree = _function_tree("probe_signal_host_process")
    kills = [
        node for node in ast.walk(func_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "kill"
    ]
    assert kills, "expected the signal probe to call os.kill"
    for call in kills:
        assert len(call.args) >= 2, "os.kill must specify a signal"
        sig = call.args[1]
        assert isinstance(sig, ast.Constant) and sig.value == 0, (
            "the signal probe must use signal 0 (null signal); a non-zero signal could "
            "actually be delivered to a process"
        )


def test_write_probe_targets_only_the_sandbox_not_a_host_control_file():
    """The write probe writes to the read-only rootfs, never to a host-affecting path."""
    func = _function_source("probe_host_filesystem_write")
    for target in FORBIDDEN_WRITE_TARGETS:
        assert target not in func


def _function_tree(name: str) -> ast.AST:
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found in probes.py")


def _function_source(name: str) -> str:
    return ast.get_source_segment(SOURCE, _function_tree(name)) or ""
