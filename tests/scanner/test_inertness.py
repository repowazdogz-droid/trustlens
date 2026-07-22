"""Demonstrate that scanning a hostile repository does nothing.

Every other test in this suite is about what TrustLens *reports*. This one is about what
TrustLens *does*, and it is the test whose failure would mean the scanner is itself the
vulnerability. A tool that executes untrusted content while analysing it is worse than no
tool, because it converts inspection into compromise.

The controls here are demonstrations, not assertions:

* A genuinely malicious pickle is constructed whose payload would create an observable
  file. `test_planted_pickle_payload_is_actually_live` **executes it deliberately** to
  prove the payload fires — otherwise the non-execution control below would be vacuous,
  proving only that an inert file stayed inert.
* The scanner is then run over that same payload with `subprocess`, `os.system` and
  `socket` replaced by objects that raise on use. Any attempt to spawn or connect fails
  the test rather than escaping notice.

All payloads only touch files inside pytest's temporary directory and contact nothing.
"""

from __future__ import annotations

import os
import pickle
import socket
import subprocess
from pathlib import Path

import pytest

from trustlens.scanner.checks import python_surface, template_injection


class _Detonator:
    """Its __reduce__ makes pickle.loads run a command. Payload only touches a temp file."""

    def __init__(self, canary: Path) -> None:
        self.canary = canary

    def __reduce__(self):
        return (os.system, (f"touch {self.canary}",))


def build_hostile_repo(root: Path) -> dict[str, Path]:
    """A repository designed to fire if anything imports, loads or renders it."""
    root.mkdir(parents=True, exist_ok=True)
    canaries = {
        "import": root / "CANARY_IMPORTED",
        "pickle": root / "CANARY_UNPICKLED",
        "yaml": root / "CANARY_YAML",
        "setup": root / "CANARY_SETUP",
    }

    # Fires at import time.
    (root / "evil_module.py").write_text(
        "# TrustLens SYNTHETIC UNSAFE FIXTURE - fires on import\n"
        "import os\n"
        f"os.system('touch {canaries['import']}')\n"
        "def loader(x):\n"
        "    return eval(x)\n",
        encoding="utf-8",
    )
    # Fires if setup.py is executed.
    (root / "setup.py").write_text(
        "# TrustLens SYNTHETIC UNSAFE FIXTURE - fires if executed\n"
        "import os\n"
        f"os.system('touch {canaries['setup']}')\n"
        "from setuptools import setup\n"
        "setup(name='hostile')\n",
        encoding="utf-8",
    )
    # Fires if unpickled.
    (root / "payload.pkl").write_bytes(pickle.dumps(_Detonator(canaries["pickle"])))
    # Fires if loaded with a constructing YAML loader.
    (root / "config.yaml").write_text(
        "# TrustLens SYNTHETIC UNSAFE FIXTURE - fires on unsafe yaml.load\n"
        f"boom: !!python/object/apply:os.system ['touch {canaries['yaml']}']\n",
        encoding="utf-8",
    )
    return canaries


# ------------------------------------------------------- the planted cases must be live

def test_planted_pickle_payload_is_actually_live(tmp_path):
    """Prove the payload fires, so the non-execution control below is not vacuous.

    This test DELIBERATELY executes the malicious pickle. The payload is `touch` against a
    path inside pytest's tmp_path and contacts nothing. Without this, a passing
    non-execution test would be indistinguishable from testing an inert file.
    """
    canary = tmp_path / "PROOF_PAYLOAD_LIVE"
    blob = pickle.dumps(_Detonator(canary))
    assert not canary.exists()

    pickle.loads(blob)  # deliberate detonation of a payload we constructed

    assert canary.exists(), (
        "the planted pickle payload did not fire, so any non-execution result proves nothing"
    )


def test_planted_yaml_payload_is_actually_live(tmp_path):
    """Same argument for the YAML tag: prove an unsafe loader would fire."""
    import yaml

    canary = tmp_path / "PROOF_YAML_LIVE"
    doc = f"boom: !!python/object/apply:os.system ['touch {canary}']\n"
    assert not canary.exists()

    yaml.unsafe_load(doc)  # deliberate detonation under a constructing loader

    assert canary.exists(), "the planted YAML payload did not fire; the control would be vacuous"


# ------------------------------------------------------------- scanning must be inert

@pytest.fixture
def hostile_repo(tmp_path):
    """Build the hostile repository.

    Requested *before* `no_execution` in every test signature, because constructing the
    malicious pickle serialises `os.system` by name and cannot be done once that name has
    been replaced by a local function.
    """
    repo = tmp_path / "hostile"
    canaries = build_hostile_repo(repo)
    return repo, canaries


@pytest.fixture
def no_execution(monkeypatch):
    """Make any process spawn or socket use fail loudly during a scan."""
    fired: list[str] = []

    def _boom(name):
        def _f(*a, **k):
            fired.append(name)
            raise AssertionError(f"scanner called {name}({a!r}, {k!r}) — scanning must be inert")

        return _f

    monkeypatch.setattr(subprocess, "Popen", _boom("subprocess.Popen"))
    monkeypatch.setattr(subprocess, "run", _boom("subprocess.run"))
    monkeypatch.setattr(subprocess, "call", _boom("subprocess.call"))
    monkeypatch.setattr(os, "system", _boom("os.system"))
    monkeypatch.setattr(os, "popen", _boom("os.popen"))
    monkeypatch.setattr(socket, "socket", _boom("socket.socket"))
    monkeypatch.setattr(socket, "create_connection", _boom("socket.create_connection"))
    return fired


def test_scanning_a_hostile_repository_executes_nothing(hostile_repo, no_execution):
    repo, canaries = hostile_repo

    python_surface.run(repo)
    template_injection.run(repo)

    for name, canary in canaries.items():
        assert not canary.exists(), (
            f"scanning fired the {name} payload — TrustLens executed untrusted content"
        )
    assert no_execution == [], f"scanner attempted: {no_execution}"


def test_scanner_still_detects_the_hostile_repository(hostile_repo):
    """Inertness must not have been achieved by declining to look."""
    repo, _ = hostile_repo

    surface = python_surface.run(repo)
    template = template_injection.run(repo)

    statuses = {f["capability"]: f["status"] for f in surface.findings}
    assert statuses["execution.dynamic_eval"] == "FOUND", "eval in evil_module.py missed"
    assert statuses["process.shell"] == "FOUND", "os.system missed"

    deser = next(
        f for f in template.findings if f["capability"] == "execution.deserialization"
    )
    assert deser["status"] == "FOUND", "the YAML object tag was missed"


def test_scanner_does_not_import_the_scanned_repository(hostile_repo, no_execution):
    """A scanned module must never appear in sys.modules."""
    import sys

    repo, _ = hostile_repo
    before = set(sys.modules)

    python_surface.run(repo)
    template_injection.run(repo)

    new = set(sys.modules) - before
    assert "evil_module" not in new and "setup" not in new, (
        f"scanner imported scanned content: {new}"
    )


def test_scanner_writes_nothing_into_the_scanned_tree(hostile_repo, no_execution):
    """Static analysis is read-only against the artifact."""
    repo, _ = hostile_repo
    before = {p: p.stat().st_mtime_ns for p in sorted(repo.rglob("*")) if p.is_file()}

    python_surface.run(repo)
    template_injection.run(repo)

    after = {p: p.stat().st_mtime_ns for p in sorted(repo.rglob("*")) if p.is_file()}
    assert set(after) == set(before), (
        f"scanning changed the file set: added {set(after) - set(before)}, "
        f"removed {set(before) - set(after)}"
    )
    assert after == before, "scanning modified a file in the scanned tree"


def test_unreadable_file_becomes_a_recorded_failure_not_a_crash(tmp_path, no_execution):
    repo = tmp_path / "perms"
    repo.mkdir()
    (repo / "ok.py").write_text("X = 1\n", encoding="utf-8")
    blocked = repo / "blocked.py"
    blocked.write_text("import os\n", encoding="utf-8")
    blocked.chmod(0o000)
    try:
        result = python_surface.run(repo)
        failed = {Path(f["path"]).name: f["kind"] for f in result.scope["failed"]}
        assert "blocked.py" in failed, "an unreadable file must be recorded, not skipped"
        assert failed["blocked.py"] == "io_error"
        assert all(f["status"] != "NOT_FOUND_WITHIN_ANALYSED_SCOPE" for f in result.findings), (
            "an unreadable file in scope must force PARTIAL, never a clean result"
        )
    finally:
        blocked.chmod(0o644)
