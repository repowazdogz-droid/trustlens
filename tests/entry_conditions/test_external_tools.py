#!/usr/bin/env python3
"""Characterisation probe: how does each external tool report a file it could not read?

This is not a test of the tools. It is a test of the assumptions TrustLens makes *about*
the tools, and it exists because those assumptions were wrong once already: Phase 0's
documentation-based reading concluded Semgrep would report parse failures in its JSON
`errors[]`, and a real run showed it reporting unparseable files as successfully scanned.

Run it directly, or under pytest:

    python3 tests/entry_conditions/probe_external_tools.py
    python3 -m pytest tests/entry_conditions -q

**A failure here is not a regression in TrustLens.** It means a tool changed its reporting
behaviour, and the corresponding mapping in the scanner needs revisiting. If a tool starts
reporting failures properly, that is good news that requires work.

Findings recorded 2026-07-22 are in `docs/PHASE1_ENTRY_CONDITIONS.md`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Fixtures deliberately include files that are unparseable, undecodable and unreadable.
FIXTURES: dict[str, bytes] = {
    "good_but_bad.py": b"import subprocess\ndef f(c):\n    subprocess.Popen(c, shell=True)\n",
    "broken_syntax.py": b"def f(:\n    not python ]]]\n",
    "legacy_py2.py": b"print 'python 2 syntax'\n",
    "bad_encoding.py": b"\xff\xfe# not utf-8\nx = 1\n",
    "requirements.txt": b"requests==2.31.0\nthis is >>> not valid <<<\n",
    "package-lock.json": b'{ "name": "x", "packages": { BROKEN\n',
}
UNREADABLE = "unreadable.py"


def build_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    for name, data in FIXTURES.items():
        (repo / name).write_bytes(data)
    unreadable = repo / UNREADABLE
    unreadable.write_bytes(b"secret = 'x'\n")
    unreadable.chmod(0o000)
    return repo


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        pytest.skip(f"{tool} not installed")
    return path


@pytest.fixture(scope="module")
def repo():
    with tempfile.TemporaryDirectory() as tmp:
        yield build_repo(Path(tmp))


def test_bandit_reports_failures_in_json(repo):
    """Bandit DOES distinguish. Its errors[] maps directly onto scope.failed."""
    _require("bandit")
    out = repo.parent / "bandit.json"
    _run(["bandit", "-r", ".", "-f", "json", "-o", str(out)], repo)
    data = json.loads(out.read_text())

    assert "errors" in data, "bandit's JSON must carry an errors array"
    by_file = {Path(e["filename"]).name: e["reason"] for e in data["errors"]}

    for unparseable in ("broken_syntax.py", "legacy_py2.py", "bad_encoding.py"):
        assert unparseable in by_file, f"bandit silently skipped {unparseable}"
        assert "syntax error" in by_file[unparseable].lower()

    assert UNREADABLE in by_file, "bandit must report the unreadable file"
    assert "permission" in by_file[UNREADABLE].lower()


def test_semgrep_does_not_report_parse_failures(repo):
    """Semgrep does NOT distinguish. Characterises the behaviour TrustLens must work around.

    If this test starts failing, Semgrep has improved and
    `docs/PHASE1_ENTRY_CONDITIONS.md` plus the scanner's scope handling should be revisited.
    """
    _require("semgrep")
    rules = repo.parent / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: probe-shell-true\n"
        "    patterns: [{pattern: 'subprocess.Popen(..., shell=True, ...)'}]\n"
        "    message: shell=True\n"
        "    languages: [python]\n"
        "    severity: WARNING\n"
    )
    proc = _run(
        [
            "semgrep", "--metrics=off", "--disable-version-check",
            "--config", str(rules), "--json", ".",
        ],
        repo,
    )
    data = json.loads(proc.stdout)

    assert data["errors"] == [], (
        "Semgrep now reports errors for unparseable files. Revisit the scope mapping — "
        f"errors: {data['errors']}"
    )
    scanned = {Path(p).name for p in data["paths"].get("scanned", [])}
    assert "broken_syntax.py" in scanned, (
        "Semgrep no longer claims unparseable files as scanned; revisit the mapping"
    )
    assert UNREADABLE not in scanned
    assert not any(
        UNREADABLE in json.dumps(s) for s in data["paths"].get("skipped", [])
    ), "the unreadable file is absent from Semgrep's JSON entirely"


def test_gitleaks_json_has_no_scope_or_error_fields(repo):
    """gitleaks reports findings only; 'could not read' exists solely on stderr."""
    _require("gitleaks")
    out = repo.parent / "gl.json"
    proc = _run(
        ["gitleaks", "dir", ".", "--report-format", "json",
         "--report-path", str(out), "--no-banner"],
        repo,
    )
    data = json.loads(out.read_text())
    assert isinstance(data, list), "gitleaks JSON is a flat findings list"
    assert "permission" not in json.dumps(data).lower(), (
        "gitleaks now reports unreadable files in JSON; revisit the mapping"
    )
    assert "permission denied" in proc.stderr.lower(), (
        "the permission failure should at least appear on stderr"
    )


def test_syft_json_has_no_errors_key(repo):
    """syft silently drops malformed manifest content and exits 0."""
    _require("syft")
    proc = _run(["syft", "scan", "dir:.", "-o", "syft-json", "-q"], repo)
    data = json.loads(proc.stdout)
    assert "errors" not in data, "syft now reports errors in JSON; revisit the mapping"
    assert proc.returncode == 0


def test_osv_scanner_empty_results_can_mean_no_database(repo):
    """The most dangerous shape: results:[] identical to a clean scan.

    With --offline and no downloaded database, osv-scanner returns an empty result set.
    Only the exit code and stderr reveal that nothing was checked.
    """
    _require("osv-scanner")
    proc = _run(
        ["osv-scanner", "scan", "source", "-r", ".", "--offline", "--format", "json"],
        repo,
    )
    if proc.stdout.strip():
        data = json.loads(proc.stdout)
        assert "error" not in json.dumps(data).lower(), (
            "osv-scanner now reports errors in JSON; revisit the mapping"
        )
    assert proc.returncode != 0, (
        "a missing offline database must at least be visible in the exit code"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
