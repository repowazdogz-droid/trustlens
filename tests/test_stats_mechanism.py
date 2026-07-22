"""The reported test count must come from the runner, with no path for a typed number.

A stated count drifted from reality twice — a commit claimed 91 when the suite ran 84, then
316 when it ran 525. Two instances is a pattern, and a pattern needs a mechanism rather than
a resolution to be more careful. These tests check the mechanism, including that the
commit-msg hook actually rejects a wrong claim rather than merely existing.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import os

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Tests that shell out to stats.py (which runs the whole suite) must not run *inside* a
#: stats.py child run, or the recursion is unbounded. Marked rather than removed, because
#: the hook's real behaviour is exactly what needs testing.
nested = pytest.mark.skipif(
    os.environ.get("TRUSTLENS_STATS_CHILD") == "1",
    reason="inside a stats.py child run; invoking it again would recurse without bound",
)
STATS = ROOT / "scripts" / "stats.py"
HOOK = ROOT / ".githooks" / "commit-msg"


def test_stats_script_exists_and_is_executable():
    assert STATS.is_file()
    assert HOOK.is_file()
    assert HOOK.stat().st_mode & 0o111, "the hook must be executable or git will skip it"


def test_summary_parser_reads_the_runner_not_a_guess():
    """Parse pytest-shaped summary lines, including the skipped case."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import stats as stats_mod

    for line, expected in [
        ("520 passed, 5 skipped in 9.11s", {"passed": 520, "skipped": 5, "failed": 0, "collected": 525}),
        ("525 passed in 4.35s", {"passed": 525, "skipped": 0, "failed": 0, "collected": 525}),
        # Order-independence: pytest puts failures FIRST. An ordered pattern reported
        # failed=0 here, which would have made stats.py claim success on a failing suite.
        ("3 failed, 10 passed in 1.00s", {"passed": 10, "failed": 3, "collected": 13}),
        ("1 failed, 2 passed, 3 skipped in 0.10s", {"passed": 2, "failed": 1, "skipped": 3}),
        ("2 errors in 0.5s", {"errors": 2}),
    ]:
        got = stats_mod.parse_summary(line)
        assert got is not None, f"failed to parse {line!r}"
        for key, want in expected.items():
            assert got[key] == want, f"{line!r}: {key} was {got[key]}, expected {want}"


def test_a_non_summary_line_is_not_mistaken_for_one():
    sys.path.insert(0, str(ROOT / "scripts"))
    import stats as stats_mod

    assert stats_mod.parse_summary("collecting ... 525 items") is None
    assert stats_mod.parse_summary("") is None


def test_collected_is_the_stable_number():
    """`passed` varies with the environment; `collected` does not.

    The external-tool probes skip when no analyser is on PATH, so a commit made in a clean
    environment would report a different `passed` than one made with the tools installed.
    Collected is identical in both, which is why it is the number the hook checks.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import stats as stats_mod

    collected = stats_mod.parse_summary("520 passed, 5 skipped in 9.11s")["collected"]
    assert collected == 525
    assert stats_mod.parse_summary("525 passed in 4.35s")["collected"] == collected, (
        "collected must be identical whether or not the probes skipped"
    )


def test_stats_refuses_to_report_an_unparsable_run(monkeypatch):
    """A number that could not be read must not become a zero."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import stats as stats_mod

    class _Fake:
        stdout = "no summary line here"
        returncode = 0

    monkeypatch.setattr(stats_mod.subprocess, "run", lambda *a, **k: _Fake())
    with pytest.raises(SystemExit, match="refusing to report a number"):
        stats_mod.run_tests()


# ------------------------------------------------------------------ the hook itself

def _run_hook(message: str, tmp_path: Path) -> subprocess.CompletedProcess:
    msg_file = tmp_path / "COMMIT_EDITMSG"
    msg_file.write_text(message, encoding="utf-8")
    return subprocess.run(
        [str(HOOK), str(msg_file)], cwd=ROOT, capture_output=True, text=True
    )


@nested
def test_hook_rejects_a_wrong_count(tmp_path):
    result = _run_hook("Some change\n\n999999 tests pass.\n", tmp_path)
    assert result.returncode == 1, "the hook must reject an impossible count"
    assert "REJECTED" in result.stderr
    assert "999999" in result.stderr


@nested
def test_hook_ignores_a_message_with_no_claim(tmp_path):
    result = _run_hook("A change with no numeric claim\n", tmp_path)
    assert result.returncode == 0


@nested
def test_hook_accepts_the_count_the_runner_reports(tmp_path):
    actual = subprocess.run(
        [sys.executable, str(STATS), "--tests"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    assert actual.isdigit(), f"stats.py did not emit a number: {actual!r}"
    result = _run_hook(f"A change\n\n{actual} tests pass.\n", tmp_path)
    assert result.returncode == 0, result.stderr


def test_hook_is_wired_up_in_this_clone():
    """core.hooksPath must point at .githooks, or the hook never runs.

    This is a per-clone git setting and is NOT carried by the repository, so it is checked
    rather than assumed. A failure here means the mechanism is present but inactive.
    """
    configured = subprocess.run(
        ["git", "config", "--get", "core.hooksPath"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    assert configured == ".githooks", (
        "core.hooksPath is not set to .githooks, so the commit-msg hook will not run. "
        "Run: git config core.hooksPath .githooks"
    )


def test_contributing_documents_the_mechanism():
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "scripts/stats.py" in text
    assert "core.hooksPath" in text
