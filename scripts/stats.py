#!/usr/bin/env python3
"""Emit verified project statistics, read from the tools themselves.

Every number this project reports — test counts, rule counts, target coverage — comes from
here, by running the thing that knows and parsing its output. Nothing is typed, recalled, or
copied from a previous report.

This exists because a stated test count drifted from the real one **twice**: a commit
claimed 91 when the suite ran 84, and later claimed 316 when it ran 525. Two instances is a
pattern, and the fix for a pattern is a mechanism, not more care.

Usage:
    python3 scripts/stats.py            # human-readable block
    python3 scripts/stats.py --json     # machine-readable
    python3 scripts/stats.py --tests    # just the COLLECTED count, for scripting

The commit-msg hook in .githooks/ uses this to reject any commit message whose claimed test
count disagrees with a fresh run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: pytest's summary counts. Each keyword is searched INDEPENDENTLY rather than with one
#: ordered pattern, because pytest varies the order: "525 passed in 4.3s" but
#: "3 failed, 10 passed in 1.0s". An ordered pattern silently reported failed=0 on a
#: failing run — the false-success pattern, inside the tool built to prevent it.
_COUNT_PATTERNS = {
    "passed": re.compile(r"(\d+) passed"),
    "failed": re.compile(r"(\d+) failed"),
    "skipped": re.compile(r"(\d+) skipped"),
    "errors": re.compile(r"(\d+) errors?\b"),
}
#: A line is pytest's summary only if it reports a duration and at least one count.
_DURATION = re.compile(r"\sin\s[\d.]+s")


def parse_summary(line: str) -> dict | None:
    """Read every count out of one summary line, order-independently."""
    if not _DURATION.search(line):
        return None
    counts = {}
    for key, pattern in _COUNT_PATTERNS.items():
        match = pattern.search(line)
        counts[key] = int(match.group(1)) if match else 0
    if not any(counts.values()):
        return None
    counts["collected"] = counts["passed"] + counts["failed"] + counts["skipped"]
    return counts


def run_tests() -> dict:
    """Run the suite and read the counts out of pytest's own summary.

    The child run is marked with TRUSTLENS_STATS_CHILD so that the tests which exercise
    this script skip inside it. Without that marker the recursion is unbounded: the suite
    contains tests that call this script, which runs the suite, which calls this script.
    """
    import os

    env = dict(os.environ)
    env["TRUSTLENS_STATS_CHILD"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    # The canonical number is COLLECTED, not passed. `passed` varies with the environment
    # because the external-tool probes skip when no analyser is on PATH (525 passed here,
    # 520 passed + 5 skipped in a clean venv). Collected is identical in both, so it is the
    # number that belongs in a commit message.
    for line in reversed(proc.stdout.strip().splitlines()):
        counts = parse_summary(line)
        if counts is not None:
            counts["summary_line"] = line.strip().strip("= ")
            counts["exit_code"] = proc.returncode
            return counts
    raise SystemExit(
        "could not parse pytest's summary line; refusing to report a number that was not "
        f"read from the runner.\n--- stdout tail ---\n{proc.stdout[-2000:]}"
    )


def rule_stats() -> dict:
    sys.path.insert(0, str(ROOT))
    from trustlens.scanner.checks import python_surface as ps
    from trustlens.scanner.checks import template_injection as ti

    sys.path.insert(0, str(ROOT / "tests" / "scanner"))
    from test_target_coverage import EXCLUDED_TARGETS

    targets = {t for r in ps.RULES for t in r.targets}
    return {
        "rules": len(ps.RULES),
        "detectors": len(ti.DETECTORS),
        "capabilities": len({r.capability for r in ps.RULES}),
        "targets": len(targets),
        "targets_generated": len(targets) - len(EXCLUDED_TARGETS),
        "targets_excluded": len(EXCLUDED_TARGETS),
    }


def collect() -> dict:
    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True
        ).stdout.strip()
    )
    return {"commit": commit, "dirty": dirty, "tests": run_tests(), "rules": rule_stats()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--tests",
        action="store_true",
        help="print the COLLECTED count only (stable across environments)",
    )
    args = parser.parse_args()

    if args.tests:
        print(run_tests()["collected"])
        return 0

    stats = collect()
    if args.json:
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0

    t, r = stats["tests"], stats["rules"]
    pct = 100 * r["targets_generated"] // r["targets"]
    print("Verified project statistics (read from the tools, not typed)")
    print(f"  commit           : {stats['commit']}{' (dirty)' if stats['dirty'] else ''}")
    print(f"  pytest summary   : {t['summary_line']}")
    print(f"  collected        : {t['collected']}   <- the number to quote; stable across environments")
    print(f"  passed           : {t['passed']}   (environment-dependent: probes skip without analysers)")
    print(f"  failed           : {t['failed']}")
    print(f"  skipped          : {t['skipped']}")
    print(f"  rules            : {r['rules']} across {r['capabilities']} capabilities")
    print(f"  detectors        : {r['detectors']}")
    print(
        f"  target coverage  : {r['targets_generated']}/{r['targets']} generated ({pct}%), "
        f"{r['targets_excluded']} excluded with a stated reason"
    )
    return 0 if t["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
