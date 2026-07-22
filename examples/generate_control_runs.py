#!/usr/bin/env python3
"""Regenerate stored control-run evidence for the bundled example repositories.

A fixture sitting in the repository is not evidence that the scanner detects it. These are
the actual records produced by running the full scanner over each bundled example, stored
so that a reader can inspect what the tool really emitted rather than take a claim on
trust, and so that a change in behaviour shows up as a diff.

Run from the repository root:

    PYTHONPATH=. python3 examples/generate_control_runs.py
    git diff --exit-code examples/control_runs/

Timestamps are fixed constants and paths are repository-relative, so regeneration is
byte-identical. If it is not, determinism has broken and the content hashes stop meaning
anything.
"""

from __future__ import annotations

import json
from pathlib import Path

from trustlens.scanner.assemble import scan, summarise
from trustlens.scanner.report import render

REPOS = Path("examples/repos")
OUT = Path("examples/control_runs")

STARTED = "2026-07-22T00:00:00+00:00"
COMPLETED = "2026-07-22T00:00:01+00:00"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for repo in sorted(p for p in REPOS.iterdir() if p.is_dir()):
        result = scan(
            repo,
            started_at=STARTED,
            completed_at=COMPLETED,
            artifact_source=f"examples/repos/{repo.name}",
        )
        summary = summarise(result)
        payload = {
            "example_repo": repo.name,
            "summary": summary,
            "record": result.record,
        }
        # The rendered report is stored too, as the human-facing half of the control-run
        # evidence. It is derived from the record, so it is deterministic for a
        # deterministic record and a drift between the two shows up as a diff.
        (OUT / f"{repo.name}.report.txt").write_text(
            render(result.record, summary) + "\n", encoding="utf-8"
        )
        path = OUT / f"{repo.name}.json"
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"{repo.name:24} found={len(summary['found']):2}  "
            f"incomplete={len(summary['incomplete']):2}  "
            f"complete={summary['analysis_complete']}  -> {path}"
        )


if __name__ == "__main__":
    main()
