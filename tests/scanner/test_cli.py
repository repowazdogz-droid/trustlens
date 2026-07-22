"""Controls for the command line.

The exit code is what a pipeline reads, so it is part of the evidence. The load-bearing
test here is `test_incomplete_scan_does_not_exit_zero`: a caller that treats an incomplete
scan as a clean one reproduces the false-clean failure at the process boundary, where none
of the in-process guards can see it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustlens.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_USAGE, main

REPOS = Path(__file__).resolve().parents[2] / "examples" / "repos"


def _run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ------------------------------------------------------------------------ exit codes

def test_clean_repository_exits_zero(capsys):
    code, out, _ = _run(["scan", str(REPOS / "clean_tabular")], capsys)
    assert code == EXIT_CLEAN
    assert "TrustLens scan report" in out


def test_repository_with_findings_exits_one(capsys):
    code, out, _ = _run(["scan", str(REPOS / "unsafe_dataset_loader")], capsys)
    assert code == EXIT_FINDINGS
    assert "[FOUND]" in out


def test_incomplete_scan_does_not_exit_zero(capsys):
    """An unreadable file must not produce a clean exit status.

    This is the false-clean failure at the process boundary: a CI job that only reads the
    exit code would treat an incomplete analysis as a passing one.
    """
    code, _, err = _run(["scan", str(REPOS / "partial_encoding")], capsys)
    assert code == EXIT_INCOMPLETE
    assert code != EXIT_CLEAN
    assert "not a clean result" in err


def test_missing_path_is_a_usage_error(capsys):
    code, _, err = _run(["scan", "/definitely/not/here"], capsys)
    assert code == EXIT_USAGE
    assert "not a directory" in err


@pytest.mark.parametrize(
    "repo,expected",
    [
        ("clean_tabular", EXIT_CLEAN),
        ("clean_jsonl", EXIT_CLEAN),
        ("clean_imagefolder", EXIT_CLEAN),
        ("unsafe_dataset_loader", EXIT_FINDINGS),
        ("unsafe_model_repo", EXIT_FINDINGS),
        ("partial_encoding", EXIT_INCOMPLETE),
    ],
)
def test_every_bundled_example_scans_end_to_end(repo, expected, capsys):
    code, out, _ = _run(["scan", str(REPOS / repo)], capsys)
    assert code == expected, f"{repo} exited {code}, expected {expected}"
    assert "Structural discrepancy level:" in out


# --------------------------------------------------------------------------- output

def test_json_output_is_the_record(capsys):
    code, out, _ = _run(["scan", str(REPOS / "unsafe_dataset_loader"), "--format", "json"], capsys)
    assert code == EXIT_FINDINGS
    payload = json.loads(out)
    assert payload["record"]["schema_version"] == "trustlens/1.0.0"
    assert payload["summary"]["found"]


def test_written_record_validates(tmp_path, capsys):
    from trustlens.evidence.schema import validate_record

    out_path = tmp_path / "record.json"
    code, _, _ = _run(
        ["scan", str(REPOS / "unsafe_model_repo"), "--output", str(out_path)], capsys
    )
    assert code == EXIT_FINDINGS
    validate_record(json.loads(out_path.read_text()))


def test_text_report_and_json_record_agree(capsys):
    _, text, _ = _run(["scan", str(REPOS / "unsafe_model_repo")], capsys)
    _, raw, _ = _run(["scan", str(REPOS / "unsafe_model_repo"), "--format", "json"], capsys)
    record = json.loads(raw)["record"]
    for finding in record["findings"]:
        if finding["status"] == "FOUND":
            assert finding["capability"] in text, (
                "the text report and the JSON record disagree about what was found"
            )


# ---------------------------------------------------------------------- acquisition

def test_acquire_refuses_without_the_authorisation_flag(capsys, tmp_path):
    code, _, err = _run(["acquire", "./somewhere", str(tmp_path / "d")], capsys)
    assert code == EXIT_USAGE
    assert "--i-am-authorised" in err
    assert not (tmp_path / "d").exists()


def test_plan_refuses_an_unsupported_source(capsys):
    code, _, err = _run(["plan", "ftp://example.invalid/x.git"], capsys)
    assert code == EXIT_USAGE
    assert "only https" in err


def test_scan_subcommand_never_reaches_acquisition(monkeypatch, capsys):
    import trustlens.scanner.acquire as acq

    def _boom(*a, **k):
        raise AssertionError("scan must never acquire")

    monkeypatch.setattr(acq, "plan", _boom)
    monkeypatch.setattr(acq, "acquire", _boom)
    code, _, _ = _run(["scan", str(REPOS / "clean_tabular")], capsys)
    assert code == EXIT_CLEAN


# ------------------------------------------------------------------------ interface

def test_help_states_the_non_claims(capsys):
    from trustlens.cli import build_parser

    text = build_parser().format_help()
    assert "does not determine malicious intent" in text.lower()
    assert "certify artifacts as safe" in text.lower()


def test_no_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0
