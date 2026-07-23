"""The blast-radius CLI, end to end, writing a record and returning an honest exit code."""

from __future__ import annotations

import json
from pathlib import Path

from trustlens.cli import main
from trustlens.evidence import validate_structure

RECORDS = Path(__file__).resolve().parents[2] / "examples" / "records"


def _env():
    return {
        "entry": {"kind": "service_account", "identifier": "dataset-worker", "namespace": "ml"},
        "assets": [
            {"kind": "storage_resource", "identifier": "prod-data"},
            # the cloud metadata endpoint is itself a credential-theft asset; the sandbox
            # observed the worker's attempt to reach it being blocked
            {"kind": "api_endpoint", "identifier": "169.254.169.254"},
        ],
        "capability_targets": {
            "execution.dynamic_import": {"kind": "secret", "identifier": "aws-credential"},
            "cloud.metadata_endpoint": {"kind": "api_endpoint", "identifier": "169.254.169.254"},
        },
        "configured_edges": [
            {
                "source": {"kind": "secret", "identifier": "aws-credential"},
                "target": {"kind": "storage_resource", "identifier": "prod-data"},
                "relation": "grants", "provenance": "configured",
                "derived_from": ["credential_mapper:role-policy:abc"],
                "evidence_detail": "s3:GetObject on prod-data",
            }
        ],
        "environment_description_ref": {
            "description_id": "prod-dataset-processing-v3", "description_hash": "c" * 64,
            "captured_at_basis": "operator_asserted",
            "description_captured_at": "2026-06-01T00:00:00+00:00",
            "source_format": "trustlens_env_v1",
        },
    }


def test_cli_composes_and_writes_a_valid_record(tmp_path, capsys):
    env_path = tmp_path / "env.json"
    env_path.write_text(json.dumps(_env()))
    out = tmp_path / "blast.json"

    code = main([
        "blast-radius",
        "--scan", str(RECORDS / "scanner_record.json"),
        "--sandbox", str(RECORDS / "sandbox_record.json"),
        "--env", str(env_path),
        "--output", str(out),
    ])
    captured = capsys.readouterr()

    # A live configured path worker->cred->s3 exists, so exit code is FINDINGS (1).
    assert code == 1, captured.err
    assert "BLAST RADIUS" in captured.out
    # The blocked metadata path must be shown as BLOCKED, not omitted.
    assert "BLOCKED" in captured.out

    record = json.loads(out.read_text())
    validate_structure(record)
    assert record["run"]["execution_mode"] == "offline_modelling"
    # The permitted framing, never a prevention claim.
    joined = " ".join(record["claims"]["does_not_establish"])
    assert "prevented" in joined


def test_cli_reports_no_path_as_clean_scope_not_silent(tmp_path, capsys):
    env = _env()
    # An asset nothing reaches.
    env["assets"] = [{"kind": "storage_resource", "identifier": "unreachable-bucket"}]
    env_path = tmp_path / "env.json"
    env_path.write_text(json.dumps(env))

    code = main([
        "blast-radius",
        "--scan", str(RECORDS / "scanner_record.json"),
        "--env", str(env_path),
    ])
    captured = capsys.readouterr()
    assert code == 0  # no live path
    assert "NOT_FOUND_WITHIN_ANALYSED_SCOPE" in captured.out
    assert "not proof that no path exists" in captured.out


def test_cli_rejects_an_env_missing_assets(tmp_path, capsys):
    env = _env()
    del env["assets"]
    env_path = tmp_path / "env.json"
    env_path.write_text(json.dumps(env))
    code = main([
        "blast-radius", "--scan", str(RECORDS / "scanner_record.json"), "--env", str(env_path),
    ])
    assert code == 3  # usage error
    assert "assets" in capsys.readouterr().err
