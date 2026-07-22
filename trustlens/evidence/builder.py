"""Correct-by-construction builders for evidence records.

Components should build records through these helpers rather than assembling dicts, so
that the invariants are enforced where the mistake is made rather than at validation time
when the context has been lost. In particular `make_finding` refuses to construct a
`NOT_FOUND_WITHIN_ANALYSED_SCOPE` finding over a scope containing failures — the third and
earliest of the three enforcement points, ahead of the JSON Schema and the semantic
validator.
"""

from __future__ import annotations

from typing import Any, Iterable

from .canonical import compute_finding_id, seal
from .schema import SCHEMA_VERSION
from .status import Status, parse as parse_status

#: Mirrors the detection_method -> evidence_strength conditionals in finding.schema.json.
#: Kept here as well so a mismatch surfaces at construction rather than at validation.
_DEFAULT_STRENGTH = {
    "declared_metadata": "DECLARED_ONLY",
    "static_ast": "STATIC_MATCH",
    "static_ast_dataflow": "STATIC_DATAFLOW",
    "static_pattern": "STATIC_MATCH",
    "static_external_tool": "STATIC_MATCH",
    "archive_inspection": "STATIC_MATCH",
    "config_derivation": "CONFIG_DERIVED",
    "policy_evaluation": "CONFIG_DERIVED",
    "graph_derivation": "INFERRED",
    "dynamic_observation": "DIRECT_OBSERVATION",
    "dynamic_blocked_observation": "DIRECT_OBSERVATION",
    "manual_assertion": "DECLARED_ONLY",
}


def make_scope(
    *,
    analysed: Iterable[str],
    languages: Iterable[str],
    excluded: Iterable[dict] | None = None,
    failed: Iterable[dict] | None = None,
) -> dict:
    """Build a scope block, deriving `vacuous` rather than trusting a caller to set it."""
    analysed_list = list(analysed)
    return {
        "analysed": analysed_list,
        "excluded": list(excluded or []),
        "failed": list(failed or []),
        "languages": list(languages),
        "vacuous": len(analysed_list) == 0,
    }


def make_evidence(
    *,
    kind: str,
    path: str | None = None,
    line: int | None = None,
    end_line: int | None = None,
    column: int | None = None,
    pointer: str | None = None,
    excerpt: str | None = None,
    redacted: bool = False,
    detail: str | None = None,
) -> dict:
    location = {
        "kind": kind,
        "path": path,
        "line": line,
        "excerpt": excerpt,
        "redacted": redacted,
    }
    for key, value in (
        ("end_line", end_line),
        ("column", column),
        ("pointer", pointer),
        ("detail", detail),
    ):
        if value is not None:
            location[key] = value
    return location


def make_finding(
    *,
    capability: str,
    status: str | Status,
    detection_method: str,
    rule_id: str,
    rule_version: str,
    source_component: str,
    scope: dict,
    confidence_basis: str,
    limitations: list[str],
    evidence: list[dict] | None = None,
    evidence_strength: str | None = None,
    evidence_unavailable_reason: str | None = None,
    unsupported_construct: str | None = None,
    unknown_reason: str | None = None,
    reproduced_by: list[str] | None = None,
    reproduced_records: list[str] | None = None,
    derived_from: list[str] | None = None,
    environment_description_ref: dict | None = None,
    notes: str | None = None,
) -> dict:
    parsed = parse_status(status)
    evidence = list(evidence or [])

    if parsed is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE and scope.get("failed"):
        failed_paths = ", ".join(item["path"] for item in scope["failed"])
        raise ValueError(
            "Refusing to build a NOT_FOUND_WITHIN_ANALYSED_SCOPE finding over a scope "
            f"containing {len(scope['failed'])} failed item(s) ({failed_paths}). "
            "The honest status is PARTIAL: analysis of the intended scope did not "
            "complete, and a clean result would claim coverage that was not achieved."
        )
    if parsed is Status.PARTIAL and not scope.get("failed"):
        raise ValueError(
            "PARTIAL requires a non-empty scope.failed naming what was not analysed and "
            "why. Without it the status is an unfalsifiable hedge."
        )
    if parsed is Status.FOUND and not evidence and not evidence_unavailable_reason:
        raise ValueError(
            "A FOUND finding needs at least one evidence location, or an explicit "
            "evidence_unavailable_reason explaining why no location can be produced."
        )
    if parsed is Status.UNSUPPORTED and not unsupported_construct:
        raise ValueError("UNSUPPORTED requires unsupported_construct.")
    if parsed is Status.UNKNOWN and not unknown_reason:
        raise ValueError("UNKNOWN requires unknown_reason.")
    if not limitations:
        raise ValueError(
            "limitations must be non-empty. Every check has a blind spot; a finding "
            "claiming none has not had its blind spot examined."
        )

    strength = evidence_strength or _DEFAULT_STRENGTH[detection_method]
    expected = _DEFAULT_STRENGTH[detection_method]
    if strength != expected and not (
        detection_method == "static_external_tool" and strength == "STATIC_DATAFLOW"
    ):
        raise ValueError(
            f"detection_method {detection_method!r} implies evidence_strength "
            f"{expected!r}, not {strength!r}. Method and strength must agree so that a "
            "configuration-derived path cannot be recorded with an observation's weight."
        )

    finding_id = compute_finding_id(
        source_component=source_component,
        capability=capability,
        rule_id=rule_id,
        rule_version=rule_version,
        evidence=evidence,
        analysed=scope.get("analysed", []),
    )

    return {
        "finding_id": finding_id,
        "capability": capability,
        "status": parsed.value,
        "detection_method": detection_method,
        "evidence_strength": strength,
        "rule_id": rule_id,
        "rule_version": rule_version,
        "source_component": source_component,
        "scope": scope,
        "evidence": evidence,
        "evidence_unavailable_reason": evidence_unavailable_reason,
        "confidence_basis": confidence_basis,
        "limitations": list(limitations),
        "unsupported_construct": unsupported_construct,
        "unknown_reason": unknown_reason,
        "independently_reproduced": {
            "reproduced": bool(reproduced_by),
            "by": list(reproduced_by or []),
            "records": list(reproduced_records or []),
        },
        "derived_from": list(derived_from or []),
        "environment_description_ref": environment_description_ref,
        "notes": notes,
    }


def make_record(
    *,
    component: str,
    tool_version: str,
    commit: str | None,
    artifact: dict,
    run: dict,
    scope: dict,
    claims: dict,
    residual_uncertainty: str,
    declared_capabilities: list[dict] | None = None,
    findings: list[dict] | None = None,
    contradictions: list[dict] | None = None,
    mitigations: list[dict] | None = None,
    generic_advice: list[str] | None = None,
    unknowns: list[dict] | None = None,
    unsupported: list[dict] | None = None,
    environment_description_ref: dict | None = None,
    sandbox: dict | None = None,
    external_tools: list[dict] | None = None,
    commit_dirty: bool | None = None,
    input_records: list[dict] | None = None,
) -> dict:
    """Assemble and seal a record. Sealing computes `content_hash` and `record_id`."""
    generic_advice = list(generic_advice or [])
    mitigations = list(mitigations or [])
    input_records = list(input_records or [])
    if component == "blast_radius" and not input_records:
        raise ValueError(
            "A blast_radius record must declare the records it composed. A simulation "
            "with no declared inputs has no traceable evidence base."
        )
    if generic_advice and not mitigations:
        raise ValueError(
            "Generic advice may accompany finding-specific mitigations but may never "
            "stand in for them. Produce at least one specific mitigation first."
        )

    tool: dict[str, Any] = {
        "name": "trustlens",
        "version": tool_version,
        "commit": commit,
        "component": component,
    }
    if commit_dirty is not None:
        tool["commit_dirty"] = commit_dirty
    if external_tools is not None:
        tool["external_tools"] = external_tools

    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": "",
        "content_hash": "",
        "tool": tool,
        "artifact": artifact,
        "run": run,
        "scope": scope,
        "input_records": input_records,
        "declared_capabilities": list(declared_capabilities or []),
        "findings": list(findings or []),
        "contradictions": list(contradictions or []),
        "mitigations": mitigations,
        "generic_advice": generic_advice,
        "unknowns": list(unknowns or []),
        "unsupported": list(unsupported or []),
        "residual_uncertainty": residual_uncertainty,
        "environment_description_ref": environment_description_ref,
        "sandbox": sandbox,
        "claims": claims,
    }
    return seal(record)
