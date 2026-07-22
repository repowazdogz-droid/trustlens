"""Render a human-readable report FROM an evidence record.

The rule this module exists to enforce: **the report is a projection of the record, never a
second account of it.** Every line below is derived from record fields. Nothing is
restated from memory, recomputed by a different route, or phrased to sound consistent with
what the scanner found. If the record and the report ever disagree, the report is wrong by
construction — and the tests check that by reading facts back out of the rendered text and
comparing them to the record.

The discrepancy label is decomposable by construction: `discrepancy_level()` returns the
level *and the identifiers that produced it*, and the renderer prints those identifiers
beneath the label. A reader can always get from the label back to the evidence. The label
never replaces the findings.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..evidence import Status, parse as parse_status

RULE_VERSION = "0.1.0"

#: Capabilities whose presence, when the artifact declared it would not, is the sharpest
#: form of the discrepancy this tool exists to surface.
_EXECUTION_CAPABILITIES = {
    "execution.dynamic_eval",
    "execution.dynamic_import",
    "execution.deserialization",
    "execution.loader_script",
    "execution.build_hook",
    "process.shell",
    "process.subprocess",
    "template.expression_evaluation",
}


@dataclass(frozen=True)
class Discrepancy:
    level: str
    reasons: tuple[str, ...]
    basis: str


def discrepancy_level(record: dict) -> Discrepancy:
    """Derive the structural-discrepancy level, with the identifiers that produced it.

    Returns the level AND its reasons, so the label can never be printed without the
    evidence that produced it.
    """
    findings = record.get("findings", [])
    contradictions = record.get("contradictions", [])

    declared_vs_observed = [
        c["contradiction_id"] for c in contradictions if c["contradiction_id"].startswith("DVR-")
    ]
    self_contradictions = [
        c["contradiction_id"] for c in contradictions if c["contradiction_id"].startswith("D-")
    ]
    execution_found = [
        f["finding_id"]
        for f in findings
        if f["status"] == "FOUND" and f["capability"] in _EXECUTION_CAPABILITIES
    ]
    any_found = [f["finding_id"] for f in findings if f["status"] == "FOUND"]
    incomplete = [
        f["finding_id"]
        for f in findings
        if parse_status(f["status"]) in (Status.PARTIAL, Status.UNKNOWN, Status.UNSUPPORTED)
    ]

    if declared_vs_observed:
        return Discrepancy(
            "HIGH",
            tuple(declared_vs_observed + execution_found),
            "the artifact declares a capability it does not have, and that capability was found",
        )
    if execution_found:
        return Discrepancy(
            "MEDIUM",
            tuple(execution_found),
            "execution-capable constructs were found, with no declaration contradicting them",
        )
    if any_found:
        return Discrepancy(
            "LOW",
            tuple(any_found),
            "capabilities were found, none of them execution-capable",
        )
    if incomplete and not any_found:
        return Discrepancy(
            "UNDETERMINED",
            tuple(incomplete),
            "no capability was found, but analysis did not complete over the intended scope",
        )
    return Discrepancy(
        "LOW",
        (),
        "no capability was found and every check completed over its recorded scope",
    )


def _fmt_evidence(finding: dict, limit: int = 3) -> list[str]:
    lines = []
    for ev in finding.get("evidence", [])[:limit]:
        where = ev.get("path") or "<no path>"
        if ev.get("line"):
            where += f":{ev['line']}"
        if ev.get("pointer"):
            where += f" {ev['pointer']}"
        detail = ev.get("detail") or ""
        lines.append(f"      Evidence: {where}")
        if detail:
            lines.append(f"      Mechanism: {detail}")
        if ev.get("excerpt"):
            lines.append(f"      Excerpt: {ev['excerpt'][:100]}")
    remaining = len(finding.get("evidence", [])) - limit
    if remaining > 0:
        lines.append(f"      … {remaining} further evidence location(s) in the record")
    return lines


def render(record: dict, summary: dict | None = None) -> str:
    """Render the record as text. Every line is derived from a record field."""
    out: list[str] = []
    artifact = record["artifact"]
    scope = record["scope"]
    findings = record["findings"]

    out.append("TrustLens scan report")
    out.append("=" * 70)
    out.append(f"Artifact        : {artifact['artifact_id']}  ({artifact['artifact_type']})")
    out.append(f"Source          : {artifact['source']}")
    out.append(
        f"Immutable ref   : {artifact['immutable_reference'] or 'none recorded — acquisition is not reproducible'}"
    )
    out.append(f"Artifact hash   : {artifact['content_hash']}")
    out.append(f"Record          : {record['record_id']}  (schema {record['schema_version']})")
    # The record's own seal, so a reader can tie this report to a specific sealed record
    # and detect a report rendered from an edited one.
    out.append(f"Record hash     : {record['content_hash']}")
    out.append(f"Tool            : trustlens {record['tool']['version']}")
    out.append("")

    # ---- Declared
    out.append("Declared:")
    declared = record.get("declared_capabilities", [])
    if not declared:
        out.append("  No declaration was found in any conventional card or manifest location.")
        out.append("  This is an absence of a declaration, NOT a declaration of absence.")
    else:
        if artifact.get("declared_kind"):
            out.append(f"  Repository type: {artifact['declared_kind']}")
        for d in declared:
            src = d["source"]
            where = src.get("path") or "?"
            if src.get("line"):
                where += f":{src['line']}"
            out.append(f"  [{d['declaration']}] {d['capability']}")
            out.append(f"      Stated at: {where}")
            out.append(f"      Verbatim: {d['verbatim'][:110]}")
    out.append("")

    # ---- Observed
    out.append("Actually reachable within analysed scope:")
    order = {"FOUND": 0, "PARTIAL": 1, "UNKNOWN": 2, "UNSUPPORTED": 3,
             "NOT_FOUND_WITHIN_ANALYSED_SCOPE": 4}
    for finding in sorted(findings, key=lambda f: (order.get(f["status"], 9), f["capability"])):
        status = finding["status"]
        out.append(f"  [{status}] {finding['capability']}")
        if status == "FOUND":
            out.extend(_fmt_evidence(finding))
        elif status == "PARTIAL":
            out.append(f"      Analysed: {len(finding['scope']['analysed'])} file(s)")
            for item in finding["scope"]["failed"]:
                out.append(f"      NOT analysed: {item['path']} ({item['kind']}: {item['reason'][:80]})")
        elif status == "NOT_FOUND_WITHIN_ANALYSED_SCOPE":
            sc = finding["scope"]
            out.append(
                f"      Analysed: {len(sc['analysed'])} file(s); languages: {', '.join(sc['languages'])}"
            )
            out.append(f"      Rules: {finding['rule_id']} v{finding['rule_version']}")
            if sc["excluded"]:
                out.append(
                    f"      Excluded: {', '.join(e['path'] for e in sc['excluded'])}"
                )
        elif status == "UNKNOWN":
            out.append(f"      Reason: {(finding.get('unknown_reason') or '')[:140]}")
        elif status == "UNSUPPORTED":
            out.append(f"      Construct: {finding.get('unsupported_construct')}")
    out.append("")

    # ---- Contradictions
    contradictions = record.get("contradictions", [])
    out.append("Structural discrepancy:")
    if not contradictions:
        out.append("  No contradiction was found between the declarations and the findings.")
    for c in contradictions:
        out.append(f"  [{c['contradiction_id']}] {c['summary']}")
        for side in c["between"]:
            out.append(f"      {side['evidence_kind']}: {side['assertion'][:110]}")
        out.append("      Recorded, not reconciled.")
    out.append("")

    # ---- Scope integrity
    out.append("Scope:")
    out.append(f"  Analysed : {len(scope['analysed'])} file(s)")
    if scope["excluded"]:
        for e in scope["excluded"]:
            out.append(f"  Excluded : {e['path']} — {e['reason']}")
    if scope["failed"]:
        for f in scope["failed"]:
            out.append(f"  FAILED   : {f['path']} — {f['kind']}: {f['reason'][:90]}")
    else:
        out.append("  No path in the recorded scope failed to analyse.")
    out.append("")

    # ---- Unknowns
    unknowns = record.get("unknowns", [])
    if unknowns:
        out.append("Unknowns:")
        for u in unknowns:
            out.append(f"  {u['subject']}")
            out.append(f"      {u['reason'][:150]}")
        out.append("")

    # ---- The label, with its decomposition
    disc = discrepancy_level(record)
    out.append(f"Structural discrepancy level: {disc.level}")
    out.append(f"  Basis: {disc.basis}")
    if disc.reasons:
        out.append("  Derived from:")
        for r in disc.reasons:
            out.append(f"    - {r}")
    else:
        out.append("  Derived from: no finding or contradiction raised the level.")
    out.append(
        "  This label is a summary of the identifiers above and does not replace them."
    )
    out.append("")

    # ---- Bounds, carried from the record rather than restated
    out.append("What this establishes:")
    for line in record["claims"]["establishes"]:
        out.append(f"  - {line}")
    out.append("")
    out.append("What this does NOT establish:")
    for line in record["claims"]["does_not_establish"]:
        out.append(f"  - {line}")
    out.append("")
    out.append(f"Residual uncertainty: {record['residual_uncertainty']}")

    return "\n".join(out)
