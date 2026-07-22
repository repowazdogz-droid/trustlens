"""Top-level scanner: run every check family and assemble one evidence record.

Aggregation is where a false-clean result is most likely to be introduced, because the
code combining results is furthest from the code that knew what it found. This session
already produced that failure twice at the individual-rule level — a detection with no
corresponding finding, and a fixture passing on an unrelated match — so the assembler is
built around the assumption that it will happen again here.

The mechanism is **coverage reconciliation**. Every check family declares, up front, the
set of capabilities it is responsible for reporting. After running, the assembler compares
what was declared against what was delivered. Any capability a family promised and did not
deliver becomes an `UNKNOWN` finding and a recorded gap — never silence, and never a clean
result. Any family that raises becomes a scope failure that forces `PARTIAL` and is
surfaced in the verdict.

The consequence worth stating plainly: **the overall verdict cannot be clean unless every
declared capability was actually reported on.** A dropped, corrupted or exception-killed
family degrades the verdict rather than disappearing from it.
"""

from __future__ import annotations

import hashlib
import json
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..evidence import (
    FindingIndex,
    Status,
    make_finding,
    make_record,
    make_scope,
    parse as parse_status,
)
from ..evidence.schema import SchemaValidationError, validate_structure
from .checks import loader_scripts, python_surface, template_injection

TOOL_VERSION = "0.1.0"


# --------------------------------------------------------------------------- check registry

@dataclass(frozen=True)
class CheckSpec:
    """A check family and the capabilities it promises to report on."""

    name: str
    runner: Callable
    capabilities: frozenset[str]


def _capabilities_of_rules() -> frozenset[str]:
    return frozenset(r.capability for r in python_surface.RULES) | frozenset(
        python_surface.DERIVED_CAPABILITIES
    )


CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(
        name="template_injection",
        runner=template_injection.run,
        capabilities=frozenset(
            {
                "template.injection_surface",
                "template.expression_evaluation",
                "execution.deserialization",
            }
        ),
    ),
    CheckSpec(
        name="python_surface",
        runner=python_surface.run,
        capabilities=_capabilities_of_rules(),
    ),
    CheckSpec(
        name="loader_scripts",
        runner=loader_scripts.run,
        capabilities=frozenset(
            {"execution.loader_script", "execution.dynamic_import", "execution.build_hook"}
        ),
    ),
)


# --------------------------------------------------------------------------- artifact hash

def directory_manifest_v1(root: Path, excluded_dirs: set[str]) -> tuple[str, int, int]:
    """SHA-256 over sorted `<relpath>\\0<sha256>` lines. Defined in SCHEMA.md."""
    lines, count, total = [], 0, 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in excluded_dirs for part in rel.parts):
            continue
        try:
            data = p.read_bytes()
        except OSError:
            # Unreadable files cannot contribute to the hash; they are recorded as scope
            # failures by the individual checks, so the omission is visible elsewhere.
            continue
        lines.append(f"{rel}\0{hashlib.sha256(data).hexdigest()}")
        count += 1
        total += len(data)
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    return digest, count, total


# --------------------------------------------------------------------------- reconciliation

@dataclass
class FamilyOutcome:
    name: str
    delivered: set[str] = field(default_factory=set)
    error: str | None = None


@dataclass
class ScanResult:
    record: dict
    outcomes: list[FamilyOutcome]
    coverage_gaps: list[str]
    rows: list[dict]

    @property
    def complete(self) -> bool:
        return not self.coverage_gaps and all(o.error is None for o in self.outcomes)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def scan(
    root: Path,
    *,
    excluded_dirs: set[str] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    commit: str | None = None,
    checks: tuple[CheckSpec, ...] = CHECKS,
    artifact_source: str | None = None,
) -> ScanResult:
    """Run every check family over `root` and assemble a validated evidence record."""
    root = Path(root)
    excluded_dirs = excluded_dirs or {"vendor", ".git", "node_modules", "__pycache__"}
    started = started_at or _now()

    findings: list[dict] = []
    outcomes: list[FamilyOutcome] = []
    analysed: set[str] = set()
    excluded: list[dict] = []
    failed: list[dict] = []
    languages: set[str] = set()
    notes: list[str] = []

    for spec in checks:
        outcome = FamilyOutcome(name=spec.name)
        try:
            result = spec.runner(root, excluded_dirs=excluded_dirs)
        except Exception as exc:  # a check must never take the scan down silently
            outcome.error = f"{type(exc).__name__}: {exc}"
            failed.append(
                {
                    "path": f"<check:{spec.name}>",
                    "reason": (
                        f"check family raised {type(exc).__name__}: {exc}. "
                        f"{traceback.format_exc(limit=1).strip()}"
                    ),
                    "kind": "internal_error",
                }
            )
            notes.append(f"Check family {spec.name} FAILED and reported nothing.")
            outcomes.append(outcome)
            continue

        accepted = []
        for finding in result.findings:
            problems = validate_structure_of_finding(finding)
            if problems:
                # A malformed finding is not silently dropped; it is converted into a
                # recorded failure so the capability it claimed still cannot read clean.
                failed.append(
                    {
                        "path": f"<finding:{spec.name}:{finding.get('capability', '?')}>",
                        "reason": f"finding failed schema validation: {'; '.join(problems)[:300]}",
                        "kind": "internal_error",
                    }
                )
                notes.append(
                    f"Check family {spec.name} produced a malformed finding for "
                    f"{finding.get('capability', '?')}; recorded as a failure."
                )
                continue
            accepted.append(finding)
            outcome.delivered.add(finding["capability"])

        findings += accepted
        analysed.update(result.scope["analysed"])
        languages.update(result.scope["languages"])
        for item in result.scope["excluded"]:
            if item not in excluded:
                excluded.append(item)
        for item in result.scope["failed"]:
            if item not in failed:
                failed.append(item)
        outcomes.append(outcome)

    # ---- coverage reconciliation: what was promised versus what arrived
    coverage_gaps: list[str] = []
    for spec, outcome in zip(checks, outcomes):
        missing = sorted(spec.capabilities - outcome.delivered)
        for capability in missing:
            coverage_gaps.append(f"{spec.name}:{capability}")
            reason = (
                f"check family {spec.name} did not report on this capability"
                if outcome.error is None
                else f"check family {spec.name} failed: {outcome.error}"
            )
            findings.append(
                make_finding(
                    capability=capability,
                    status="UNKNOWN",
                    detection_method="static_ast",
                    rule_id=f"assembler:coverage:{spec.name}",
                    rule_version=TOOL_VERSION,
                    source_component="scanner",
                    scope=make_scope(analysed=[], languages=[]),
                    unknown_reason=(
                        f"{reason}. The capability was declared in the family's coverage "
                        "manifest, so its absence is a gap in this run rather than an "
                        "absence of the capability in the artifact."
                    ),
                    confidence_basis=(
                        "Recorded by the assembler's coverage reconciliation, which compares "
                        "each family's declared capabilities against the findings it "
                        "delivered."
                    ),
                    limitations=[
                        "This is an absence of analysis, not a result. It must not be read "
                        "as evidence that the capability is absent from the artifact.",
                    ],
                )
            )

    if coverage_gaps:
        notes.append(
            f"Coverage reconciliation found {len(coverage_gaps)} declared capability/ies "
            "with no delivered finding; each is recorded as UNKNOWN."
        )

    source_label = artifact_source if artifact_source is not None else str(root)
    digest, file_count, total_bytes = directory_manifest_v1(root, excluded_dirs)
    scope = make_scope(
        analysed=sorted(analysed),
        languages=sorted(languages) or ["python"],
        excluded=excluded,
        failed=failed,
    )

    index = FindingIndex([{"findings": findings}])
    rows = index.declared_versus_observed({"declared_capabilities": []})

    record = make_record(
        component="scanner",
        tool_version=TOOL_VERSION,
        commit=commit,
        artifact={
            "artifact_id": root.name,
            "artifact_type": "local_directory",
            "declared_kind": None,
            # Caller-controlled so a record is reproducible regardless of whether the
            # scan was invoked with an absolute or a relative path.
            "source": source_label,
            "immutable_reference": None,
            "acquisition_method": "user_supplied_path",
            "acquisition_authorised_by": None,
            "acquired_at": started,
            "content_hash": digest,
            "content_hash_method": "directory_manifest_v1",
            "file_count": file_count,
            "total_bytes": total_bytes,
        },
        run={
            "started_at": started,
            "completed_at": completed_at or _now(),
            "execution_mode": "static_analysis",
            # Uses the same caller-controlled label as artifact.source, so the record
            # body does not vary with how the path was spelled at the call site.
            "invocation": f"trustlens scan {source_label}",
            "config_hash": None,
            "reasoning_notes": notes
            or ["All declared check families reported on every capability they cover."],
        },
        scope=scope,
        findings=findings,
        declared_capabilities=[],
        unknowns=[
            {
                "subject": "Declared capabilities of the artifact",
                "reason": "Declared-surface extraction is not implemented in this build.",
                "would_be_resolved_by": "The declared-surface extractor (README, dataset card, manifests).",
            }
        ],
        residual_uncertainty=_residual(findings, coverage_gaps, failed),
        claims={
            "establishes": [
                "The listed static checks ran over the recorded scope at the recorded rule "
                "versions.",
                "Constructs cited at the recorded positions are present in the artifact.",
            ],
            "does_not_establish": [
                "That any construct executes at runtime.",
                "That the artifact is malicious, or that any finding is exploitable.",
                "That capabilities outside the analysed rules are absent.",
            ],
        },
        environment_description_ref=None,
        sandbox=None,
    )

    return ScanResult(record=record, outcomes=outcomes, coverage_gaps=coverage_gaps, rows=rows)


def validate_structure_of_finding(finding: dict) -> list[str]:
    """Validate one finding against the shared schema, in isolation."""
    from ..evidence.schema import schema_set

    validator = schema_set().validator("urn:trustlens:1.0.0:finding")
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in validator.iter_errors(finding)
    ]


def _residual(findings: list[dict], gaps: list[str], failed: list[dict]) -> str:
    parts = []
    if gaps:
        parts.append(
            f"{len(gaps)} declared capability/ies were not reported on by their check family"
        )
    if failed:
        parts.append(f"{len(failed)} path(s) or check(s) could not be analysed")
    incomplete = [
        f["capability"]
        for f in findings
        if parse_status(f["status"]) in (Status.PARTIAL, Status.UNKNOWN, Status.UNSUPPORTED)
    ]
    if incomplete:
        parts.append(f"{len(incomplete)} capability result(s) are incomplete")
    if not parts:
        return (
            "Every declared capability was reported on and every analysed path completed. "
            "Runtime reachability of every finding remains unestablished, and capabilities "
            "outside the implemented rules were not examined."
        )
    return (
        "; ".join(parts).capitalize()
        + ". No result in this record establishes that a capability is absent from the artifact."
    )


# --------------------------------------------------------------------------- presentation

def summarise(result: ScanResult) -> dict:
    """A decomposable summary. The label never replaces the findings it came from."""
    findings = result.record["findings"]
    by_status: dict[str, list[str]] = {}
    for f in findings:
        by_status.setdefault(f["status"], []).append(f["capability"])

    found = sorted(by_status.get("FOUND", []))
    incomplete = sorted(
        by_status.get("PARTIAL", []) + by_status.get("UNKNOWN", []) + by_status.get("UNSUPPORTED", [])
    )

    scope_failures = [
        {"path": f["path"], "kind": f["kind"]} for f in result.record["scope"]["failed"]
    ]

    return {
        "found": found,
        "incomplete": incomplete,
        # Surfaced at the top level: a finding may legitimately be clean over a narrower
        # scope than the record's, so a reader must be able to see that something in the
        # artifact could not be analysed without cross-referencing every finding.
        "scope_failures": scope_failures,
        "scope_complete": not scope_failures,
        "clean_within_scope": sorted(by_status.get("NOT_FOUND_WITHIN_ANALYSED_SCOPE", [])),
        "coverage_gaps": result.coverage_gaps,
        "analysis_complete": result.complete,
        "contributing_findings": {
            capability: [f["finding_id"] for f in findings if f["capability"] == capability]
            for capability in found + incomplete
        },
    }
