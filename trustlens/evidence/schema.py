"""Schema loading and validation for TrustLens evidence records.

Two layers of checking, because JSON Schema cannot express all of the invariants that
matter:

* `validate_structure` runs the JSON Schema, which carries the structural rules —
  including the load-bearing one that a `NOT_FOUND_WITHIN_ANALYSED_SCOPE` finding may
  not have a non-empty `scope.failed`.
* `validate_semantics` runs the cross-field rules a schema cannot see: identifier
  uniqueness and derivation, hash reproduction, reference resolution, and the rule that a
  derived finding is never stronger than the weakest evidence it was derived from.

`validate_record` runs both and raises a single aggregated error, so a caller sees every
problem at once rather than fixing them one round-trip at a time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .canonical import compute_content_hash, compute_finding_id, compute_record_id
from .status import Status, parse as parse_status

SCHEMA_VERSION = "trustlens/1.0.0"

_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


class SchemaValidationError(ValueError):
    """Aggregated validation failure. Carries every problem found, not just the first."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        joined = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"{len(problems)} validation problem(s):\n{joined}")


@dataclass(frozen=True)
class SchemaSet:
    registry: Registry
    schemas: dict[str, dict] = field(default_factory=dict)

    def validator(self, schema_id: str) -> Draft202012Validator:
        return Draft202012Validator(self.schemas[schema_id], registry=self.registry)


def _iter_schema_files() -> Iterable[Path]:
    yield from sorted(_SCHEMA_DIR.glob("*.schema.json"))
    yield from sorted(_SCHEMA_DIR.glob("enums/*.schema.json"))


def load_schemas(schema_dir: Path | None = None) -> SchemaSet:
    """Load every schema in `schemas/` into a resolvable registry, keyed by `$id`."""
    global _SCHEMA_DIR
    directory = schema_dir or _SCHEMA_DIR
    schemas: dict[str, dict] = {}
    resources: list[tuple[str, Resource]] = []
    paths = (
        sorted(directory.glob("*.schema.json"))
        + sorted(directory.glob("enums/*.schema.json"))
    )
    if not paths:
        raise FileNotFoundError(f"No schemas found under {directory}")
    for path in paths:
        doc = json.loads(path.read_text(encoding="utf-8"))
        schema_id = doc.get("$id")
        if not schema_id:
            raise ValueError(f"{path} has no $id; every TrustLens schema must be addressable")
        schemas[schema_id] = doc
        resources.append((schema_id, Resource.from_contents(doc)))
    return SchemaSet(registry=Registry().with_resources(resources), schemas=schemas)


_CACHED: SchemaSet | None = None


def schema_set() -> SchemaSet:
    global _CACHED
    if _CACHED is None:
        _CACHED = load_schemas()
    return _CACHED


def validate_structure(record: dict) -> list[str]:
    """Run the JSON Schema. Returns a list of human-readable problems (empty if valid)."""
    validator = schema_set().validator("urn:trustlens:1.0.0:evidence_record")
    problems = []
    for err in sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path)):
        location = "/".join(str(p) for p in err.absolute_path) or "<root>"
        problems.append(f"schema: {location}: {err.message}")
    return problems


#: Evidence strength ordering, weakest first. A derived finding may not exceed the
#: weakest strength among the findings it was derived from.
_STRENGTH_ORDER = [
    "DECLARED_ONLY",
    "INFERRED",
    "CONFIG_DERIVED",
    "STATIC_MATCH",
    "STATIC_DATAFLOW",
    "DIRECT_OBSERVATION",
]
_STRENGTH_RANK = {s: i for i, s in enumerate(_STRENGTH_ORDER)}


def validate_semantics(
    record: dict,
    *,
    check_ids: bool = True,
    corpus: dict[str, dict] | None = None,
) -> list[str]:
    """Cross-field rules that JSON Schema cannot express.

    `corpus` maps record_id -> record for the records this one declares as inputs. When
    supplied, references to findings in those records are resolved rather than merely
    permitted; when omitted, an external reference is accepted only if the record
    declares at least one input record, so a dangling reference in a leaf record is
    still an error.
    """
    problems: list[str] = []
    findings = record.get("findings", [])
    by_id = {f.get("finding_id"): f for f in findings if isinstance(f, dict)}

    declared_inputs = record.get("input_records", [])
    external_ids: set[str] = set()
    external_findings: dict[str, dict] = {}
    if corpus:
        for ref in declared_inputs:
            source = corpus.get(ref.get("record_id"))
            if source is None:
                problems.append(
                    f"input_records: record {ref.get('record_id')} was declared as an "
                    "input but is not present in the supplied corpus"
                )
                continue
            if source.get("content_hash") != ref.get("content_hash"):
                problems.append(
                    f"input_records: record {ref.get('record_id')} content_hash does not "
                    "match the corpus copy — the input has changed since composition"
                )
            for f in source.get("findings", []):
                if "finding_id" in f:
                    external_ids.add(f["finding_id"])
                    external_findings[f["finding_id"]] = f

    def _resolvable(ref: str) -> bool:
        if ref in by_id:
            return True
        if corpus:
            return ref in external_ids
        return bool(declared_inputs)

    if record.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            f"schema_version is {record.get('schema_version')!r}; this build validates "
            f"{SCHEMA_VERSION!r}. See SCHEMA.md for the migration rules."
        )

    ids = [f.get("finding_id") for f in findings]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        problems.append(f"duplicate finding_id(s): {sorted(duplicates)}")

    for f in findings:
        fid = f.get("finding_id", "<missing>")

        if check_ids:
            expected = compute_finding_id(
                source_component=f.get("source_component", ""),
                capability=f.get("capability", ""),
                rule_id=f.get("rule_id", ""),
                rule_version=f.get("rule_version", ""),
                evidence=f.get("evidence", []),
                analysed=f.get("scope", {}).get("analysed", []),
            )
            if fid != expected:
                problems.append(
                    f"finding {fid}: id does not match its derivation (expected {expected}). "
                    "Finding ids are deterministic so that two runs can be diffed."
                )

        # Defence in depth: the schema already forbids this pairing, but records can be
        # constructed programmatically and this is the invariant the whole taxonomy rests on.
        status = parse_status(f.get("status", "UNKNOWN"))
        failed = f.get("scope", {}).get("failed", [])
        if status is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE and failed:
            problems.append(
                f"finding {fid}: status NOT_FOUND_WITHIN_ANALYSED_SCOPE with "
                f"{len(failed)} failed item(s). An incomplete scan is PARTIAL; reporting "
                "it as a completed clean scan overstates what was checked."
            )
        if status is Status.PARTIAL and not failed:
            problems.append(
                f"finding {fid}: status PARTIAL with an empty scope.failed. PARTIAL must "
                "name what was not analysed and why, or it is an unfalsifiable hedge."
            )

        for parent_id in f.get("derived_from") or []:
            parent = by_id.get(parent_id) or external_findings.get(parent_id)
            if parent is None:
                if corpus is not None:
                    problems.append(
                        f"finding {fid}: derived_from {parent_id!r} could not be resolved "
                        "in this record or in any declared input record. A derived "
                        "finding whose parent cannot be found has no evidence base."
                    )
                else:
                    # Cross-record parents are unresolvable without a corpus. This is a
                    # real limitation rather than a passed check: composing components
                    # must call validate_record(..., corpus=...) so that strength and
                    # incompleteness propagation are actually verified. Recorded in
                    # SCHEMA.md and LIMITATIONS.md.
                    problems.append(
                        f"finding {fid}: derived_from {parent_id!r} is external to this "
                        "record and no corpus was supplied, so strength and "
                        "incompleteness propagation were NOT verified. Re-validate with "
                        "corpus= to check them."
                    )
                continue
            child_rank = _STRENGTH_RANK.get(f.get("evidence_strength"), -1)
            parent_rank = _STRENGTH_RANK.get(parent.get("evidence_strength"), -1)
            if child_rank > parent_rank:
                problems.append(
                    f"finding {fid}: evidence_strength {f.get('evidence_strength')} exceeds "
                    f"that of {parent_id} ({parent.get('evidence_strength')}). A derived "
                    "finding is never stronger than the weakest evidence it rests on."
                )
            if parse_status(parent.get("status", "UNKNOWN")) is Status.PARTIAL and status is (
                Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE
            ):
                problems.append(
                    f"finding {fid}: derived NOT_FOUND_WITHIN_ANALYSED_SCOPE from PARTIAL "
                    f"parent {parent_id}. Incompleteness propagates; it is not discharged "
                    "by re-stating the result downstream."
                )

    declared_count = len(record.get("declared_capabilities", []))
    for c in record.get("contradictions", []):
        for side in c.get("between", []):
            ref = side.get("ref", "")
            if side.get("evidence_kind") == "declared":
                if not (ref.isdigit() and int(ref) < declared_count):
                    problems.append(
                        f"contradiction {c.get('contradiction_id')}: declared ref {ref!r} "
                        "does not index declared_capabilities"
                    )
            elif not _resolvable(ref):
                problems.append(
                    f"contradiction {c.get('contradiction_id')}: ref {ref!r} is not a "
                    "finding_id in this record or in any declared input record"
                )

    for m in record.get("mitigations", []):
        for tid in m.get("triggering_finding_ids", []):
            if not _resolvable(tid):
                problems.append(
                    f"mitigation {m.get('mitigation_id')}: triggering finding {tid!r} is "
                    "not present in this record or in any declared input record. A "
                    "mitigation must point at evidence."
                )

    expected_hash = compute_content_hash(record)
    if record.get("content_hash") != expected_hash:
        problems.append(
            f"content_hash does not reproduce (recorded {record.get('content_hash')}, "
            f"recomputed {expected_hash}). The record has been edited after sealing, or "
            "was never sealed."
        )
    else:
        expected_rid = compute_record_id(record, expected_hash)
        if record.get("record_id") != expected_rid:
            problems.append(
                f"record_id does not reproduce (recorded {record.get('record_id')}, "
                f"recomputed {expected_rid})"
            )

    return problems


def validate_record(
    record: dict, *, check_ids: bool = True, corpus: dict[str, dict] | None = None
) -> None:
    """Validate structure and semantics. Raises SchemaValidationError listing every problem."""
    problems = validate_structure(record)
    problems += validate_semantics(record, check_ids=check_ids, corpus=corpus)
    if problems:
        raise SchemaValidationError(problems)


def load_record(path: str | Path, *, validate: bool = True) -> dict:
    record = json.loads(Path(path).read_text(encoding="utf-8"))
    if validate:
        validate_record(record)
    return record
