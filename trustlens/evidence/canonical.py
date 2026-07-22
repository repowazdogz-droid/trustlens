"""Canonical serialisation, record hashing and deterministic identifiers.

Determinism is the point. Two runs over the same artifact with the same tool version
and the same rules must produce byte-identical canonical bodies and therefore identical
`content_hash` values, so that a reader can tell "the evidence is unchanged" from
"the evidence happens to look similar".

Floating-point values are rejected rather than serialised. A float's shortest
round-trip representation is not identical across languages, so admitting one would make
the hash unreproducible by an independent implementation — which would quietly remove the
only property that makes the hash worth computing.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any


class NonCanonicalValueError(TypeError):
    """Raised when a value cannot be canonically serialised."""


def _reject_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise NonCanonicalValueError(
            f"Floating-point value at {path}: {obj!r}. TrustLens records use integers "
            "or strings so that record hashes are reproducible across languages. "
            "Represent the quantity as an integer (e.g. milliseconds) or a string."
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise NonCanonicalValueError(f"Non-string object key at {path}: {k!r}")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")


def canonical_bytes(obj: Any) -> bytes:
    """Serialise to the canonical form: sorted keys, no insignificant whitespace, UTF-8."""
    _reject_floats(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: Fields excluded from the canonical body.
#:
#: `record_id` and `content_hash` are derived from the body and cannot be inputs to it.
#: `run.completed_at` is excluded so that two runs producing identical evidence produce
#: identical `content_hash` values despite differing wall-clock durations. `run.started_at`
#: is deliberately NOT excluded from the body of a *record_id* computation — see below.
_EXCLUDED_TOP_LEVEL = ("record_id", "content_hash")


def canonical_body(record: dict) -> dict:
    """Return the record stripped of its derived fields, ready for hashing."""
    body = copy.deepcopy(record)
    for key in _EXCLUDED_TOP_LEVEL:
        body.pop(key, None)
    run = body.get("run")
    if isinstance(run, dict):
        run.pop("completed_at", None)
    return body


def compute_content_hash(record: dict) -> str:
    """SHA-256 over the canonical body. Identical evidence yields an identical value."""
    return sha256_hex(canonical_bytes(canonical_body(record)))


def compute_record_id(record: dict, content_hash: str | None = None) -> str:
    """Identify this particular run.

    Distinct from `content_hash`: two runs producing identical evidence share a
    `content_hash` (that is what makes reproduction checkable) but have different
    `record_id` values because they started at different times.
    """
    ch = content_hash if content_hash is not None else compute_content_hash(record)
    started = record.get("run", {}).get("started_at", "")
    return sha256_hex(f"{ch}{started}".encode("utf-8"))[:32]


def seal(record: dict) -> dict:
    """Populate `content_hash` and `record_id` in place, returning the record."""
    ch = compute_content_hash(record)
    record["content_hash"] = ch
    record["record_id"] = compute_record_id(record, ch)
    return record


def _normalise_evidence(evidence: list[dict]) -> list[list]:
    """Order-insensitive, presentation-insensitive projection of evidence locations.

    Only the coordinates participate, not the excerpt: re-running against the same file
    must produce the same finding id even if the excerpt window changes.
    """
    projected = [
        [e.get("kind"), e.get("path"), e.get("line"), e.get("pointer"), e.get("detail")]
        for e in evidence
    ]
    return sorted(projected, key=lambda row: json.dumps(row, sort_keys=True))


def compute_finding_id(
    *,
    source_component: str,
    capability: str,
    rule_id: str,
    rule_version: str,
    evidence: list[dict],
    analysed: list[str],
) -> str:
    """Deterministic finding id: `<component>:<capability>:<16 hex>`.

    The digest covers the rule that fired, the capability claimed, the evidence
    coordinates and the analysed scope. Scope participates deliberately: the same rule
    reporting a clean result over a different set of files is a different finding, and
    collapsing the two would let a narrowed scope masquerade as an unchanged result.
    """
    payload = {
        "source_component": source_component,
        "capability": capability,
        "rule_id": rule_id,
        "rule_version": rule_version,
        "evidence": _normalise_evidence(evidence),
        "analysed": sorted(analysed),
    }
    digest = sha256_hex(canonical_bytes(payload))[:16]
    return f"{source_component}:{capability}:{digest}"
