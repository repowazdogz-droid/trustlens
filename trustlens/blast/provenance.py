"""Edge provenance labels and the weakest-link confidence rule.

This module holds the one invariant Phase 4 exists to enforce: **a path is rendered at the
confidence of its weakest edge.** Everything else in the phase composes edges; this decides how
strongly the composition may be stated.

The labels answer "how was this edge established?", and they carry a confidence rank. A path's
rank is the *minimum* over its edges — one `inferred` edge caps an otherwise fully-observed
path at `inferred`. This is not tunable. It is the barrier between a composed guess and a
measurement.
"""

from __future__ import annotations

import enum


@enum.unique
class EdgeProvenance(enum.Enum):
    """How a single edge in the blast-radius graph was established.

    Not a `str` enum, and string comparison raises — the same guard `Status` uses, for the same
    reason: a silent `False` when someone writes `edge.provenance == "inferred"` would usually
    land on the branch that treats a weak edge as a strong one.
    """

    DECLARED = "declared"
    STATICALLY_FOUND = "statically_found"
    CONFIGURED = "configured"
    INFERRED = "inferred"
    DYNAMICALLY_OBSERVED = "dynamically_observed"
    DYNAMICALLY_BLOCKED = "dynamically_blocked"
    UNKNOWN = "unknown"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            raise TypeError(
                f"Refusing to compare EdgeProvenance.{self.name} with the string {other!r}. "
                "A silent False here is usually the branch that treats a weak edge as strong. "
                "Use EdgeProvenance(...) to parse."
            )
        return self is other

    def __hash__(self) -> int:
        return hash(self.value)


#: Confidence rank for LIVE (unblocked) edges. Higher = stronger evidence the hop is real and
#: traversable. `DYNAMICALLY_BLOCKED` is deliberately absent: it is a NEGATIVE observation and
#: is handled separately by `is_blocked_path`, not placed on this positive scale.
_RANK: dict[EdgeProvenance, int] = {
    EdgeProvenance.DYNAMICALLY_OBSERVED: 5,
    EdgeProvenance.CONFIGURED: 4,
    EdgeProvenance.STATICALLY_FOUND: 3,
    EdgeProvenance.DECLARED: 2,
    EdgeProvenance.INFERRED: 1,
    EdgeProvenance.UNKNOWN: 0,
}


@enum.unique
class PathConfidence(enum.Enum):
    """The render tier of a whole path — the weakest-link label, plus the blocked case.

    Ordered strongest to weakest. A path never renders above its computed tier, and the
    renderer never gives two tiers the same visual weight (`render.py`).
    """

    OBSERVED = "observed"                     # every edge dynamically observed
    CONFIGURATION_DERIVED = "configuration_derived"
    STATICALLY_DERIVED = "statically_derived"
    DECLARED = "declared"
    INFERRED = "inferred"                     # at least one composed/deduced edge
    UNKNOWN = "unknown"
    BLOCKED = "blocked"                       # at least one edge observed to be refused


_RANK_TO_CONFIDENCE = {
    5: PathConfidence.OBSERVED,
    4: PathConfidence.CONFIGURATION_DERIVED,
    3: PathConfidence.STATICALLY_DERIVED,
    2: PathConfidence.DECLARED,
    1: PathConfidence.INFERRED,
    0: PathConfidence.UNKNOWN,
}


def is_blocked_path(provenances: list[EdgeProvenance]) -> bool:
    """True if any edge was observed to be refused. Such a path is cut, not live."""
    return EdgeProvenance.DYNAMICALLY_BLOCKED in provenances


def path_confidence(provenances: list[EdgeProvenance]) -> PathConfidence:
    """The render tier for a path, from its edge provenances.

    The whole invariant, in one function:

    * an empty path has no evidence at all → UNKNOWN;
    * any blocked edge → BLOCKED (a cut path, retained and labelled, never a live path);
    * otherwise the tier is the WEAKEST edge's rank. Not the average, not the strongest —
      the minimum, so a single inferred edge caps the path at inferred.
    """
    if not provenances:
        return PathConfidence.UNKNOWN
    if is_blocked_path(provenances):
        return PathConfidence.BLOCKED
    weakest = min(_RANK[p] for p in provenances)
    return _RANK_TO_CONFIDENCE[weakest]


def provenance_from_evidence_strength(evidence_strength: str, source_component: str) -> EdgeProvenance:
    """Map an upstream finding's evidence_strength + component to an edge provenance.

    Kept in one place so the mapping is auditable rather than scattered across the combiner.
    """
    # Dynamic observations come only from the sandbox component.
    if source_component == "sandbox":
        if evidence_strength == "DIRECT_OBSERVATION":
            return EdgeProvenance.DYNAMICALLY_OBSERVED
        # A sandbox finding recording a blocked attempt is marked by the combiner explicitly;
        # by strength alone we cannot tell blocked from observed, so default conservatively.
        return EdgeProvenance.DYNAMICALLY_OBSERVED
    mapping = {
        "DIRECT_OBSERVATION": EdgeProvenance.STATICALLY_FOUND,  # static "observation" of code
        "CONFIG_DERIVED": EdgeProvenance.CONFIGURED,
        "INFERRED": EdgeProvenance.INFERRED,
        "DECLARED": EdgeProvenance.DECLARED,
    }
    return mapping.get(evidence_strength, EdgeProvenance.UNKNOWN)
