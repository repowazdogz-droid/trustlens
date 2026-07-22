"""The five-state analysis status taxonomy, and the rules that keep the five states apart.

The central failure this module exists to prevent: a check that could not complete
being reported, or consumed, as a check that completed and found nothing. Those are
different claims. `PARTIAL` says "I did not finish looking". `NOT_FOUND_WITHIN_ANALYSED_SCOPE`
says "I finished looking here and saw nothing here". Only the second one bounds anything,
and even then it bounds the scope rather than the artifact.

Three mechanisms enforce the distinction, so that it survives contact with code written
later by someone who has not read this docstring:

1. `Status` is not a `str` subclass, and comparing it to a `str` raises rather than
   returning False. Downstream code that reaches for `finding["status"] == "NOT_FOUND..."`
   fails loudly at the point of the mistake instead of silently taking the False branch.
2. `combine()` implements a precedence lattice in which
   `NOT_FOUND_WITHIN_ANALYSED_SCOPE` is the weakest element. Combining anything with a
   `PARTIAL` yields `PARTIAL`. A clean aggregate is reachable only when every input was
   clean.
3. `absence_within_scope()` is the only sanctioned way to ask "may I treat this as
   absence?", and `require_complete_scope()` raises `IncompleteAnalysisError` when a
   caller tries to consume an incomplete result as a complete one.
"""

from __future__ import annotations

import enum
from typing import Iterable


class StatusComparisonError(TypeError):
    """Raised when a Status is compared against a raw string.

    This is deliberately noisy. A silent False here is exactly the bug this module
    exists to prevent, because the False branch is usually the "treat as absent" branch.
    """


class IncompleteAnalysisError(RuntimeError):
    """Raised when an incomplete result is consumed as though analysis had completed."""


@enum.unique
class Status(enum.Enum):
    """The five states. Not four, and not a boolean."""

    FOUND = "FOUND"
    NOT_FOUND_WITHIN_ANALYSED_SCOPE = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            raise StatusComparisonError(
                f"Refusing to compare Status.{self.name} with the string {other!r}. "
                "String comparison against a status silently returns False and the "
                "False branch is usually the 'treat as absent' branch. Use "
                "Status(...) to parse, or trustlens.evidence.status.absence_within_scope()."
            )
        return self is other

    def __ne__(self, other: object) -> bool:
        if isinstance(other, str):
            raise StatusComparisonError(
                f"Refusing to compare Status.{self.name} with the string {other!r}."
            )
        return self is not other

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return self.value


#: Precedence, strongest claim first. `combine` returns the highest-precedence input.
#:
#: The ordering is not a severity ranking. It is an information ordering chosen so that
#: aggregation is fail-closed with respect to absence: NOT_FOUND_WITHIN_ANALYSED_SCOPE is
#: last, so an aggregate can only claim a clean scope when every constituent claimed one.
#: UNKNOWN outranks UNSUPPORTED because "we do not know whether this was examined" is
#: weaker information than "we know this cannot be examined".
_PRECEDENCE: tuple[Status, ...] = (
    Status.FOUND,
    Status.PARTIAL,
    Status.UNKNOWN,
    Status.UNSUPPORTED,
    Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE,
)

_RANK = {s: i for i, s in enumerate(_PRECEDENCE)}


def parse(value: str | Status) -> Status:
    """Parse a wire-format status string into a Status, rejecting anything unrecognised."""
    if isinstance(value, Status):
        return value
    try:
        return Status(value)
    except ValueError as exc:
        raise ValueError(
            f"{value!r} is not one of the five TrustLens statuses: "
            f"{[s.value for s in Status]}"
        ) from exc


def combine(statuses: Iterable[Status | str]) -> Status:
    """Aggregate several results about the same capability into one.

    Returns the highest-precedence input. Notably `combine([PARTIAL, NOT_FOUND...])`
    is `PARTIAL`: one file that failed to parse contaminates the whole aggregate, which
    is the correct and conservative outcome. An empty input is UNKNOWN, never clean.
    """
    parsed = [parse(s) for s in statuses]
    if not parsed:
        return Status.UNKNOWN
    return min(parsed, key=lambda s: _RANK[s])


def absence_within_scope(status: Status | str) -> bool:
    """The only sanctioned predicate for "may this be read as absence?".

    True only for NOT_FOUND_WITHIN_ANALYSED_SCOPE, and even then the absence is bounded
    by the finding's recorded scope. No status in this taxonomy ever establishes that a
    capability is absent from the artifact.
    """
    return parse(status) is Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE


def require_complete_scope(status: Status | str, *, context: str) -> Status:
    """Assert that a result may be consumed as a completed analysis.

    Raises IncompleteAnalysisError for PARTIAL, UNSUPPORTED and UNKNOWN. Call this at
    any point where downstream logic is about to depend on a check having finished —
    for example before a blast-radius path asserts that a hop does not exist.
    """
    parsed = parse(status)
    if parsed in (Status.FOUND, Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE):
        return parsed
    raise IncompleteAnalysisError(
        f"{context}: analysis status is {parsed.value}, which does not represent a "
        "completed analysis of the intended scope. Consuming it as one would report an "
        "incomplete check as a clean check. Handle it explicitly, or propagate it."
    )


def is_complete(status: Status | str) -> bool:
    """Non-raising form of `require_complete_scope`, for branching rather than asserting."""
    return parse(status) in (Status.FOUND, Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE)
