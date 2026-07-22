"""The consumption API downstream components must use to read findings.

Phase 4 combines evidence produced by Phases 1-3. That combination step is where an
incomplete result is most likely to be quietly promoted into a clean one, because the
combining code is far away from the code that knew the parse failed. This module is the
chokepoint: it exposes no way to ask "was this capability found?" that returns a bare
boolean, because a bare boolean has nowhere to put PARTIAL.
"""

from __future__ import annotations

from dataclasses import dataclass

from .status import (
    IncompleteAnalysisError,
    Status,
    absence_within_scope,
    combine,
    parse,
)


@dataclass(frozen=True)
class CapabilityView:
    """Everything known about one capability across a set of records."""

    capability: str
    status: Status
    contributing_finding_ids: tuple[str, ...]
    incomplete_finding_ids: tuple[str, ...]
    strongest_evidence: str | None

    @property
    def may_assume_absent(self) -> bool:
        """True only when every contributing check completed and none found anything.

        A single PARTIAL among the contributors makes this False, which is the whole
        point: absence claimed over an incomplete scan is not absence.
        """
        return absence_within_scope(self.status) and not self.incomplete_finding_ids

    def require_absent(self, *, context: str) -> None:
        if self.may_assume_absent:
            return
        if self.incomplete_finding_ids:
            raise IncompleteAnalysisError(
                f"{context}: cannot treat {self.capability} as absent — "
                f"{len(self.incomplete_finding_ids)} contributing check(s) did not "
                f"complete ({', '.join(self.incomplete_finding_ids)}). Report the path as "
                "PARTIAL rather than closing it."
            )
        raise IncompleteAnalysisError(
            f"{context}: cannot treat {self.capability} as absent — combined status is "
            f"{self.status.value}."
        )


_STRENGTH_ORDER = [
    "DECLARED_ONLY",
    "INFERRED",
    "CONFIG_DERIVED",
    "STATIC_MATCH",
    "STATIC_DATAFLOW",
    "DIRECT_OBSERVATION",
]


class FindingIndex:
    """Read-only view over the findings of one or more evidence records."""

    def __init__(self, records: list[dict]) -> None:
        self._findings: list[dict] = []
        self._records = records
        for record in records:
            self._findings.extend(record.get("findings", []))

    @property
    def findings(self) -> list[dict]:
        return list(self._findings)

    def capabilities(self) -> list[str]:
        return sorted({f["capability"] for f in self._findings})

    def view(self, capability: str) -> CapabilityView:
        matching = [f for f in self._findings if f.get("capability") == capability]
        if not matching:
            # Never invent a clean result for a capability nobody checked.
            return CapabilityView(
                capability=capability,
                status=Status.UNKNOWN,
                contributing_finding_ids=(),
                incomplete_finding_ids=(),
                strongest_evidence=None,
            )
        statuses = [parse(f["status"]) for f in matching]
        incomplete = tuple(
            f["finding_id"]
            for f in matching
            if parse(f["status"]) in (Status.PARTIAL, Status.UNKNOWN, Status.UNSUPPORTED)
        )
        strengths = [
            f.get("evidence_strength")
            for f in matching
            if parse(f["status"]) is Status.FOUND
        ]
        strongest = None
        if strengths:
            strongest = max(strengths, key=lambda s: _STRENGTH_ORDER.index(s))
        return CapabilityView(
            capability=capability,
            status=combine(statuses),
            contributing_finding_ids=tuple(f["finding_id"] for f in matching),
            incomplete_finding_ids=incomplete,
            strongest_evidence=strongest,
        )

    def incomplete(self) -> list[CapabilityView]:
        """Every capability whose evidence is incomplete. Rendered as its own report block."""
        return [
            v
            for v in (self.view(c) for c in self.capabilities())
            if v.incomplete_finding_ids
        ]

    def declared_versus_observed(self, record: dict) -> list[dict]:
        """The comparison the product exists to make, per capability.

        Returns one row per capability that is either declared or observed, carrying the
        declaration, the combined observed status, and whether the two conflict. Rows
        where the observed side is incomplete are marked so that a discrepancy is never
        asserted on the strength of a check that did not finish.
        """
        rows = []
        declared = {d["capability"]: d for d in record.get("declared_capabilities", [])}
        for capability in sorted(set(declared) | set(self.capabilities())):
            view = self.view(capability)
            decl = declared.get(capability)
            declaration = decl["declaration"] if decl else None
            conflict = (
                declaration in ("not_required", "explicitly_absent")
                and view.status is Status.FOUND
            )
            rows.append(
                {
                    "capability": capability,
                    "declared": declaration,
                    "declared_evidence": decl["source"] if decl else None,
                    "observed_status": view.status.value,
                    "evidence_strength": view.strongest_evidence,
                    "structural_discrepancy": conflict,
                    "evidence_incomplete": bool(view.incomplete_finding_ids),
                    "undeclared": declaration is None,
                }
            )
        return rows
