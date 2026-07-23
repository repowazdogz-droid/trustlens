"""The blast-radius graph: provenance-labelled edges, and paths whose confidence is capped.

Reuses the mapper's `Node`/`NodeKind` so the two phases name the same real-world things the
same way (the cross-component identity the Phase 2 tests already guard). Adds an edge type that
carries the Phase 4 provenance label and the five-state status of the finding it came from, and
a path type that computes its own confidence from its edges and cannot be constructed claiming
more.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..evidence.status import Status
from ..mapper.model import Node
from .provenance import EdgeProvenance, PathConfidence, is_blocked_path, path_confidence

#: Completeness ordering for a PATH's status — higher means more fully established. This is a
#: WEAKEST-LINK aggregation, not `combine()`. `combine()` takes the strongest status because it
#: answers "did any source find the capability"; a path asks the opposite question — "is every
#: hop established?" — so one PARTIAL or UNKNOWN edge must degrade the whole path. Using
#: `combine()` here would let a single FOUND edge mask a PARTIAL one, which is exactly the
#: silent-upgrade this project keeps guarding against.
_STATUS_COMPLETENESS = {
    Status.FOUND: 4,
    Status.PARTIAL: 3,
    Status.UNKNOWN: 2,
    Status.UNSUPPORTED: 1,
    Status.NOT_FOUND_WITHIN_ANALYSED_SCOPE: 0,
}


def weakest_status(statuses: list[Status]) -> Status:
    """The least-established status in a chain. A path is FOUND only if every edge is FOUND."""
    if not statuses:
        return Status.UNKNOWN
    return min(statuses, key=lambda s: _STATUS_COMPLETENESS[s])


@dataclass(frozen=True)
class BlastEdge:
    """One hop, labelled by how it was established and by the status of its evidence.

    An edge with no `derived_from` and no limitation is refused at construction: every edge in a
    blast-radius graph is composed from an upstream finding, and every edge has a blind spot.
    """

    source: Node
    target: Node
    relation: str
    provenance: EdgeProvenance
    #: The five-state status of the finding this edge was built from.
    status: Status
    #: Upstream finding ids this edge rests on. Non-empty by construction.
    derived_from: tuple[str, ...]
    #: When the described environment was captured (staleness travels with the edge).
    description_captured_at: str
    evidence_detail: str
    limitations: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, EdgeProvenance):
            raise TypeError("provenance must be an EdgeProvenance, not a raw string")
        if not isinstance(self.status, Status):
            raise TypeError("status must be a Status, not a raw string")
        if not self.derived_from:
            raise ValueError(
                f"edge {self.source.key} -> {self.target.key} rests on no upstream finding. "
                "Every blast-radius edge is composed from evidence; one with no source is a "
                "claim with no basis."
            )
        if not self.limitations:
            raise ValueError(
                f"edge {self.source.key} -> {self.target.key} states no limitation. Every "
                "edge has a blind spot; one claiming none has not had it examined."
            )

    @property
    def is_partial(self) -> bool:
        """A PARTIAL upstream status means the analysis behind this edge did not finish."""
        return self.status is Status.PARTIAL

    @property
    def sort_key(self) -> tuple:
        return (self.source.key, self.relation, self.target.key, self.provenance.value)


@dataclass(frozen=True)
class BlastPath:
    """An ordered chain of edges from an entry to an asset.

    Confidence is COMPUTED from the edges, never supplied. There is no constructor argument that
    lets a caller assert a path is observed; the only way a path is `OBSERVED` is for every edge
    in it to be `dynamically_observed`. That is the weakest-link invariant made structural.
    """

    edges: tuple[BlastEdge, ...]

    def __post_init__(self) -> None:
        if not self.edges:
            raise ValueError("a path with no edges reaches nothing")
        # Edges must actually connect head-to-tail, or this is not a path.
        for a, b in zip(self.edges, self.edges[1:]):
            if a.target != b.source:
                raise ValueError(
                    f"edges do not connect: {a.target.key} != {b.source.key}. A blast path is "
                    "a real chain, not a set of unrelated edges."
                )

    @property
    def entry(self) -> Node:
        return self.edges[0].source

    @property
    def asset(self) -> Node:
        return self.edges[-1].target

    @property
    def provenances(self) -> list[EdgeProvenance]:
        return [e.provenance for e in self.edges]

    @property
    def confidence(self) -> PathConfidence:
        """The render tier: the weakest edge, or BLOCKED. Computed, never asserted."""
        return path_confidence(self.provenances)

    @property
    def is_blocked(self) -> bool:
        return is_blocked_path(self.provenances)

    @property
    def contains_partial(self) -> bool:
        """A path with any PARTIAL edge can never be top-tier — 'inferred OR PARTIAL'."""
        return any(e.is_partial for e in self.edges)

    @property
    def status(self) -> Status:
        """The five-state status of the path: the WEAKEST edge, by completeness.

        Independent of the provenance confidence tier. A path is `FOUND` only when every edge is
        `FOUND`; one PARTIAL or UNKNOWN edge degrades the whole path, because a chain is only as
        established as its least-established hop. See `weakest_status` for why this is not
        `combine()`.
        """
        return weakest_status([e.status for e in self.edges])

    @property
    def weakest_edge(self) -> BlastEdge:
        """The edge that determines the path's confidence — named so a report can point at it."""
        from .provenance import _RANK

        if self.is_blocked:
            return next(e for e in self.edges if e.provenance is EdgeProvenance.DYNAMICALLY_BLOCKED)
        return min(self.edges, key=lambda e: _RANK[e.provenance])

    def render_label(self) -> str:
        """A compact, honest one-line tier label for a path."""
        tier = self.confidence.value
        flags = []
        if self.contains_partial:
            flags.append("PARTIAL")
        if self.status is not Status.FOUND and not self.is_blocked:
            flags.append(self.status.value)
        suffix = f" [{', '.join(flags)}]" if flags else ""
        return f"{tier}{suffix}"

    def derived_from(self) -> list[str]:
        seen: list[str] = []
        for edge in self.edges:
            for fid in edge.derived_from:
                if fid not in seen:
                    seen.append(fid)
        return seen

    def all_limitations(self) -> list[str]:
        base = [
            "Composition does not establish that the path is traversable end to end.",
            "This is a simulation, not a penetration test.",
        ]
        if self.confidence is not PathConfidence.OBSERVED and not self.is_blocked:
            base.insert(0, "No edge in this path was dynamically observed." if not any(
                e.provenance is EdgeProvenance.DYNAMICALLY_OBSERVED for e in self.edges
            ) else "At least one edge in this path was not dynamically observed.")
        edge_lims: list[str] = []
        for edge in self.edges:
            for lim in edge.limitations:
                if lim not in edge_lims:
                    edge_lims.append(lim)
        return base + edge_lims


@dataclass
class BlastGraph:
    """A blast-radius graph. Sorted output everywhere, like the mapper graph."""

    edges: list[BlastEdge] = field(default_factory=list)

    def add(self, edge: BlastEdge) -> None:
        self.edges.append(edge)

    def sorted_edges(self) -> list[BlastEdge]:
        return sorted(self.edges, key=lambda e: e.sort_key)

    def nodes(self) -> list[Node]:
        seen: dict[str, Node] = {}
        for e in self.edges:
            seen.setdefault(e.source.key, e.source)
            seen.setdefault(e.target.key, e.target)
        return [seen[k] for k in sorted(seen)]

    def outgoing(self, node: Node) -> list[BlastEdge]:
        return sorted((e for e in self.edges if e.source == node), key=lambda e: e.sort_key)

    def enumerate_paths(self, entry: Node, asset: Node, *, max_depth: int = 8) -> list[BlastPath]:
        """All simple paths from entry to asset, sorted, bounded in depth.

        Depth-bounded and cycle-free (a node is not revisited within a path). If the bound is
        hit, that is recorded by the caller as a coverage limit — never silently truncated into
        "no path exists".
        """
        paths: list[BlastPath] = []

        def walk(node: Node, chain: list[BlastEdge], visited: frozenset[str]) -> None:
            if len(chain) > max_depth:
                return
            for edge in self.outgoing(node):
                if edge.target.key in visited:
                    continue
                new_chain = chain + [edge]
                if edge.target == asset:
                    paths.append(BlastPath(tuple(new_chain)))
                else:
                    walk(edge.target, new_chain, visited | {edge.target.key})

        walk(entry, [], frozenset({entry.key}))
        return sorted(paths, key=lambda p: tuple(e.sort_key for e in p.edges))

    def depth_bound_was_hit(self, entry: Node, asset: Node, *, max_depth: int = 8) -> bool:
        """Whether any branch reached the depth bound without terminating — a coverage limit."""
        hit = False

        def walk(node: Node, depth: int, visited: frozenset[str]) -> None:
            nonlocal hit
            if depth > max_depth:
                hit = True
                return
            for edge in self.outgoing(node):
                if edge.target.key in visited or edge.target == asset:
                    continue
                walk(edge.target, depth + 1, visited | {edge.target.key})

        walk(entry, 0, frozenset({entry.key}))
        return hit
