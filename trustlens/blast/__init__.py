"""Phase 4 — blast radius simulator.

Composes the static (scanner), configured (mapper) and dynamic (sandbox) evidence sources into
reachability paths from an entry point to an asset. Every edge is labelled by how it was
established, and a path is never rendered at a higher confidence than its weakest edge.

`execution_mode: offline_modelling` — this component reads evidence records and composes them.
It acquires nothing, executes nothing, and touches no remote. See
`docs/SPEC_phase4_blast_radius.md`.
"""

from .provenance import (
    EdgeProvenance,
    PathConfidence,
    path_confidence,
    is_blocked_path,
)
from .model import BlastEdge, BlastGraph, BlastPath

__all__ = [
    "BlastEdge",
    "BlastGraph",
    "BlastPath",
    "EdgeProvenance",
    "PathConfidence",
    "is_blocked_path",
    "path_confidence",
]
