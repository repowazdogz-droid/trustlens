"""The headline invariant: a path is never rendered above its weakest edge.

The brief: "paths containing inferred or PARTIAL edges never rendered with the same confidence
as fully observed ones." This file attacks that directly — it builds paths that are observed
everywhere except one edge and confirms the one weak edge caps the whole path. If any of these
regress, a composed guess could be shown as a measurement, which is the exact failure Phase 4
exists to prevent.
"""

from __future__ import annotations

import pytest

from trustlens.evidence.status import Status
from trustlens.mapper.model import Node, NodeKind
from trustlens.blast.model import BlastEdge, BlastPath
from trustlens.blast.provenance import EdgeProvenance, PathConfidence, path_confidence


def _node(name: str) -> Node:
    return Node(NodeKind.PROCESS, name)


def _edge(a: str, b: str, provenance: EdgeProvenance, status: Status = Status.FOUND) -> BlastEdge:
    return BlastEdge(
        source=_node(a), target=_node(b), relation="reaches",
        provenance=provenance, status=status,
        derived_from=(f"src:{a}->{b}",), description_captured_at="2026-01-01T00:00:00+00:00",
        evidence_detail=f"{a} reaches {b}", limitations=("test edge",),
    )


def test_all_observed_path_is_observed():
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.DYNAMICALLY_OBSERVED),
        _edge("b", "c", EdgeProvenance.DYNAMICALLY_OBSERVED),
    ))
    assert path.confidence is PathConfidence.OBSERVED


def test_one_inferred_edge_caps_an_otherwise_observed_path():
    """The core test. Two observed edges and ONE inferred edge → the path is INFERRED, not OBSERVED."""
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.DYNAMICALLY_OBSERVED),
        _edge("b", "c", EdgeProvenance.INFERRED),          # the single weak link
        _edge("c", "d", EdgeProvenance.DYNAMICALLY_OBSERVED),
    ))
    assert path.confidence is PathConfidence.INFERRED, (
        "an inferred edge must cap the path at inferred, no matter how many observed edges "
        "surround it — otherwise a composed guess renders as a measurement"
    )
    assert path.confidence is not PathConfidence.OBSERVED


def test_one_configured_edge_caps_observed_to_configuration_derived():
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.DYNAMICALLY_OBSERVED),
        _edge("b", "c", EdgeProvenance.CONFIGURED),
    ))
    assert path.confidence is PathConfidence.CONFIGURATION_DERIVED


def test_one_unknown_edge_caps_everything_to_unknown():
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.DYNAMICALLY_OBSERVED),
        _edge("b", "c", EdgeProvenance.CONFIGURED),
        _edge("c", "d", EdgeProvenance.UNKNOWN),
    ))
    assert path.confidence is PathConfidence.UNKNOWN


def test_a_blocked_edge_makes_the_whole_path_blocked_regardless_of_strength():
    """A blocked edge cuts the path — it is not a live path even if every other edge is observed."""
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.DYNAMICALLY_OBSERVED),
        _edge("b", "c", EdgeProvenance.DYNAMICALLY_BLOCKED),
        _edge("c", "d", EdgeProvenance.DYNAMICALLY_OBSERVED),
    ))
    assert path.confidence is PathConfidence.BLOCKED
    assert path.is_blocked


def test_a_partial_edge_flags_the_path_partial_and_denies_top_tier():
    """'inferred OR PARTIAL': a PARTIAL upstream status caps the path even if provenance is strong."""
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.DYNAMICALLY_OBSERVED),
        _edge("b", "c", EdgeProvenance.DYNAMICALLY_OBSERVED, status=Status.PARTIAL),
    ))
    assert path.contains_partial
    assert "PARTIAL" in path.render_label(), (
        "a path with a PARTIAL edge must be visibly flagged PARTIAL, so it cannot be read as a "
        "complete observation"
    )
    # And its five-state status is PARTIAL via the lattice, not FOUND.
    assert path.status is Status.PARTIAL


def test_confidence_is_computed_not_settable():
    """There is no way to assert a path is observed; it must be earned by its edges.

    BlastPath takes only edges. This confirms there is no confidence override to abuse.
    """
    import dataclasses

    fields = {f.name for f in dataclasses.fields(BlastPath)}
    assert fields == {"edges"}, (
        f"BlastPath has fields {fields}; a confidence/tier field would let a caller assert a "
        "strength the edges do not support"
    )


def test_render_label_is_honest_about_status_and_partial():
    path = BlastPath((
        _edge("a", "b", EdgeProvenance.CONFIGURED, status=Status.PARTIAL),
    ))
    label = path.render_label()
    assert "configuration_derived" in label
    assert "PARTIAL" in label


def test_empty_provenance_list_is_unknown_not_a_pass():
    assert path_confidence([]) is PathConfidence.UNKNOWN


def test_provenance_refuses_string_comparison():
    with pytest.raises(TypeError):
        _ = EdgeProvenance.INFERRED == "inferred"
