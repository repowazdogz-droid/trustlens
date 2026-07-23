"""Parse the operator-supplied environment file that drives a blast-radius composition.

The entry point, the assets, which node each capability reaches, and the configured
credential→resource grants are all **operator facts**, not things TrustLens can infer from the
artifact — so they are supplied explicitly in an env file rather than guessed. This is the same
stance the mapper takes: the environment description is operator-asserted, and its capture time
travels with every edge derived from it.
"""

from __future__ import annotations

from ..evidence.status import Status
from ..mapper.model import Node, NodeKind
from .model import BlastEdge
from .provenance import EdgeProvenance


class EnvError(ValueError):
    """Raised when the environment file is missing a field the composition needs."""


def _node(spec: dict, where: str) -> Node:
    try:
        kind = NodeKind(spec["kind"])
    except (KeyError, ValueError) as exc:
        raise EnvError(f"{where}: invalid or missing node 'kind' ({exc})") from None
    if "identifier" not in spec:
        raise EnvError(f"{where}: node has no 'identifier'")
    return Node(kind, spec["identifier"], namespace=spec.get("namespace"))


def parse_env(env: dict) -> dict:
    """Return {entry, assets, capability_targets, configured_edges, environment_description_ref}."""
    if "entry" not in env:
        raise EnvError("env file has no 'entry' node (the compromised principal)")
    entry = _node(env["entry"], "entry")

    assets = [_node(a, f"assets[{i}]") for i, a in enumerate(env.get("assets") or [])]
    if not assets:
        raise EnvError("env file lists no 'assets' — there is nothing to compute a path to")

    capability_targets = {
        cap: _node(spec, f"capability_targets[{cap}]")
        for cap, spec in (env.get("capability_targets") or {}).items()
    }

    env_ref = env.get("environment_description_ref")
    if not env_ref:
        raise EnvError(
            "env file has no 'environment_description_ref'; a composition must record the "
            "description it rests on so staleness travels with it"
        )
    captured_at = env_ref.get("description_captured_at")
    if not captured_at:
        raise EnvError("environment_description_ref has no description_captured_at")

    configured_edges: list[BlastEdge] = []
    for i, spec in enumerate(env.get("configured_edges") or []):
        provenance = EdgeProvenance(spec.get("provenance", "configured"))
        configured_edges.append(
            BlastEdge(
                source=_node(spec["source"], f"configured_edges[{i}].source"),
                target=_node(spec["target"], f"configured_edges[{i}].target"),
                relation=spec.get("relation", "grants"),
                provenance=provenance,
                status=Status(spec.get("status", "FOUND")),
                derived_from=tuple(spec.get("derived_from") or (f"env:configured_edge:{i}",)),
                description_captured_at=spec.get("description_captured_at", captured_at),
                evidence_detail=spec.get("evidence_detail", "operator-declared configured grant"),
                limitations=tuple(spec.get("limitations") or (
                    "Operator-declared configuration; not independently observed.",
                )),
            )
        )

    return {
        "entry": entry,
        "assets": assets,
        "capability_targets": capability_targets,
        "configured_edges": configured_edges,
        "environment_description_ref": env_ref,
        "description_captured_at": captured_at,
    }
