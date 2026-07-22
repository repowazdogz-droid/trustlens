"""Decode Kubernetes RBAC manifests into typed reachability edges.

Built in TrustLens rather than delegated. Both offline RBAC graph tools were rejected under
the structured-input heuristic and both fail a 20-run determinism test
(`docs/GROUNDING_UPDATE_phase2_rbac.md`). Feeding either requires decoding manifests into
typed objects first — which is this module — after which building the edge set directly is
strictly less work than parsing their non-deterministic DOT back.

Scope, stated rather than implied: this module builds the *graph*. It does not evaluate RBAC
authorisation semantics — aggregation, wildcard precedence, `nonResourceURLs`, subresource
matching. That is what the optional `trustlens rbac` command wraps the upstream authorizer
for, and edges emitted here carry a limitation saying so.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .model import Edge, EdgeKind, Graph, Node, NodeKind, Reachability

RULE_VERSION = "0.1.0"

RBAC_KINDS = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"})

#: Verbs that grant read access to secrets, which is the credential-relevant case.
_READ_VERBS = frozenset({"get", "list", "watch", "*"})


@dataclass
class RbacIngestResult:
    graph: Graph
    analysed: list[str]
    failed: list[dict]
    unknowns: list[dict]


def _fail(path: str, kind: str, reason: str) -> dict:
    return {"path": path, "reason": reason, "kind": kind}


def load_manifests(paths: list[Path], root: Path) -> tuple[list[dict], list[str], list[dict]]:
    """Load RBAC objects from YAML files. Never constructs arbitrary Python.

    Uses `yaml.safe_load_all`; a document carrying a `!!python/...` tag raises and is
    recorded as a failure rather than being constructed. That is the same guarantee the
    Phase 1 scanner makes, and it is not relaxed here.
    """
    objects: list[dict] = []
    analysed: list[str] = []
    failed: list[dict] = []
    for path in paths:
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            failed.append(_fail(rel, "decode_error", f"UnicodeDecodeError: {exc}"))
            continue
        except OSError as exc:
            failed.append(_fail(rel, "io_error", f"{type(exc).__name__}: {exc}"))
            continue
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            failed.append(
                _fail(rel, "parse_error", f"{type(exc).__name__}: {str(exc)[:200]}")
            )
            continue
        found = False
        for doc in docs:
            if isinstance(doc, dict) and doc.get("kind") in RBAC_KINDS:
                doc["__source__"] = rel
                objects.append(doc)
                found = True
        if found:
            analysed.append(rel)
    return objects, analysed, failed


def _name(obj: dict) -> str:
    return ((obj.get("metadata") or {}).get("name")) or "<unnamed>"


def _namespace(obj: dict) -> str | None:
    return (obj.get("metadata") or {}).get("namespace")


def build_graph(
    objects: list[dict], *, captured_at: str, captured_at_basis: str
) -> tuple[Graph, list[dict]]:
    graph = Graph()
    unknowns: list[dict] = []

    roles = {
        (o.get("kind"), _name(o), _namespace(o)): o
        for o in objects
        if o.get("kind") in ("Role", "ClusterRole")
    }

    limits = (
        "Derived from supplied manifests. It does not establish that these objects are "
        "applied to any cluster.",
        "This module builds the graph; it does not evaluate RBAC authorisation semantics "
        "(aggregation, wildcard precedence, subresources). Use the optional `trustlens rbac` "
        "command for an authoritative decision.",
    )

    # --- bindings: subject -> role
    for obj in objects:
        kind = obj.get("kind")
        if kind not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        src = obj["__source__"]
        ns = _namespace(obj)
        ref = obj.get("roleRef") or {}
        role_node = Node(
            NodeKind.K8S_ROLE,
            ref.get("name", "<unknown>"),
            namespace=ns if ref.get("kind") == "Role" else None,
        )
        subjects = obj.get("subjects") or []
        if not subjects:
            unknowns.append(
                {
                    "subject": f"{kind} {_name(obj)} in {src}",
                    "reason": "the binding lists no subjects, so it grants nothing that can be modelled.",
                    "would_be_resolved_by": "A binding with a subjects list.",
                }
            )
        for i, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                continue
            sub_kind = subject.get("kind", "")
            node_kind = (
                NodeKind.SERVICE_ACCOUNT if sub_kind == "ServiceAccount" else NodeKind.PROCESS
            )
            graph.add(
                Edge(
                    source=Node(node_kind, subject.get("name", "<unnamed>"),
                                namespace=subject.get("namespace") or ns),
                    target=role_node,
                    kind=EdgeKind.BOUND_TO,
                    reachability=Reachability.CONFIGURED,
                    evidence_path=src,
                    evidence_pointer=f"/subjects/{i}",
                    evidence_excerpt=f"{kind} {_name(obj)} binds {sub_kind} "
                                     f"{subject.get('name')} to {ref.get('kind')} {ref.get('name')}"[:200],
                    description_captured_at=captured_at,
                    captured_at_basis=captured_at_basis,
                    rule_id="k8s-binding-subject",
                    limitations=limits,
                )
            )

    # --- roles: role -> the resources its rules name
    for (kind, name, ns), obj in sorted(roles.items(), key=lambda kv: str(kv[0])):
        src = obj["__source__"]
        role_node = Node(NodeKind.K8S_ROLE, name, namespace=ns)
        for i, rule in enumerate(obj.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            verbs = [v for v in (rule.get("verbs") or []) if isinstance(v, str)]
            resources = [r for r in (rule.get("resources") or []) if isinstance(r, str)]
            for resource in resources:
                reads_secrets = resource in ("secrets", "*") and any(
                    v in _READ_VERBS for v in verbs
                )
                graph.add(
                    Edge(
                        source=role_node,
                        target=Node(
                            NodeKind.SECRET if reads_secrets else NodeKind.API_ENDPOINT,
                            resource,
                            namespace=ns,
                        ),
                        kind=EdgeKind.CAN_READ if reads_secrets else EdgeKind.CAN_ACCESS,
                        reachability=Reachability.CONFIGURED,
                        evidence_path=src,
                        evidence_pointer=f"/rules/{i}",
                        evidence_excerpt=f"{','.join(sorted(verbs))} on {resource}"[:200],
                        description_captured_at=captured_at,
                        captured_at_basis=captured_at_basis,
                        rule_id="k8s-role-rule",
                        limitations=limits
                        + (
                            "A wildcard verb or resource is recorded literally; its expansion "
                            "against the API surface is not computed here.",
                        ),
                    )
                )
            if resources and not verbs:
                unknowns.append(
                    {
                        "subject": f"{kind} {name} rule {i} in {src}",
                        "reason": "the rule names resources but no verbs, so no access is modelled.",
                        "would_be_resolved_by": "A rule with a verbs list.",
                    }
                )

    return graph, unknowns


def ingest(
    root: Path, *, captured_at: str, captured_at_basis: str, excluded_dirs: set[str] | None = None
) -> RbacIngestResult:
    excluded_dirs = excluded_dirs or {".git", "vendor", "node_modules"}
    root = Path(root)
    paths = [
        p
        for p in sorted(root.rglob("*"))
        if p.is_file()
        and p.suffix in (".yaml", ".yml")
        and not any(part in excluded_dirs for part in p.relative_to(root).parts)
    ]
    objects, analysed, failed = load_manifests(paths, root)
    graph, unknowns = build_graph(
        objects, captured_at=captured_at, captured_at_basis=captured_at_basis
    )
    return RbacIngestResult(graph=graph, analysed=analysed, failed=failed, unknowns=unknowns)
