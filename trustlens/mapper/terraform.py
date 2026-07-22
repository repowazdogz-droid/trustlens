"""Ingest a Terraform / OpenTofu plan JSON into typed reachability edges.

Written against a **real generated plan**, not a hand-written fixture
(`tests/fixtures/mapper/real_terraform/PROVENANCE.md`). That decision caught two things
immediately that a hand-written fixture would have encoded wrong:

* **`format_version` is `1.2`**, where Phase 0's grounding note recorded the format as
  `1.0`. A fixture written from the note would have pinned the wrong version.
* **`policy` is a JSON *string*, not a nested object.** `jsonencode(...)` in the config
  becomes a string in the plan, so the parser must decode twice. A hand-written fixture
  would most likely have embedded a dict, and the double-decode bug would have shipped.

Everything here is offline. No provider is contacted, no state is refreshed, no credential
is used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .model import Edge, EdgeKind, Graph, Node, NodeKind, Reachability

RULE_VERSION = "0.1.0"

#: Plan format versions this parser has been exercised against. An unrecognised version is
#: recorded as an unknown rather than parsed optimistically, because the whole point of
#: using a real plan was to stop guessing at the format.
KNOWN_FORMAT_VERSIONS = ("1.0", "1.1", "1.2")


@dataclass
class IngestResult:
    graph: Graph
    analysed: list[str]
    failed: list[dict]
    unknowns: list[dict]


def _fail(path: str, kind: str, reason: str) -> dict:
    return {"path": path, "reason": reason, "kind": kind}


def _decode_policy(raw, path: str, pointer: str) -> tuple[dict | None, dict | None]:
    """Decode an IAM policy document, which arrives as a JSON string in a real plan."""
    if isinstance(raw, dict):
        return raw, None
    if not isinstance(raw, str):
        return None, _fail(
            path, "parse_error", f"{pointer}: policy is {type(raw).__name__}, not a string or object"
        )
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, _fail(path, "parse_error", f"{pointer}: policy is not valid JSON: {exc}")
    if not isinstance(decoded, dict):
        return None, _fail(
            path, "parse_error", f"{pointer}: decoded policy is {type(decoded).__name__}, not an object"
        )
    return decoded, None


def _statements(policy: dict) -> list[dict]:
    stmt = policy.get("Statement")
    if isinstance(stmt, dict):
        return [stmt]
    return [s for s in stmt or [] if isinstance(s, dict)]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [v for v in value if isinstance(v, str)]


def ingest_plan(
    path: Path,
    rel: str,
    *,
    captured_at: str,
    captured_at_basis: str,
) -> IngestResult:
    """Parse a plan JSON into edges. Never contacts a provider."""
    graph = Graph()
    failed: list[dict] = []
    unknowns: list[dict] = []

    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return IngestResult(graph, [], [_fail(rel, "decode_error", f"UnicodeDecodeError: {exc}")], [])
    except OSError as exc:
        return IngestResult(graph, [], [_fail(rel, "io_error", f"{type(exc).__name__}: {exc}")], [])

    try:
        plan = json.loads(text)
    except json.JSONDecodeError as exc:
        return IngestResult(graph, [], [_fail(rel, "parse_error", f"JSONDecodeError: {exc}")], [])
    if not isinstance(plan, dict):
        return IngestResult(
            graph, [], [_fail(rel, "parse_error", "plan root is not a JSON object")], []
        )

    version = plan.get("format_version")
    if version not in KNOWN_FORMAT_VERSIONS:
        unknowns.append(
            {
                "subject": f"Terraform plan format version {version!r} in {rel}",
                "reason": (
                    f"this parser has been exercised against {', '.join(KNOWN_FORMAT_VERSIONS)}. "
                    "An unrecognised version is parsed on a best-effort basis and fields may "
                    "have moved."
                ),
                "would_be_resolved_by": "Exercising the parser against a real plan of this version.",
            }
        )

    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        return IngestResult(
            graph,
            [],
            [_fail(rel, "parse_error", "plan has no resource_changes array")],
            unknowns,
        )

    limits = (
        "Derived from a plan, which describes intended state. It does not establish that "
        "the resource exists or that the grant is in effect.",
        "Only the supplied plan is considered. Service control policies, permission "
        "boundaries and resource policies not present here were not evaluated.",
    )

    roles: dict[str, Node] = {}
    policies: dict[str, tuple[Node, dict]] = {}

    # --- pass 1: roles and policy documents
    for i, change in enumerate(changes):
        if not isinstance(change, dict):
            continue
        rtype, rname = change.get("type"), change.get("name")
        after = (change.get("change") or {}).get("after") or {}
        pointer = f"/resource_changes/{i}"

        if rtype == "aws_iam_role":
            node = Node(NodeKind.IAM_ROLE, after.get("name") or rname or f"role-{i}")
            roles[f"{rtype}.{rname}"] = node
            assume, err = _decode_policy(after.get("assume_role_policy"), rel, f"{pointer}/assume_role_policy")
            if err:
                failed.append(err)
            elif assume:
                for j, stmt in enumerate(_statements(assume)):
                    # The cross-domain link. An IRSA / workload-identity trust policy
                    # names the Kubernetes service account in a `:sub` condition:
                    #   "oidc...:sub": "system:serviceaccount:<namespace>:<name>"
                    # That condition IS the K8s->IAM edge, and dropping it would leave the
                    # federated principal looking far broader than it is.
                    for cond_op, cond_map in (stmt.get("Condition") or {}).items():
                        if not isinstance(cond_map, dict):
                            continue
                        for cond_key, cond_val in cond_map.items():
                            if not cond_key.endswith(":sub"):
                                continue
                            for sub in _as_list(cond_val):
                                if not sub.startswith("system:serviceaccount:"):
                                    continue
                                parts = sub.split(":")
                                ns, sa = (parts[2], parts[3]) if len(parts) >= 4 else (None, sub)
                                graph.add(
                                    Edge(
                                        source=Node(NodeKind.SERVICE_ACCOUNT, sa, namespace=ns),
                                        target=node,
                                        kind=EdgeKind.CAN_ASSUME,
                                        reachability=Reachability.CONFIGURED,
                                        evidence_path=rel,
                                        evidence_pointer=(
                                            f"{pointer}/assume_role_policy/Statement/{j}"
                                            f"/Condition/{cond_op}/{cond_key}"
                                        ),
                                        evidence_excerpt=f"{cond_op} {cond_key} = {sub}"[:200],
                                        description_captured_at=captured_at,
                                        captured_at_basis=captured_at_basis,
                                        rule_id="tf-irsa-serviceaccount-trust",
                                        limitations=limits
                                        + (
                                            "Establishes that the trust policy names this "
                                            "service account. It does not establish that the "
                                            "service account exists, that the OIDC provider is "
                                            "configured, or that a token is actually issued.",
                                        ),
                                    )
                                )
                    principal = stmt.get("Principal") or {}
                    for ptype, pval in (principal.items() if isinstance(principal, dict) else []):
                        for p in _as_list(pval):
                            graph.add(
                                Edge(
                                    source=Node(NodeKind.FEDERATED_PRINCIPAL, p),
                                    target=node,
                                    kind=EdgeKind.CAN_ASSUME,
                                    reachability=Reachability.CONFIGURED,
                                    evidence_path=rel,
                                    evidence_pointer=f"{pointer}/assume_role_policy/Statement/{j}",
                                    evidence_excerpt=f"{ptype}: {p}"[:200],
                                    description_captured_at=captured_at,
                                    captured_at_basis=captured_at_basis,
                                    rule_id="tf-assume-role-principal",
                                    limitations=limits
                                    + (
                                        "Trust-policy Conditions are recorded but not "
                                        "evaluated; the principal may be narrower than shown.",
                                    ),
                                )
                            )

        elif rtype == "aws_iam_policy":
            node = Node(NodeKind.IAM_POLICY, after.get("name") or rname or f"policy-{i}")
            doc, err = _decode_policy(after.get("policy"), rel, f"{pointer}/policy")
            if err:
                failed.append(err)
                continue
            policies[f"{rtype}.{rname}"] = (node, doc or {})
            for j, stmt in enumerate(_statements(doc or {})):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = _as_list(stmt.get("Action"))
                for resource in _as_list(stmt.get("Resource")):
                    graph.add(
                        Edge(
                            source=node,
                            target=Node(NodeKind.STORAGE_RESOURCE, resource),
                            kind=EdgeKind.POLICY_ALLOWS,
                            reachability=Reachability.CONFIGURED,
                            evidence_path=rel,
                            evidence_pointer=f"{pointer}/policy/Statement/{j}",
                            evidence_excerpt=f"Allow {','.join(sorted(actions))} on {resource}"[:200],
                            description_captured_at=captured_at,
                            captured_at_basis=captured_at_basis,
                            rule_id="tf-policy-allow",
                            limitations=limits
                            + (
                                "Statement Conditions are not evaluated; the grant may be "
                                "narrower in practice.",
                            ),
                        )
                    )

    # --- pass 2: attachments, using configuration references for the join
    config = ((plan.get("configuration") or {}).get("root_module") or {}).get("resources") or []
    for res in config:
        if res.get("type") != "aws_iam_role_policy_attachment":
            continue
        exprs = res.get("expressions") or {}
        role_refs = (exprs.get("role") or {}).get("references") or []
        policy_refs = (exprs.get("policy_arn") or {}).get("references") or []
        # References arrive both as `aws_iam_role.x.name` and bare `aws_iam_role.x`; the
        # bare form is the resource address the other passes keyed on.
        role_key = next((r for r in role_refs if r.count(".") == 1), None)
        policy_key = next((r for r in policy_refs if r.count(".") == 1), None)
        role_node = roles.get(role_key or "")
        policy_entry = policies.get(policy_key or "")
        if role_node and policy_entry:
            graph.add(
                Edge(
                    source=role_node,
                    target=policy_entry[0],
                    kind=EdgeKind.GRANTS,
                    reachability=Reachability.CONFIGURED,
                    evidence_path=rel,
                    evidence_pointer=f"/configuration/root_module/resources[{res.get('name')}]",
                    evidence_excerpt=f"{role_key} <- {policy_key}"[:200],
                    description_captured_at=captured_at,
                    captured_at_basis=captured_at_basis,
                    rule_id="tf-role-policy-attachment",
                    limitations=limits,
                )
            )
        else:
            unknowns.append(
                {
                    "subject": f"Policy attachment {res.get('name')} in {rel}",
                    "reason": (
                        "the attachment's role or policy reference could not be resolved to a "
                        "resource in this plan; the grant it creates is not modelled."
                    ),
                    "would_be_resolved_by": "A plan containing both referenced resources.",
                }
            )

    return IngestResult(graph=graph, analysed=[rel], failed=failed, unknowns=unknowns)
