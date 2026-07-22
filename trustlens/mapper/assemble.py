"""Assemble the credential reachability record from an offline environment description.

Pure Python. **Spawns no process and contacts nothing** — no cloud API, no cluster, no
credential use. `tests/mapper/test_inertness.py` demonstrates that the same way Phase 1
does. The optional Go RBAC helper is a separate command and is not reachable from here.

The seven inherited invariants are enforced, not assumed:

1. **PARTIAL propagation** — any failed input forces `PARTIAL`, never a clean "no path found".
2. **`description_captured_at` is mandatory**, on the description and on every edge derived
   from it. `Edge.__post_init__` raises without it.
3. **`CONFIG_DERIVED` strength binding** — every finding here uses `config_derivation` or
   `policy_evaluation`, which the schema binds to `CONFIG_DERIVED`. A configured path can
   never carry an observation's weight.
4. **Contradictions recorded, never reconciled.**
5. **Coverage reconciliation** — each ingester declares its capabilities; anything promised
   and undelivered becomes `UNKNOWN` plus a recorded gap.
6. **Inertness.**
7. **Rule liveness** — every `rule_id` has a trigger test.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..evidence import make_evidence, make_finding, make_record, make_scope
from .model import EdgeKind, Graph, Node, NodeKind, Reachability
from . import rbac as rbac_mod
from . import terraform as tf_mod

TOOL_VERSION = "0.1.0"
RULE_VERSION = "0.1.0"

#: Capabilities this component promises to report on. Coverage reconciliation compares this
#: against what was delivered, so a silent non-report becomes UNKNOWN rather than nothing.
DECLARED_CAPABILITIES = (
    "identity.role_assumption",
    "identity.token_use",
    "reachability.resource_access",
    "k8s.serviceaccount_token_access",
    "k8s.api_access",
    "env.credential_pattern_read",
)


#: Every rule that can emit an edge. Used so a clean finding can state how many rules ran,
#: rather than only how many files were read.
_RULE_IDS = (
    "tf-assume-role-principal",
    "tf-irsa-serviceaccount-trust",
    "tf-policy-allow",
    "tf-role-policy-attachment",
    "k8s-binding-subject",
    "k8s-role-rule",
)


class DescriptionError(ValueError):
    """The environment description cannot be used. Never downgraded to a warning."""


@dataclass
class EnvironmentDescription:
    description_id: str
    captured_at: str
    captured_at_basis: str
    content_hash: str
    source_format: str
    terraform_plan: str | None = None
    kubernetes_dir: str | None = None
    asserts: dict = field(default_factory=dict)
    path: str = ""


def load_description(path: Path) -> EnvironmentDescription:
    """Load the description. A missing capture time is fatal, by design.

    The brief makes `description_captured_at` mandatory and requires it surfaced everywhere
    a derived report appears. Defaulting it — to now, to unknown, to anything — would make a
    stale model indistinguishable from a fresh one, so absence is refused outright.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DescriptionError(f"{path}: not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise DescriptionError(f"{path}: {type(exc).__name__}: {exc}") from exc

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise DescriptionError(f"{path}: not valid YAML: {type(exc).__name__}: {exc}") from exc
    if not isinstance(doc, dict):
        raise DescriptionError(f"{path}: description root is not a mapping")

    captured = doc.get("description_captured_at")
    if not captured:
        raise DescriptionError(
            f"{path}: description_captured_at is REQUIRED and is missing. TrustLens will "
            "not default it: a model with an unknown capture time is indistinguishable "
            "from a current one, and every path derived from this description inherits "
            "its age."
        )
    if not isinstance(captured, str):
        # PyYAML parses an unquoted ISO timestamp into a datetime; normalise rather than
        # reject, but keep the requirement that it be present and parseable.
        captured = captured.isoformat() if hasattr(captured, "isoformat") else str(captured)
    try:
        datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DescriptionError(
            f"{path}: description_captured_at {captured!r} is not an ISO 8601 timestamp: {exc}"
        ) from exc

    basis = doc.get("captured_at_basis", "operator_asserted")
    if basis not in ("operator_asserted", "exported_by_tool", "unknown"):
        raise DescriptionError(
            f"{path}: captured_at_basis {basis!r} must be operator_asserted, "
            "exported_by_tool or unknown"
        )

    return EnvironmentDescription(
        description_id=doc.get("description_id") or path.stem,
        captured_at=captured,
        captured_at_basis=basis,
        content_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        source_format=doc.get("source_format", "trustlens_env_v1"),
        terraform_plan=doc.get("terraform_plan"),
        kubernetes_dir=doc.get("kubernetes_manifests"),
        asserts=doc.get("asserts") or {},
        path=path.name,
    )


@dataclass
class MapResult:
    record: dict
    graph: Graph
    coverage_gaps: list[str]

    @property
    def complete(self) -> bool:
        return not self.coverage_gaps and not self.record["scope"]["failed"]


def _env_ref(desc: EnvironmentDescription) -> dict:
    return {
        "description_id": desc.description_id,
        "description_captured_at": desc.captured_at,
        "captured_at_basis": desc.captured_at_basis,
        "description_hash": desc.content_hash,
        "source_format": desc.source_format,
    }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


#: Capabilities declared above for which NO rule in this build can produce an edge.
#: They are reported UNSUPPORTED, not NOT_FOUND — "this component cannot assess the
#: construct at all" is exactly what UNSUPPORTED means, and reporting them clean would be
#: the env.credential_pattern_read failure again: a capability that can never fire looking
#: identical to one that fired and matched nothing.
UNPRODUCIBLE_CAPABILITIES = {
    "identity.token_use": (
        "Token issuance and use are runtime facts. Nothing in a static description "
        "establishes that a token was minted or presented; Phase 3 observation would."
    ),
    "env.credential_pattern_read": (
        "Process environment contents are not part of the Terraform or Kubernetes RBAC "
        "inputs this build ingests. A trustlens_env_v1 process-environment section would "
        "produce it; that section is not implemented."
    ),
}

#: Which capability each edge kind reports under.
_EDGE_CAPABILITY = {
    EdgeKind.CAN_ASSUME: "identity.role_assumption",
    EdgeKind.GRANTS: "identity.role_assumption",
    EdgeKind.POLICY_ALLOWS: "reachability.resource_access",
    EdgeKind.BOUND_TO: "k8s.api_access",
    EdgeKind.CAN_ACCESS: "k8s.api_access",
    EdgeKind.CAN_READ: "k8s.serviceaccount_token_access",
}


def map_credentials(
    description_path: Path,
    *,
    started_at: str | None = None,
    completed_at: str | None = None,
    commit: str | None = None,
) -> MapResult:
    """Build the reachability record. Offline, inert, no credentials."""
    description_path = Path(description_path)
    desc = load_description(description_path)
    base = description_path.parent
    started = started_at or _now()

    graph = Graph()
    analysed: list[str] = [desc.path]
    failed: list[dict] = []
    unknowns: list[dict] = []

    if desc.terraform_plan:
        tf_path = base / desc.terraform_plan
        if tf_path.is_file():
            res = tf_mod.ingest_plan(
                tf_path,
                desc.terraform_plan,
                captured_at=desc.captured_at,
                captured_at_basis=desc.captured_at_basis,
            )
            graph.edges.extend(res.graph.edges)
            analysed += res.analysed
            failed += res.failed
            unknowns += res.unknowns
        else:
            failed.append(
                {
                    "path": desc.terraform_plan,
                    "reason": "referenced by the description but not present on disk",
                    "kind": "io_error",
                }
            )

    if desc.kubernetes_dir:
        k8s_path = base / desc.kubernetes_dir
        if k8s_path.is_dir():
            res = rbac_mod.ingest(
                k8s_path,
                captured_at=desc.captured_at,
                captured_at_basis=desc.captured_at_basis,
            )
            graph.edges.extend(res.graph.edges)
            analysed += [f"{desc.kubernetes_dir}/{a}" for a in res.analysed]
            failed += [{**f, "path": f"{desc.kubernetes_dir}/{f['path']}"} for f in res.failed]
            unknowns += res.unknowns
        else:
            failed.append(
                {
                    "path": desc.kubernetes_dir,
                    "reason": "referenced by the description but not present on disk",
                    "kind": "io_error",
                }
            )

    scope = make_scope(
        analysed=sorted(set(analysed)),
        languages=["trustlens_env_v1", "terraform_plan", "kubernetes_manifest"],
        excluded=[],
        failed=failed,
    )

    # --- findings, one per declared capability, always emitted
    by_capability: dict[str, list] = {c: [] for c in DECLARED_CAPABILITIES}
    for edge in graph.sorted_edges():
        cap = _EDGE_CAPABILITY.get(edge.kind)
        if cap:
            by_capability.setdefault(cap, []).append(edge)

    producible_rules = sorted({r for r in _RULE_IDS})
    findings = []
    for capability in sorted(by_capability):
        edges = by_capability[capability]
        if capability in UNPRODUCIBLE_CAPABILITIES and not edges:
            findings.append(
                make_finding(
                    capability=capability,
                    status="UNSUPPORTED",
                    detection_method="config_derivation",
                    rule_id=f"credential-mapper:{capability}",
                    rule_version=RULE_VERSION,
                    source_component="credential_mapper",
                    scope=scope,
                    environment_description_ref=_env_ref(desc),
                    unsupported_construct=UNPRODUCIBLE_CAPABILITIES[capability],
                    confidence_basis=(
                        "No rule in this build can produce an edge for this capability, so "
                        "it is reported as unassessed rather than as clean. Reporting it "
                        "NOT_FOUND would make a capability that can never fire "
                        "indistinguishable from one that fired and matched nothing."
                    ),
                    limitations=[
                        "This is an absence of analysis, not a result. It must not be read "
                        "as evidence that the capability is absent from the environment.",
                    ],
                )
            )
            continue
        status = "FOUND" if edges else ("PARTIAL" if failed else "NOT_FOUND_WITHIN_ANALYSED_SCOPE")
        rule_ids = sorted({e.rule_id for e in edges})
        findings.append(
            make_finding(
                capability=capability,
                status=status,
                detection_method="config_derivation",
                rule_id=f"credential-mapper:{capability}",
                rule_version=RULE_VERSION,
                source_component="credential_mapper",
                scope=scope,
                environment_description_ref=_env_ref(desc),
                evidence=[
                    make_evidence(
                        kind="config_key",
                        path=e.evidence_path,
                        line=None,
                        pointer=e.evidence_pointer,
                        excerpt=e.evidence_excerpt,
                        detail=(
                            f"{e.source.key} --{e.kind.value}--> {e.target.key} "
                            f"[{e.reachability.value}; rule={e.rule_id}; "
                            f"captured {desc.captured_at}]"
                        ),
                    )
                    for e in edges
                ],
                confidence_basis=(
                    f"{len(edges)} configured edge(s) derived by {len(rule_ids)} rule(s) "
                    f"({', '.join(rule_ids)}) from a description captured "
                    f"{desc.captured_at} ({desc.captured_at_basis})."
                    if edges
                    else (
                        f"None of the {len(producible_rules)} edge rule(s) in this build "
                        f"produced an edge for this capability across {len(set(analysed))} "
                        f"input(s), from a description captured {desc.captured_at}."
                    )
                ),
                limitations=[
                    "Derived from a supplied description; it is only as accurate as that "
                    "description and only as current as its capture time.",
                    "Does not establish that any credential is valid, unexpired, or in use.",
                    "Does not establish that a reachable service is exploitable.",
                    "A path absent from this model is not thereby impossible.",
                ],
            )
        )

    delivered = {f["capability"] for f in findings}
    coverage_gaps = sorted(set(DECLARED_CAPABILITIES) - delivered)

    # An operator assertion IS a declaration about a capability, so it belongs in
    # declared_capabilities. That also makes the contradiction structurally correct:
    # declared-versus-configured, with the declared side indexable.
    _ASSERTION_CAPABILITY = {
        "no_cloud_role_assumption": "identity.role_assumption",
        "no_secret_access": "k8s.serviceaccount_token_access",
    }
    declared_capabilities = []
    assertion_index: dict[str, int] = {}
    for key, asserted in sorted(desc.asserts.items()):
        capability = _ASSERTION_CAPABILITY.get(key)
        if capability is None or asserted is not True:
            continue
        assertion_index[key] = len(declared_capabilities)
        declared_capabilities.append(
            {
                "capability": capability,
                "declaration": "explicitly_absent",
                "declared_by": "operator_statement",
                "source": make_evidence(
                    kind="config_key",
                    path=desc.path,
                    line=None,
                    pointer=f"/asserts/{key}",
                    excerpt=f"{key}: true",
                ),
                "verbatim": f"{key}: true",
                "extraction_rule_id": "env-operator-assertion",
                "extraction_rule_version": RULE_VERSION,
            }
        )

    # --- contradictions between what the description asserts and what the inputs imply
    contradictions = []
    for key, asserted in sorted(desc.asserts.items()):
        implied = _check_assertion(key, asserted, graph)
        if implied is None or key not in assertion_index:
            continue
        contradictions.append(
            {
                "contradiction_id": f"ENV-{key}",
                "summary": (
                    f"The description asserts {key} = {asserted!r}, but the supplied "
                    f"configuration implies otherwise: {implied['why']}"
                ),
                "between": [
                    {
                        "evidence_kind": "declared",
                        "ref": str(assertion_index[key]),
                        "assertion": f"{key} = {asserted!r} (operator assertion)",
                    },
                    {
                        "evidence_kind": "configured",
                        "ref": implied["finding_id"](findings),
                        "assertion": implied["why"],
                    },
                ],
                "reconciled": False,
                "capability": implied["capability"],
            }
        )

    record = make_record(
        component="credential_mapper",
        tool_version=TOOL_VERSION,
        commit=commit,
        artifact={
            "artifact_id": desc.description_id,
            "artifact_type": "environment_description",
            "declared_kind": None,
            "source": desc.path,
            "immutable_reference": None,
            "acquisition_method": "user_supplied_path",
            "acquisition_authorised_by": None,
            "acquired_at": started,
            "content_hash": desc.content_hash,
            "content_hash_method": "file_bytes",
            "file_count": len(set(analysed)),
            "total_bytes": 0,
        },
        run={
            "started_at": started,
            "completed_at": completed_at or _now(),
            "execution_mode": "offline_modelling",
            "invocation": f"trustlens map-credentials {desc.path}",
            "config_hash": None,
            "reasoning_notes": [
                "Offline modelling only: no cloud API, no cluster, no credential was used.",
                f"Environment description captured {desc.captured_at} "
                f"({desc.captured_at_basis}); every edge below inherits that age.",
                f"{len(graph.edges)} edge(s) built across {len(set(analysed))} input(s).",
            ],
        },
        scope=scope,
        declared_capabilities=declared_capabilities,
        findings=findings,
        contradictions=contradictions,
        unknowns=unknowns,
        residual_uncertainty=(
            f"Every path in this record is derived from a description captured "
            f"{desc.captured_at} ({desc.captured_at_basis}), which TrustLens cannot verify. "
            + (
                f"{len(failed)} input(s) could not be read, so the model is incomplete. "
                if failed
                else ""
            )
            + "No result here establishes that a path is absent from the real environment."
        ),
        claims={
            "establishes": [
                "The configured reachability derivable from the supplied descriptions "
                f"under the recorded interpretation rules, as of {desc.captured_at}.",
                "Paths supported by explicit configuration evidence, each citing the file "
                "and pointer it came from.",
                "Contradictions and unknowns found in the supplied model.",
            ],
            "does_not_establish": [
                "That the supplied descriptions match current production.",
                "That any credential is valid, unexpired, or in use.",
                "That any reachable service is exploitable.",
                "That every identity or network path has been modelled.",
                "That a path missing from this model is impossible.",
                "That the environment is secure.",
            ],
        },
        environment_description_ref=_env_ref(desc),
        sandbox=None,
    )

    return MapResult(record=record, graph=graph, coverage_gaps=coverage_gaps)


def _check_assertion(key: str, asserted, graph: Graph) -> dict | None:
    """Compare an operator assertion against what the supplied configuration implies."""
    if key == "no_cloud_role_assumption" and asserted is True:
        edges = [e for e in graph.sorted_edges() if e.kind == EdgeKind.CAN_ASSUME]
        if edges:
            return {
                "why": (
                    f"{len(edges)} role-assumption edge(s) are configured, e.g. "
                    f"{edges[0].source.key} can assume {edges[0].target.key}"
                ),
                "capability": "identity.role_assumption",
                "finding_id": lambda fs: next(
                    f["finding_id"] for f in fs if f["capability"] == "identity.role_assumption"
                ),
            }
    if key == "no_secret_access" and asserted is True:
        edges = [e for e in graph.sorted_edges() if e.kind == EdgeKind.CAN_READ]
        if edges:
            return {
                "why": (
                    f"{len(edges)} secret-read edge(s) are configured, e.g. "
                    f"{edges[0].source.key} can read {edges[0].target.key}"
                ),
                "capability": "k8s.serviceaccount_token_access",
                "finding_id": lambda fs: next(
                    f["finding_id"]
                    for f in fs
                    if f["capability"] == "k8s.serviceaccount_token_access"
                ),
            }
    return None
