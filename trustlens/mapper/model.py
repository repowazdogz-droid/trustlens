"""Typed nodes and edges for the credential reachability graph.

TrustLens builds this graph itself. Both offline RBAC graph tools were rejected under the
structured-input heuristic (`CONTRIBUTING.md`): calling either requires parsing manifests
into typed objects first, and both return presentation DOT rather than typed edges. Both
also fail a 20-run determinism test.

Two invariants are enforced in this module rather than left to callers:

**Capture time travels with every edge.** An edge derived from a description carries that
description's `description_captured_at`. There is no constructor that omits it, because
staleness here is structural: a reachability claim from a six-month-old description is a
claim about six months ago.

**Iteration order is sorted, always.** The rejected tools are non-deterministic precisely
because they iterate unsorted maps when emitting. That is a caller-side bug, verified in
`rback/render.go`, and this module avoids the whole class by sorting at every emit point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeKind(str, Enum):
    """What a node in the reachability graph is."""

    PROCESS = "process"
    SERVICE_ACCOUNT = "service_account"
    #: A human or external identity named as an RBAC subject. NOT a process: typing a
    #: `kind: User` subject as one produces edges reading "a process can do X" about a
    #: person, which is a different security claim.
    USER = "user"
    GROUP = "group"
    #: An external identity provider named in a trust policy. NOT a service
    #: account: typing an OIDC provider ARN as one would let a cross-domain join
    #: match on a name that means something else.
    FEDERATED_PRINCIPAL = "federated_principal"
    ENV_VAR = "environment_variable"
    FILE = "file"
    SECRET = "secret"
    TOKEN = "token"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    STORAGE_RESOURCE = "storage_resource"
    #: A wildcard in a policy Resource field. NOT a resource: "*" means EVERY resource, and
    #: typing it as one makes a path to everything render identically to a path to one
    #: specific bucket — the most consequential of the three conflations found.
    WILDCARD_RESOURCE = "wildcard_resource"
    API_ENDPOINT = "api_endpoint"
    #: A NAMESPACED Kubernetes Role. Distinct from a ClusterRole below: they are different
    #: object types, and distinguishing them only by whether a namespace field happens to
    #: be None is the same conflation that briefly typed an OIDC provider as a service
    #: account. A namespaced Role and a cluster-scoped role of the same name are not the
    #: same grant.
    K8S_ROLE = "k8s_role"
    K8S_CLUSTER_ROLE = "k8s_cluster_role"
    K8S_NAMESPACE = "k8s_namespace"
    NETWORK_SEGMENT = "network_segment"


class EdgeKind(str, Enum):
    """What relation an edge asserts. Deliberately narrow; add rather than overload."""

    CAN_READ = "can_read"
    CAN_INHERIT = "can_inherit"
    CAN_ASSUME = "can_assume"
    CAN_AUTHENTICATE_TO = "can_authenticate_to"
    CAN_ACCESS = "can_access"
    CAN_LIST = "can_list"
    CAN_WRITE = "can_write"
    CAN_IMPERSONATE = "can_impersonate"
    BOUND_TO = "bound_to"
    GRANTS = "grants"
    NETWORK_CAN_REACH = "network_can_reach"
    POLICY_ALLOWS = "policy_allows"
    CONFIGURATION_BLOCKS = "configuration_blocks"


class Reachability(str, Enum):
    """How a path is known, kept distinct so an inference is never shown as a fact.

    The brief requires these to be separable, and the schema's evidence_strength binding
    enforces the corresponding weight: CONFIGURED maps to CONFIG_DERIVED, INFERRED to
    INFERRED. There is no value here for 'verified dynamically' because Phase 2 observes
    nothing — that arrives with Phase 3 and must not be pre-claimed.
    """

    CONFIGURED = "configured"
    INFERRED = "inferred"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class Node:
    kind: NodeKind
    identifier: str
    namespace: str | None = None

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.namespace + '/' if self.namespace else ''}{self.identifier}"


@dataclass(frozen=True)
class Edge:
    """One relation, with the evidence and the capture time that produced it."""

    source: Node
    target: Node
    kind: EdgeKind
    reachability: Reachability
    #: Where this came from: a file path and a pointer into it.
    evidence_path: str
    evidence_pointer: str | None
    evidence_excerpt: str | None
    #: When the environment described was OBSERVED, not when the file was parsed.
    description_captured_at: str
    captured_at_basis: str
    rule_id: str
    #: What this edge does not establish. Non-empty by construction.
    limitations: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if not self.description_captured_at:
            raise ValueError(
                f"edge {self.source.key} -> {self.target.key} has no "
                "description_captured_at. Every edge derived from a description carries "
                "that description's capture time; staleness is structural, not optional."
            )
        if not self.limitations:
            raise ValueError(
                f"edge {self.source.key} -> {self.target.key} states no limitation. "
                "Every edge has a blind spot; one claiming none has not had it examined."
            )

    @property
    def sort_key(self) -> tuple:
        return (self.source.key, self.kind.value, self.target.key, self.rule_id)


@dataclass
class Graph:
    """A reachability graph. Every accessor returns sorted output, deliberately."""

    edges: list[Edge] = field(default_factory=list)

    def add(self, edge: Edge) -> None:
        self.edges.append(edge)

    def sorted_edges(self) -> list[Edge]:
        """Sorted, always.

        The two rejected graph tools are non-deterministic because they iterate unsorted
        Go maps when emitting nodes (verified in `rback/render.go` lines 14-78). Sorting
        here is what keeps TrustLens's records byte-identical across runs, which the whole
        evidence model depends on.
        """
        return sorted(self.edges, key=lambda e: e.sort_key)

    def nodes(self) -> list[Node]:
        seen: dict[str, Node] = {}
        for e in self.edges:
            seen.setdefault(e.source.key, e.source)
            seen.setdefault(e.target.key, e.target)
        return [seen[k] for k in sorted(seen)]

    def outgoing(self, node: Node) -> list[Edge]:
        return sorted(
            (e for e in self.edges if e.source == node), key=lambda e: e.sort_key
        )

    def capture_times(self) -> list[str]:
        return sorted({e.description_captured_at for e in self.edges})
