"""The two Phase 2 components must agree on node identity, or the phase does not compose.

`map-credentials` builds the graph in Python; `trustlens rbac` evaluates authorisation in
Go. They are separate processes by design. That separation is only safe if both name the
same real-world thing the same way — otherwise a cross-domain path silently fails to join
and the record reports two disconnected fragments as though nothing connected them.

Nothing asserted this until now. The convention is `namespace/name` for a Kubernetes
service account on both sides, and these tests fail if either side changes it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from trustlens.mapper import rbac_helper
from trustlens.mapper.assemble import map_credentials
from trustlens.mapper.model import EdgeKind, NodeKind

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mapper"
ENV = FIX / "complete_env" / "env.yaml"
K8S = FIX / "complete_env" / "k8s"
TS = {"started_at": "2026-07-22T00:00:00+00:00", "completed_at": "2026-07-22T00:00:01+00:00"}

BINARY = rbac_helper.resolve_binary()
needs_binary = pytest.mark.skipif(
    BINARY is None, reason="optional trustlens-rbac helper not built"
)


def _mapper_service_accounts() -> set[str]:
    result = map_credentials(ENV, **TS)
    return {
        f"{n.namespace}/{n.identifier}"
        for n in result.graph.nodes()
        if n.kind is NodeKind.SERVICE_ACCOUNT and n.namespace
    }


@needs_binary
def test_both_components_name_the_same_service_account_identically():
    """The join point. If these diverge, cross-domain paths silently stop joining."""
    helper = rbac_helper.run_helper(K8S)
    assert helper.available, helper.unavailable_reason

    helper_sas = set(helper.service_accounts)
    mapper_sas = _mapper_service_accounts()

    assert helper_sas, "the helper found no service accounts in the shared fixture"
    assert mapper_sas, "the mapper found no service accounts in the shared fixture"
    shared = helper_sas & mapper_sas
    assert shared, (
        "the two components share NO service-account identifier over the same manifests.\n"
        f"  helper: {sorted(helper_sas)}\n  mapper: {sorted(mapper_sas)}\n"
        "Cross-domain paths cannot join if the identity conventions differ."
    )
    assert "ml/dataset-worker" in shared


@needs_binary
def test_helper_decision_subjects_use_the_same_convention():
    helper = rbac_helper.run_helper(K8S)
    subjects = {d["subject"] for d in helper.decisions}
    assert subjects <= set(helper.service_accounts), (
        "decision subjects must use the same identifier form as service_accounts"
    )
    assert subjects & _mapper_service_accounts()


@needs_binary
def test_the_full_cross_domain_chain_resolves_across_both_components():
    """K8s secret access (Go) and cloud role assumption (Python) meet at one identity."""
    helper = rbac_helper.run_helper(K8S)
    result = map_credentials(ENV, **TS)

    subject = "ml/dataset-worker"
    # Go side: the upstream authorizer says this subject can read secrets.
    secret_reads = [
        d for d in helper.decisions
        if d["subject"] == subject and d["resource"] == "secrets" and d["allowed"]
    ]
    assert secret_reads, "the upstream authorizer should allow secret reads for this subject"

    # Python side: the same subject can assume a cloud role that grants resource access.
    sa_node = next(
        n for n in result.graph.nodes()
        if n.kind is NodeKind.SERVICE_ACCOUNT
        and f"{n.namespace}/{n.identifier}" == subject
    )
    assumes = [e for e in result.graph.outgoing(sa_node) if e.kind is EdgeKind.CAN_ASSUME]
    assert assumes, "the same subject should have a cloud role-assumption edge"

    role = assumes[0].target
    grants = [e for e in result.graph.outgoing(role) if e.kind is EdgeKind.GRANTS]
    assert grants, "the assumed role should grant a policy"


def test_federated_principal_is_not_typed_as_a_service_account():
    """Regression: an OIDC provider ARN was typed SERVICE_ACCOUNT.

    That would let a cross-domain join match on a name that means something else — a
    federated identity provider is not a workload identity.
    """
    result = map_credentials(ENV, **TS)
    sas = [n for n in result.graph.nodes() if n.kind is NodeKind.SERVICE_ACCOUNT]
    assert sas, "the real service account must still be present"
    for node in sas:
        assert not node.identifier.startswith("arn:aws:iam::"), (
            f"{node.identifier} is a federated principal, not a service account"
        )
    federated = [n for n in result.graph.nodes() if n.kind is NodeKind.FEDERATED_PRINCIPAL]
    assert federated, "the OIDC provider should be present under its own node kind"


@needs_binary
def test_helper_absence_does_not_break_the_mapper():
    """The optional half being missing must degrade coverage, not the core result."""
    result = map_credentials(ENV, **TS)
    assert result.graph.edges, "the mapper stands alone without the helper"
    assert any(e.kind is EdgeKind.CAN_ASSUME for e in result.graph.edges)


# ------------------------------------- the conflation audit, applied beyond the first case

def test_rbac_user_and_group_subjects_are_not_typed_as_processes(tmp_path):
    """A `kind: User` subject is a person, not a process.

    Typing one as PROCESS produces edges reading "a process can read secrets" about a
    human, which is a different security claim. Found by auditing every node kind after
    the FEDERATED_PRINCIPAL fix rather than assuming that was the only instance.
    """
    from trustlens.mapper import rbac as rbac_mod

    d = tmp_path / "k8s"
    d.mkdir()
    (d / "b.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
        "metadata: {name: b, namespace: ml}\n"
        "roleRef: {kind: Role, name: r, apiGroup: rbac.authorization.k8s.io}\n"
        "subjects:\n"
        "  - {kind: User, name: alice}\n"
        "  - {kind: Group, name: platform}\n"
        "  - {kind: ServiceAccount, name: sa, namespace: ml}\n",
        encoding="utf-8",
    )
    res = rbac_mod.ingest(d, captured_at="2026-01-01T00:00:00+00:00",
                          captured_at_basis="operator_asserted")
    kinds = {n.identifier: n.kind for n in res.graph.nodes()}
    assert kinds["alice"] is NodeKind.USER
    assert kinds["platform"] is NodeKind.GROUP
    assert kinds["sa"] is NodeKind.SERVICE_ACCOUNT
    assert NodeKind.PROCESS not in kinds.values()


def test_cluster_role_and_namespaced_role_are_distinct_kinds(tmp_path):
    """Same name, different object type — they must not collapse into one node."""
    from trustlens.mapper import rbac as rbac_mod

    d = tmp_path / "k8s"
    d.mkdir()
    (d / "r.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata: {name: reader, namespace: ml}\n"
        "rules: [{apiGroups: [''], resources: ['configmaps'], verbs: ['get']}]\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata: {name: reader}\n"
        "rules: [{apiGroups: [''], resources: ['configmaps'], verbs: ['get']}]\n",
        encoding="utf-8",
    )
    res = rbac_mod.ingest(d, captured_at="2026-01-01T00:00:00+00:00",
                          captured_at_basis="operator_asserted")
    kinds = {n.kind for n in res.graph.nodes() if n.identifier == "reader"}
    assert kinds == {NodeKind.K8S_ROLE, NodeKind.K8S_CLUSTER_ROLE}, (
        "a Role and a ClusterRole of the same name must not share a node kind"
    )


def test_a_policy_wildcard_is_not_typed_as_a_resource():
    """`Resource: "*"` means EVERY resource; typing it as one hides the difference."""
    result = map_credentials(ENV, **TS)
    for node in result.graph.nodes():
        if node.identifier == "*":
            assert node.kind is NodeKind.WILDCARD_RESOURCE, (
                'a "*" resource must not render identically to a specific bucket'
            )
    assert any(n.kind is NodeKind.WILDCARD_RESOURCE for n in result.graph.nodes())


def test_a_secrets_store_arn_is_not_typed_as_storage():
    from trustlens.mapper import terraform as tf
    import json as _json

    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "type": "aws_iam_policy", "name": "p",
                "change": {"after": {"name": "p", "policy": _json.dumps({
                    "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
                                   "Resource": "arn:aws:secretsmanager:eu-west-2:1:secret:db"}]
                })}},
            }
        ],
    }
    p = Path(__file__).parent / "_tmp_plan.json"
    p.write_text(_json.dumps(plan), encoding="utf-8")
    try:
        res = tf.ingest_plan(p, "plan.json", captured_at="2026-01-01T00:00:00+00:00",
                             captured_at_basis="operator_asserted")
        kinds = {n.kind for n in res.graph.nodes() if "secretsmanager" in n.identifier}
        assert kinds == {NodeKind.SECRET}, "a secrets-store ARN is not storage"
    finally:
        p.unlink(missing_ok=True)
