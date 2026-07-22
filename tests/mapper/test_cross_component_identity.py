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
