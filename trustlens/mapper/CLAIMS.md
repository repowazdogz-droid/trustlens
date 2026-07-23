# Credential mapper — claims and bounds

**Status: Phase 2 built, partial-but-closed against its stated scope.** Offline only; the
mapper acquires nothing, executes nothing, and models an environment only from descriptions
and manifests the operator supplies. Deferred work is registered, with reasons, in
[`docs/DEFERRED.md`](../../docs/DEFERRED.md).

## What it establishes

- From a `trustlens_env_v1` description, a Terraform plan JSON, and Kubernetes RBAC
  manifests, it builds a **typed reachability graph**: which principal is bound to which
  role, which role grants which policy, which policy reaches which secret or resource, and —
  across the Kubernetes→IAM boundary — which service account a federated trust applies to,
  resolved through the IRSA `:sub` condition.
- **Every edge carries the capture time of the description it was derived from.** There is no
  constructor that omits it; a reachability claim from a six-month-old description is stated
  as a claim about six months ago, and that timestamp propagates to anything derived from it.
- **Node identity is shared with the blast-radius phase** (`namespace/name` for a service
  account), so a cross-domain path joins on the same real-world thing rather than two
  disconnected fragments. `tests/mapper/test_cross_component_identity.py` fails if the two
  sides diverge.
- **Output is deterministic.** Every accessor sorts, so records are byte-identical across
  runs — unlike the two offline RBAC graph tools surveyed, both of which fail a 20-run
  determinism test (`docs/GROUNDING_UPDATE_phase2_rbac.md`).
- The optional `trustlens rbac` command wraps the **upstream Kubernetes `RBACAuthorizer`** as
  a separate, explicitly-initiated binary — never reachable from `map-credentials()`, which
  spawns nothing.

## What it does not establish

- **That any modelled configuration is applied to a live cluster or account.** The graph is
  derived from supplied manifests; it does not establish that those objects are deployed.
- **That an IAM grant is as narrow in practice as it looks.** Statement `Condition` blocks
  are **not evaluated** — the one exception is the IRSA `:sub` condition, which *identifies*
  the trusted service account rather than narrowing an otherwise-known grant. Every other
  condition is recorded and explicitly not evaluated (D1). A partial evaluation would be
  false precision, so none is done.
- **The access level of an action.** `s3:GetObject` is recorded as an opaque action string,
  not classified as a read (`policy_sentry` is deferred, D2).
- **Whether the network permits reaching anything.** No `NetworkPolicy` is ingested and no
  `network.*` edge is emitted (D3). The Phase 0 illustrative contradiction — description says
  metadata access is blocked while a NetworkPolicy permits link-local — is **not** detectable
  end to end, and that is the honest cost of D3.
- **That an operator-asserted `description_captured_at` is accurate.** The mapper records the
  basis of that timestamp; it cannot verify it.

## Known gaps, stated rather than discovered later

- D1 IAM condition evaluation, D2 `policy_sentry`, D3 network-policy reachability, D4 external
  analysers — each deferred with a reason and what stands in its place, in `docs/DEFERRED.md`.
- The `rbac` helper is a 45MB Go binary, built not committed. Its absence degrades coverage
  to the pure-Python graph; it never silently substitutes a different binary.

## Controls

- **Cross-component identity** (`test_cross_component_identity.py`) — the mapper and the Go
  helper must name the same service account identically, or a cross-domain path silently
  stops joining.
- **Conflation audits** — regression tests that a federated principal is not typed as a
  service account, a `User`/`Group` subject is not typed as a process, a `ClusterRole` and a
  namespaced `Role` of the same name are distinct kinds, and a `"*"` resource is not rendered
  as a specific one. Each was a real conflation found by auditing every node kind.
- **Determinism** — 20-run byte-identical output, the property the rejected tools lack.
- **Inertness** — `map-credentials` uses `yaml.safe_load_all`; a `!!python/...` tag is
  recorded as a failure, never constructed.
