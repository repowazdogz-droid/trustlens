# Phase 2 architecture: credential reachability mapper

**Status: ARCHITECTURE FIXED, no code written. 2026-07-22.** Written before implementation
so the placement decision is explicit rather than implicit, per the standing rule that a
decision living only in a conversation is not a decision.

## The placement decision, restated here so Phase 2 cannot drift from it

Recorded in `docs/SPEC_external_analyser_integration.md` (Warren, 2026-07-22) and repeated
here because it governs this phase's shape:

> **External analysers stay out of the scan path.** Each becomes its own command producing
> its own record, composed through `input_records[]`. `scan()` keeps its no-subprocess
> property untouched and absolute.
>
> **An analyser is optional.** Its absence makes the capabilities it would have covered
> `UNSUPPORTED`, with the reason recorded, preserving the clean-clone property.

Applied to Phase 2:

```
trustlens map-credentials ./env-description     # pure Python; no subprocess; core path
trustlens rbac            ./manifests           # optional Go helper; own record; separate
```

`map-credentials` is subject to the same inertness guarantee as `scan`: it spawns nothing.
`trustlens rbac` is the only Phase 2 component that spawns a process, it is optional, and
its absence degrades coverage to `UNSUPPORTED` rather than failing the run.

## What is built, and why each is built rather than reused

Every tool in this area was source-verified. The survey's conclusions are in
`docs/GROUNDING_UPDATE_phase2_rbac.md`.

### 1. RBAC graph construction — BUILT

Both offline RBAC graph tools were rejected under the **structured-input heuristic**
(`CONTRIBUTING.md`): calling either requires parsing manifests into typed objects first, and
both return presentation DOT rather than typed edges. Independently, both fail a 20-run
determinism test — `rback` produces 4 distinct byte outputs, `rbac-tool viz` produces 2 —
which is disqualifying for a project built on byte-identical regeneration.

TrustLens therefore decodes RBAC manifests itself and emits typed edges directly into the
Phase 0 evidence model, using the existing capability vocabulary
(`k8s.serviceaccount_token_access`, `k8s.api_access`, `identity.role_assumption`,
`reachability.resource_access`).

### 2. RBAC decision semantics — REUSED, out of process

Hand-rolling RBAC evaluation would repeat the mistake `GROUNDING.md` forbids for IAM.
Upstream `k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac` is authoritative, and its four
constructor interfaces are simple lookups satisfiable from decoded YAML:

```go
RoleGetter               { GetRole(namespace, name string) (*rbacv1.Role, error) }
RoleBindingLister        { ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) }
ClusterRoleGetter        { GetClusterRole(name string) (*rbacv1.ClusterRole, error) }
ClusterRoleBindingLister { ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) }
```

Measured cost: **28 `replace` directives pinned to one Kubernetes minor, 44 MB binary.**
Acceptable only because it lands in an optional separate command. This is the concrete
payoff of the placement decision.

### 3. Cross-domain Kubernetes → cloud IAM edges — BUILT

No surveyed tool joins these offline. `GROUNDING.md` gap 4.3, unchanged. This is the actual
differentiator and there is no prior art to reuse.

## Inherited invariants — Phase 2 does not get to relax any of these

1. **Five-state taxonomy.** A description that cannot be parsed produces `PARTIAL`, never a
   clean reachability result. No path exists by which "could not read the policy" becomes
   "no path found".
2. **`description_captured_at` is mandatory** on every environment description, propagates
   to every derived finding and every composed edge, and is surfaced in every report — not
   disclosed once. Staleness here is structural.
3. **`config_derivation` / `policy_evaluation` implies `CONFIG_DERIVED`**, enforced by the
   schema. A configured path can never be recorded with an observation's weight.
4. **Contradictions are recorded, never reconciled.** Where the description asserts one
   thing and a policy document implies another, both are kept with `reconciled: false`.
5. **Coverage reconciliation.** Every check family declares its capabilities; anything
   promised and undelivered becomes `UNKNOWN` plus a recorded gap. The mapper's verdict
   cannot be clean for work it did not do.
6. **Inertness.** `map-credentials` spawns nothing and contacts nothing. No cloud API, no
   cluster, no credential use — a Phase 2 inertness harness mirrors the Phase 1 one.
7. **Every rule needs a liveness trigger and per-target coverage**, per
   `tests/scanner/test_rule_liveness.py` and `test_target_coverage.py`.

## Build order

1. Environment-description schema and loader, with `description_captured_at` required and
   its `captured_at_basis` recorded. Adversarial fixtures first: missing timestamp, stale
   timestamp, contradictory descriptions, malformed policy JSON, unreadable files.
2. IAM policy evaluation over supplied documents, reusing `policy_sentry` action metadata
   and `Parliament` for grammar validation — both verified permissive in Phase 0, both
   pure-Python.
3. RBAC decoding and typed edge construction, in Python.
4. Cross-domain edges (service account → workload identity → IAM role → resource).
5. Contradiction detection across supplied inputs.
6. `trustlens rbac`, the optional Go helper, last — it is the only piece that can be
   deferred without blocking the rest, and building it last keeps the core honest.

## Open, and to be resolved before the step that depends on each

- **[?]** Whether the 28-replace block survives a Kubernetes minor upgrade without manual
  repair. Blocks step 6 only.
- **[?]** Whether `policy_sentry`'s bundled database is current enough for the IAM actions
  TrustLens needs, and what its refresh story is. Blocks step 2.
- **[?]** Whether the Phase 0 environment-description schema sketch survives contact with a
  real Terraform plan. Blocks step 1 and should be tested against a real plan, not a
  hand-written one.

---

# Decisions on the remaining Phase 2 scope (2026-07-22)

## IAM condition evaluation — DOCUMENTED GAP, deliberately not built

Every IAM-derived edge already carries the limitation "Statement Conditions are not
evaluated; the grant may be narrower in practice", and that stays.

**Reasoning for not building it now.** IAM conditions are not a small feature. Sound
evaluation needs the operator families (`StringEquals`/`StringLike`/`StringNotEquals`,
`ArnLike`, `IpAddress`, `DateGreaterThan`, `Bool`, `Null`, `NumericLessThan`), the
`ForAllValues:`/`ForAnyValue:` set qualifiers, the `IfExists` suffix, policy variables
(`${aws:username}`), and the multi-key/multi-value AND/OR semantics between them. A partial
implementation is **worse than none**: it would evaluate the operators it knows and silently
ignore the rest, producing edges that *look* condition-aware and are therefore trusted more,
while being wrong in exactly the cases conditions exist to cover. That is the false-precision
counterpart of the false-clean failure this project is built to avoid.

The honest state is the current one: the edge is reported, and the finding says the
condition was not evaluated. A reader can see the gap.

**What would change the decision.** `policy_sentry` and Parliament (both permissive, both
verified in Phase 0) carry condition-key metadata, and Cedar's `symcc` offers real SMT
evaluation for a Cedar-shaped policy set. Either is a route to sound evaluation. Neither is
a small integration, and both belong to their own scoped piece of work rather than being
appended to the end of Phase 2.

**One exception already implemented.** The IRSA `:sub` condition IS parsed, because it is
not a narrowing predicate over an otherwise-known grant — it is the only thing that
identifies *which* Kubernetes service account the trust applies to. Dropping it would make
the trust look far broader than it is, so parsing it makes the edge narrower and more
accurate, not falsely precise.

## policy_sentry integration and network-policy reachability — NOT BUILT

Both remain unbuilt and are recorded here rather than quietly dropped:

* **policy_sentry** would supply offline AWS action → access-level → ARN-format metadata, so
  a `s3:GetObject` edge could be classified as a read rather than left as an opaque action
  string. Verified permissive (MIT) and pure-Python in Phase 0.
* **Network-policy reachability** would add `network.*` edges from Kubernetes NetworkPolicy
  documents, including the metadata-endpoint egress case that Phase 1's scanner detects
  statically and that the Phase 0 example record models by hand.

Neither is started. Phase 2 is therefore **partially complete**: the mapper, the
cross-domain join and the optional RBAC helper are built and tested; these two are named,
scoped, and outstanding.
