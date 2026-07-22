# Grounding update: offline Kubernetes RBAC graphing

**Phase 2 entry condition. Retrieval date: 2026-07-22.** Re-verification of the Phase 0
survey's conclusion that `krane` was the only offline RBAC graph tool and that its
rejection settled the question. **Two of Phase 0's conclusions were wrong.** Provenance
markers as in `GROUNDING.md`: **[V]** verified by me here, **[?]** not verified.

---

## Correction 1 — Phase 0 said krane was the *only* offline RBAC graph tool. It is not.

**[V] `team-soteria/rback` builds an RBAC graph with no cluster and no database.** Phase 0
classified it as cluster-only, reading the README's workflow rather than the binary's input
path. The README does say it "depends on you having access to a Kubernetes cluster... as
well as `kubectl`", which is what the earlier survey recorded — but that describes the
documented *pipeline*, not a requirement of the program.

The documented invocation is a pipe:

```
kubectl get sa,roles,rolebindings,clusterroles,clusterrolebindings --all-namespaces -o json | rback > result.dot
```

**[V] Read from source**: `main.go:36` is `reader := os.Stdin`. The 3.6 KB `main.go`
contains no `exec.Command` and never invokes `kubectl` itself. It consumes RBAC JSON on
stdin and emits Graphviz DOT — nodes and edges — for service accounts, roles, cluster roles
and their rules. Supplying equivalent JSON assembled from manifest files therefore produces
a graph with no cluster contacted.

| Field | Value |
|---|---|
| Licence | **[V]** Apache-2.0 — permissive, unlike every other RBAC-graph option found |
| Archived | **[V]** No |
| Last pushed | **[V]** 2021-01-04 — **stale by five and a half years** |
| Output | DOT (a real node/edge graph), not flat findings |
| Dependency | None. No database, no daemon. |

Honest weighing: five years of staleness would be disqualifying for a *rule-bearing* tool,
because rules must track threats. `rback` bears no rules — it is a JSON-to-DOT projection,
and the RBAC object shapes it reads are long-stable API types. Staleness is a much smaller
risk for a transformation than for a detector. It remains a real risk and is recorded.

## Correction 2 — krane's rejection was right, but my stated reason was half wrong.

Phase 1 recorded krane as rejected on "an EOL graph database plus non-permissive
licensing". The EOL half is weaker than stated.

**[V] FalkorDB is alive and documents RedisGraph clients as its own.** `FalkorDB/FalkorDB`
was pushed **2026-07-22** (the day of this review), is not archived, and carries 4,813
stars. Its README's client table lists the RedisGraph client libraries — including
`redisgraph-rb`, the Ruby client krane uses via `Krane::Clients::RedisGraph` — as clients of
FalkorDB. That is documented evidence of protocol compatibility.

**[?] I could NOT verify** the common claim that FalkorDB is a fork by the original
RedisGraph team. The README contains no lineage statement, and I am not asserting one.

So the "dead dependency" reason does not hold as stated: a maintained, protocol-compatible
successor exists.

**[V] The licence reason does hold, and it is decisive.** FalkorDB's `LICENSE.txt` is the
**Server Side Public License, Version 1** — not OSI-approved, and the same non-permissive
family that disqualified RedisGraph. Swapping one for the other does not solve the licence
problem; it relocates it.

**Verdict: krane stays rejected, on licence and on operational weight** (it requires
standing up a graph database to answer questions about YAML files), **not on its dependency
being dead.** The earlier reason is corrected here rather than left to stand.

## Finding 3 — upstream RBAC semantics are reusable, which changes the build-vs-reuse call

The Phase 0 rule "do not hand-roll IAM semantics" applies equally to RBAC, and there is an
upstream implementation to reuse.

**[V]** `kubernetes/kubernetes`, `plugin/pkg/auth/authorizer/rbac/`:

- `rbac.go:172` — `func New(roles rbacregistryvalidation.RoleGetter, roleBindings RoleBindingLister, clusterRoles ClusterRoleGetter, clusterRoleBindings ClusterRoleBindingLister) *RBACAuthorizer`. The constructor takes **getter and lister interfaces, not a cluster client**, so it can be constructed over objects decoded from manifest files in memory.
- `rbac.go:78` — `Authorize(ctx, requestAttributes) (authorizer.Decision, string, error)`.
- `rbac.go:47` — `VisitRulesFor(...)`, which enumerates every rule applying to a user in a namespace.
- `subject_locator.go` — the reverse direction, "which subjects can do X", which is precisely the edge-construction primitive a reachability graph needs.

This is the authoritative implementation of the semantics TrustLens would otherwise
approximate: aggregation, wildcards, `nonResourceURLs`, subresources, and the
cluster-versus-namespace binding rules that a hand-rolled evaluator gets wrong in the same
way a hand-rolled IAM parser gets ARN completion wrong.

**The cost is that it is Go, and TrustLens is Python.** Using it means either a helper
binary or a reimplementation — and a helper binary is a subprocess, which is exactly the
placement question now pending decision in
`docs/SPEC_external_analyser_integration.md`. That question is therefore not confined to
Bandit: it decides the shape of Phase 2 as well.

---

## Revised position for Phase 2

| Need | Option | Status |
|---|---|---|
| RBAC graph from manifests, offline | **rback** (Apache-2.0, DOT output, stdin) | **VIABLE** — reversing Phase 0's classification; stale but rule-free |
| RBAC graph via a graph database | krane + RedisGraph/FalkorDB | **REJECTED** — SSPL licence, operational weight |
| Authoritative RBAC decision semantics | upstream `plugin/pkg/auth/authorizer/rbac` | **VIABLE, blocked** on the in-or-out-of-process placement decision |
| Cross-domain K8s→IAM edges | nothing found, unchanged from Phase 0 | **BUILD** |

The `GROUNDING.md` gap 4.3 — "no fetched tool joins Kubernetes RBAC to cloud IAM offline" —
is **unchanged and still the real gap**. What changed is that the RBAC half has more
reusable prior art than Phase 0 recorded, in both directions: a permissively-licensed graph
projector, and the upstream authorizer itself.

## Not verified

- **[?]** Whether FalkorDB is a fork by the original RedisGraph team. No lineage statement in
  its README; not asserted here.
- **[?]** Whether `rback`'s DOT output is stable enough to parse programmatically, or whether
  TrustLens would use it only as a renderer and build its own edge set.
- **[?]** Whether the upstream authorizer's interfaces can be satisfied from decoded YAML
  without pulling in a large part of `k8s.io/apiserver`. This needs a spike before it is
  relied on.
- **[?]** rbac-tool, kubescape, rbac-police and audit2rbac were not re-verified in this pass;
  the agent tasked with the broad sweep died on an API error and I re-ran only the
  load-bearing questions myself. Their Phase 0 classifications stand as **single-verified**,
  and given that two of Phase 0's classifications in this exact area turned out to be wrong,
  they should be re-checked before any of them is relied on.
