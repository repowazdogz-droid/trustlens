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

---

# Round 2: source-level re-verification and two spikes (2026-07-22)

All four remaining tools were treated as presumptively unverified and re-checked from
**source**, not documentation — the standard that caught the two earlier errors. It caught a
third.

## Correction 3 — `rbac-tool` is NOT cluster-only. Phase 0 was wrong again.

**[V] `cmd/visualize_cmd.go:73`:**

```go
flags.StringVarP(&opts.Infile, "file", "f", "", "Input File - use '-' to read from stdin")
```

with `--outformat` accepting `dot` (line 76). `rbac-tool viz` therefore builds an RBAC graph
from a **file or stdin**, with no cluster. Phase 0 recorded it as "DO-NOT-USE for offline
manifests" after reading the README's flag list, which does not surface `-f`.

This is the **third** Phase 0 classification in this area to fail source-level re-check. The
instruction to treat the remainder as presumptively unverified was correct.

`rbac-tool` is a better candidate than `rback`: same offline capability, Apache-2.0,
v1.20.0 (2024-10) versus rback's 2021, and DOT output is an explicit documented flag rather
than the only output shape.

## Re-verification results

| Tool | Verified from | Offline from files? | Graph? | Verdict |
|---|---|---|---|---|
| **rbac-tool** | `visualize_cmd.go:73,76` | **YES** — `-f`, `-` for stdin | DOT or HTML | **VIABLE — Phase 0 corrected** |
| **rbac-police** | `cmd/eval.go:83` — `utils.ReadFile(args[1])` | **YES for `eval`** — reads a collected-state file | policy findings, not a graph | Viable for evaluation; collector step is cluster-based |
| **audit2rbac** | `cmd/audit2rbac/audit2rbac.go:63,208,354-356` | **YES** — `--filename` required, `os.Stdin`/`os.Open` | n/a | **Not applicable.** It *synthesises* RBAC from audit logs; it does not analyse manifests. File-based, wrong function. |
| **kubescape** | repo metadata + `cmd/scan/` listing only | scans files (control/framework/workload) | **not verified** | **PARTIALLY VERIFIED** — Apache-2.0, very active (pushed 2026-07-22, 11.5k stars), but I did **not** confirm from source that it builds an RBAC graph. Do not rely on it until that is checked. |

---

## Spike 1 — is `rback`'s DOT output stable enough to parse? **NO, not as bytes.**

Built from source (commit `98e7f72`, Apache-2.0, Go 1.12 module) and run against RBAC JSON
assembled from manifests, with no cluster.

| Measurement | Result |
|---|---|
| Runs of **identical** input | 20 |
| **Distinct byte outputs** | **4** |
| Distinct canonical edge sets (IDs resolved to labels, sorted) | **1** |
| Edge count | 12, every run |
| Distinct label sets | 1 |

The variance is node-ID assignment — `n17/n16/n18` in one run, `n13/n12/n14` in another —
which is Go map iteration order. **The graph is stable; the text is not.**

**Verdict.** TrustLens rests on byte-identical regeneration and deterministic content
hashes. Output that differs across four forms for the same input cannot be hashed, diffed,
or stored as control evidence. `rback` is therefore usable only behind a canonicalisation
layer that resolves node IDs to labels and sorts the edges.

And that observation is decisive: **to feed `rback` at all, TrustLens must already have
parsed the RBAC objects into JSON.** Having done that, constructing the edge set directly is
less work than parsing non-deterministic DOT back into a graph — and it yields the typed
edges the Phase 0 schema wants rather than presentation nodes mixed with legend nodes (the
rendered graph interleaves both). `rback`'s value is visualisation, not graph construction.

## Spike 2 — can upstream `RBACAuthorizer` be satisfied from decoded YAML? **Yes. The cost is now measured, not assumed.**

**[V] The interfaces are trivial.** From `pkg/registry/rbac/validation/rule.go`
(release-1.31), the four parameters of `New()` are:

```go
RoleGetter               { GetRole(namespace, name string) (*rbacv1.Role, error) }
RoleBindingLister        { ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) }
ClusterRoleGetter        { GetClusterRole(name string) (*rbacv1.ClusterRole, error) }
ClusterRoleBindingLister { ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) }
```

Four lookup methods over in-memory maps. No cluster client, no informers, no caches. The
"satisfiable from decoded YAML" half of the earlier claim **holds fully**.

**[V] The import cost is real and was previously unmeasured.** A module importing
`k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac` **fails outright**:

```
k8s.io/api/rbac/v1alpha1: reading k8s.io/api/go.mod at revision v0.0.0: unknown revision v0.0.0
```

`k8s.io/kubernetes` publishes its staging repositories as `v0.0.0` placeholders that resolve
only through its own `replace` block. It builds only after adding **28 `replace` directives**
pinned to one Kubernetes minor (`v1.31.4` / `v0.31.4`). The resulting binary — for a program
whose entire body prints a type name — is **44 MB**.

**Verdict.** The conclusion survives, with two qualifications that were not in the earlier
report:

1. **28 replace directives pinned to a single Kubernetes minor.** Upgrading Kubernetes means
   regenerating the whole block. That is recurring maintenance, and it is the kind of cost
   that is invisible until it bites.
2. **A 44 MB binary.** Acceptable *only* because the placement decision of 2026-07-22 puts
   this in a separate, optional `trustlens rbac` command. Had external analysis gone
   in-process, this weight would have landed in TrustLens's core and the clean-clone property
   would have been lost. The placement decision is what makes this viable.

**Neither spike was inconclusive.** Spike 1 rules `rback` out as a graph source. Spike 2
keeps the upstream authorizer in, at a now-known price.

## Revised Phase 2 position

| Need | Decision |
|---|---|
| RBAC graph construction | **Build.** TrustLens parses manifests itself; feeding a graph tool requires that work anyway, and both graph tools emit presentation output rather than typed edges. |
| RBAC decision semantics | **Reuse upstream** via a separate, optional `trustlens rbac` Go command. |
| RBAC visualisation | **`rbac-tool viz -f -`** (Apache-2.0, maintained) if a rendered view is wanted. Not on the evidence path. |
| Cross-domain K8s→IAM edges | **Build.** Unchanged; still the real gap. |

## Still not verified

- **[?]** kubescape's RBAC-graph capability — metadata only, not source.
- **[?]** Whether the 28-replace approach survives a Kubernetes minor upgrade without manual
  repair. Assumed to need it; not tested.
- **[?]** Whether `rbac-tool viz`'s DOT output is deterministic. It was **not** subjected to
  the 20-run test applied to `rback`, and given that `rback` failed it, assuming `rbac-tool`
  passes would repeat exactly the mistake this round was called to correct.


---

# Round 3: both remaining verifications resolved (2026-07-22)

## `rbac-tool viz` — subjected to the same 20-run test, verified independently

Built from source (commit `a0b8c03`, Apache-2.0) and run offline from a file. File input is
first-class, confirmed at `pkg/visualize/rbacviz.go:100` — `utils.ReadObjectsFromFile(opts.Infile)`
— with the cluster path taken only when `Infile == ""` (line 56).

| Measurement | `rbac-tool viz` | `rback` |
|---|---|---|
| Runs of identical input | 20 | 20 |
| **Distinct byte outputs** | **2** | **4** |
| Distinct canonical edge sets | 1 | 1 |
| Edge count | 5, every run | 12, every run |
| What varies | subgraph id (`cluster_s1` vs `cluster_s4`) and node numbering | node numbering |

**It fails the same test.** Verified independently rather than inferred — though both use
`github.com/emicklei/dot`, which is the shared root cause.

**The rarity makes it more dangerous, not less.** `rback` produced four forms in twenty runs
and would be caught by almost any check. `rbac-tool` produced one deviation in twenty — a
5% flake that passes casual verification and fails intermittently later, which is the
harder failure to diagnose.

**Verdict: identical to `rback`.** TrustLens builds typed edges directly. `rbac-tool`'s value
here was confirming `rback`'s finding and establishing that the instability is a property of
the DOT-emitting approach rather than of one stale tool — not adding a usable dependency.

## `kubescape` — resolved to REJECTED, from source

`kubescape/rbac-utils` (Apache-2.0, pushed 2024-12-11) is the RBAC component. Rejected on
two independent grounds:

**1. It is not a graph.** `rbacutils/rbacdatastructures.go` defines `RbacTable`
(`Cluster`, `Namespace`, `UserType`, `Username`, `Role`, `Verb []string`, `Resource []string`)
— flat table rows. There is no `Node`, `Edge` or `Graph` type in the package. Both `RBAC` and
`RbacTable` carry a `// DEPRECATED` marker in the source.

**2. It is cluster-only.** The sole real scanner, `rbacscanner/rbacscannerk8sapi.go`, calls
`K8s.KubernetesClient.RbacV1().ClusterRoles().List(...)`, `.Roles("").List(...)`,
`.ClusterRoleBindings().List(...)` and `.RoleBindings("").List(...)` — live API calls
(lines 35-50). The only other implementation is `rbacscannermock.go`, a test mock. No
file-based scanner exists.

**No longer partially verified.** Fully rejected, on source.

## Final Phase 2 tool position

| Need | Decision | Basis |
|---|---|---|
| RBAC graph construction | **BUILD in TrustLens** | Both graph tools are non-deterministic presentation emitters; the structured-input heuristic rules both out |
| RBAC decision semantics | **REUSE upstream**, in the separate optional `trustlens rbac` command | Authoritative; 28 replace directives and 44 MB confined to an optional binary |
| RBAC visualisation | `rbac-tool viz -f -` if a rendered view is ever wanted | Presentation only, never on the evidence path |
| Cross-domain K8s→IAM edges | **BUILD** | Unchanged; still the real gap |

Every tool in this area is now source-verified. Four of the survey's original
classifications were wrong (`rback`, `rbac-tool`, krane's stated reason, and kubescape's
status), and all four errors came from reading documentation instead of code.
