# TrustLens — claims and bounds

Each component carries its own `CLAIMS.md` stating what its evidence establishes and, next
to it, what the same evidence does not establish. This file covers the project as a whole.
Component files:

- [`trustlens/scanner/CLAIMS.md`](trustlens/scanner/CLAIMS.md) (Phase 1)
- [`trustlens/mapper/CLAIMS.md`](trustlens/mapper/CLAIMS.md) (Phase 2)
- [`trustlens/sandbox/CLAIMS.md`](trustlens/sandbox/CLAIMS.md) (Phase 3)
- [`trustlens/blast/CLAIMS.md`](trustlens/blast/CLAIMS.md) (Phase 4)

All four phases are built. Each component's specific establishes/does-not-establish list is
in its own file; this file states the whole-tool version.

## The sandbox boundary, stated first because it is the easiest thing to over-read

The Phase 3 sandbox is **`EXPERIMENTAL` and gVisor-scoped.** It was signed off (SO-1, SO-2 in
[`docs/SIGN_OFF.md`](docs/SIGN_OFF.md)) for artifacts whose threat model is **hostile
userspace code** — and explicitly **not** for artifacts whose threat model includes
**kernel-level exploitation**, which is the class the July 2026 incident actually
represented. A clean sandbox run means "nothing hostile was observed at userspace level in
this one execution," never "the artifact is safe" and never "contained against a kernel
exploit." The boundary is enforced in code, not documentation: `status.promote()` refuses to
leave `EXPERIMENTAL` on a gVisor-only configuration, so no edit to this file can widen it.

## The project claim

> TrustLens compares what an ML dataset or repository is declared to be with what static
> analysis, deployment configuration, and controlled execution show it can actually do. It
> maps potential credential and network reachability and simulates evidence-supported blast
> radius. It does not determine malicious intent, certify artifacts as safe, or guarantee
> containment.

## Phase 0 — shared evidence model

**Establishes.**

- A conforming record states which paths were analysed, which were deliberately excluded,
  and which failed, each with a reason.
- A conforming record cannot express a completed-clean result over a scope containing
  failures. The pairing is rejected at construction, by the JSON Schema, by the semantic
  validator, and by the consumption API.
- Aggregation across findings cannot produce a clean result from an incomplete input, and
  an empty aggregate is `UNKNOWN` rather than clean.
- Every finding records the rule and rule version that produced it, how far its evidence
  reaches, and a non-empty list of what it does not establish.
- Every configuration-derived finding carries the capture timestamp of the description it
  came from, and that timestamp propagates to anything derived from it.
- A record that has been altered after sealing fails validation, because `content_hash`
  no longer reproduces.
- Regenerating the shipped example records is byte-identical.

**Does not establish.**

- That any finding a component later emits is correct. The schema constrains how evidence
  is *stated*, not whether the evidence is *good*.
- That the rules a component applies are adequate to the artifacts it will meet.
- That the scope a component chose to analyse was the right scope.
- That an operator-asserted `description_captured_at` is accurate. TrustLens records the
  basis of that timestamp and cannot verify it.
- That a conforming record is a complete account of an artifact.
- That the four barriers keeping `PARTIAL` and `NOT_FOUND_WITHIN_ANALYSED_SCOPE` apart
  cover every route by which a future component could conflate them. They cover
  construction, structure, aggregation and consumption; a component that bypasses the
  library entirely and writes JSON by hand is caught only by validation, and only if
  validation is run.

## Scope — the full pipeline needs the artifact *and* its deployment environment

The four-component workflow assumes access to both. The **scanner** works on the artifact
alone. The **mapper**, **sandbox**, and **blast-radius** layers require the credential topology
the artifact would run against — Terraform/Kubernetes-RBAC manifests or an environment
description — which lives in the deploying organisation's infrastructure, not in the artifact.
**Analysing a public artifact with no environment supplied exercises only the scanner; the other
three components have no input.** This is measured, not asserted: in the first external
evaluation, 0 of 8 public repositories shipped ingestible environment configuration, and no
credential/cloud/environment capability was found in any of them (`study/WRITEUP.md`, Finding 3).
TrustLens is aimed at an analyst working on their own infrastructure with both halves in hand; a
reader assessing a public artifact alone gets the static scanner and nothing composed on top of
it.

## What the built tool establishes

Whole-tool summary. Each component's file states these in full, with its controls.

**Scanner (Phase 1).** For a local directory, over the scope it records, it states which
capability-bearing constructs are present in the artifact's own code and configuration — with
the rule, the file, the line, and what the finding does not establish. It parses Python and
YAML itself, spawns no processes, and a parse failure is `PARTIAL`, never clean.

**Credential mapper (Phase 2).** From an offline environment description and
Terraform/Kubernetes-RBAC manifests, it builds a typed reachability graph — which principal
can assume which role, reach which secret, across the K8s→IAM boundary via the IRSA `:sub`
condition — with each edge carrying the capture time of the description it rests on. It
spawns nothing; the optional `rbac` helper wraps the upstream Kubernetes authorizer as a
separate, explicit command.

**Sandbox (Phase 3).** It executes an artifact under one operator profile inside gVisor with
`--network=none`, and records the run reproducibly: the command's output and exit status, the
observed sandbox kernel, the termination reason, and the pinned isolation mechanism version
and sha256. Separately, the **conformance suite** runs twelve prohibited-operation probes
inside the sandbox and records whether the configured boundary held (an all-conform run is
`NOT_FOUND_WITHIN_ANALYSED_SCOPE`, the weakest of the five states). It is `EXPERIMENTAL` and
gVisor-scoped (see the boundary section above). **What the built code does not yet include** is
a general behavioural tracer that classifies an arbitrary artifact's syscalls into
`filesystem.*`/`network.*`/`process.*` findings; the per-behaviour findings shown in
`examples/records/sandbox_record.json` illustrate the evidence schema, not a built observer.

**Blast-radius (Phase 4).** Offline, it composes the three sources into reachability paths
from an entry principal to an asset, **every edge labelled by how it was established**
(declared / statically found / configured / inferred / dynamically observed / dynamically
blocked / unknown), and **every path rendered at the confidence of its weakest edge** — one
inferred or `PARTIAL` edge caps the whole path, and a blocked edge marks the path cut. It
executes nothing and observes nothing itself; a composed path is an inference about
reachability, not a demonstration of it.

**Across all four:** a record cannot express a completed-clean result over a scope containing
failures; capture time propagates to anything derived from a description; a sealed record that
is altered fails validation; and regenerating the shipped example records is byte-identical.

## What the built tool does not establish

The component-level non-claims (each component's file) hold, and in addition, at the whole-tool level:

- **That any path composed across components is traversable end to end.** Edge existence is
  not path traversability, and every composed path says so.
- **That a clean result from any component means the artifact is safe.** Each component bounds
  its own scope; none bounds the artifact.
- **That the sandbox contains a kernel-level attacker.** It was not signed off for that class
  (see the boundary section); Firecracker on real KVM hardware is the stated requirement
  before that class is in scope, and it is not built.
- **That coverage is constant between runs.** External analysers are optional and absent by
  default; the deferred items in [`docs/DEFERRED.md`](docs/DEFERRED.md) (IAM conditions,
  `policy_sentry`, network-policy reachability, external analysers) are gaps, stated.

## Standing non-claims

These hold for every phase and are not softened by any later result.

TrustLens does not claim, and no output of it should be read as claiming:

- That it prevented, or would have prevented, any security incident.
- That it detects all malicious ML artifacts.
- That a clean result means an artifact is safe.
- That a sandbox result certifies containment.
- That a finding indicates malicious intent.
- That a simulated path is a proven exploit chain.

## On the July 2026 Hugging Face incident

Hugging Face published a disclosure on 16 July 2026 (`https://huggingface.co/blog/security-incident-july-2026`,
retrieved and verified 2026-07-22) describing an intrusion whose initial vector was, in
its own words, "a malicious dataset abused two code-execution paths in our dataset
processing (a remote-code dataset loader and a template-injection in a dataset
configuration) to run code on a processing worker", followed by credential harvesting and
lateral movement. The same page states that "no evidence of tampering with public,
user-facing models, datasets, or Spaces" was found.

The permitted framing, and the only one used in this repository, is:

> This class of tool could surface execution, credential, and reachability gaps of the
> kind involved in the incident.

TrustLens did not exist at the time, was not deployed, and makes no claim about what would
have happened had it been. The incident is cited here for one reason only: it is primary
evidence that the dataset-processing execution surface, the credential surface reachable
from a processing worker, and the lateral-movement surface between them are real and have
been exploited together — which is why the four components are scoped as they are.
