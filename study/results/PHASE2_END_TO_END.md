# Phase 2 — the end-to-end path: NO QUALIFYING CASE (reported per amendment A1)

**Finding: the corpus contained no case where the full evidence chain — static finding →
credential reachability → blast radius — changed what a reasonable engineer would conclude
relative to the repo's own documentation plus an existing scanner's clean verdict.**

This is reported as a finding in its own right (pre-registration §8, amendment A1), not as a
study failure, and it is not softened. No marginal or manufactured case is offered.

## Why no case can exist in this corpus — checked, not assumed

The end-to-end chain requires three layers to compose. Two of them have **no input** here:

1. **Static finding** — present. Loaders execute code; the scanner surfaces it.
2. **Credential reachability (mapper)** — the mapper builds edges only from an operator-supplied
   environment description (a Terraform plan, Kubernetes RBAC manifests, or a `trustlens_env_v1`
   description mapping which principal reaches which secret/resource). **No repo in the corpus
   ships any such config** — verified: zero `.tf` / plan JSON / RBAC / role manifests across all
   8 repos. Public dataset repositories carry data and loaders, not the deploying organisation's
   credential topology, which lives in that organisation's infrastructure, not in the artifact.
3. **Blast radius** — composes (1) and (2). With no credential edges, it has nothing to compose
   beyond the static findings.

Further, **not a single credential/cloud/network/env capability was FOUND anywhere in the
corpus.** The only such capabilities that appear at all are k9cli's — and all 12 are `PARTIAL`
(the BOM defect), i.e. unassessable. So even the *static* anchor for a credential story
(a loader reading `~/.aws/credentials`, hitting the metadata endpoint, or reading a token) is
absent from every cleanly-analysed repo.

## What this reveals — a real boundary of TrustLens's end-to-end proposition

The credential-mapper and blast-radius components require **environment context external to the
artifact**. A study of artifacts *in isolation* — which is what scanning public repos with no
operator environment is — cannot exercise them. For pure artifact analysis with no supplied
environment, **TrustLens reduces to its static scanner**; the two composed layers contribute
nothing.

This is not a defect; it is a scope statement made concrete by real data: the end-to-end value
proposition is aimed at an operator analysing *their own* artifact *against their own* credential
topology, and it needs that topology as input. The public-artifact case does not supply it.

## The structural ceiling (amendment A2), restated where the case would be

Even had a qualifying case existed, it would rest on **inferred and configured edges only**.
The sandbox is off by construction (§5), so no blast-radius path in this study can reach the
`OBSERVED` tier under the weakest-link rule — every edge would be `configured` or `inferred`,
none `dynamically_observed`. Any end-to-end claim here would therefore be a *composed inference*
about reachability, never a demonstration of it. This ceiling is stated here, at the point the
case would be presented, not only in the limitations section.

## The static-only gaps that DO exist are not this case

The corpus does contain static declared-vs-reachable gaps — loaders that execute code where a
card implies passive data (see the divergence catalogue). Those are the **scanner's** result and
are surfaced by the scanner alone; they are not the full-chain end-to-end case Phase 2 asked
for, and they are not counted as one. The credential and blast layers added nothing to them in
this corpus.
