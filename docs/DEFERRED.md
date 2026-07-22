# Deferred work register

Work that was **decided against for now**, not forgotten. Each item names why it was
deferred, what it would take, what currently stands in its place, and which phase it is a
candidate for.

The distinction this file exists to preserve: a deliberate deferral has a reason and an
owner-phase; a forgotten item has neither, and after a few months they are indistinguishable
from the outside. Anything that leaves scope goes here with its reasoning intact.

| # | Item | Deferred | Candidate phase | Currently in its place |
|---|---|---|---|---|
| D1 | IAM condition evaluation | 2026-07-22 | Phase 3+ | A stated limitation on every IAM-derived edge |
| D2 | `policy_sentry` integration | 2026-07-22 | Phase 3+ | Actions recorded as opaque strings |
| D3 | Network-policy reachability | 2026-07-22 | Phase 3+ | Phase 1 detects metadata endpoints statically; no `network.*` edges exist |
| D4 | Bandit / external analyser integration | 2026-07-22 | Phase 3+ | No external tool in any FOUND/NOT_FOUND claim |

---

## D1 — IAM condition evaluation

**Status: deliberately not built. Candidate for Phase 3 or later.**

Sound evaluation needs the operator families (`StringEquals`, `StringLike`,
`StringNotEquals`, `ArnLike`, `IpAddress`, `DateGreaterThan`, `Bool`, `Null`,
`NumericLessThan`), the `ForAllValues:` / `ForAnyValue:` set qualifiers, the `IfExists`
suffix, policy variables (`${aws:username}`), and the AND/OR semantics between multiple keys
and multiple values.

**Why partial is worse than none.** A partial implementation evaluates the operators it
knows and silently ignores the rest, producing edges that *look* condition-aware — and are
therefore trusted more — while being wrong in exactly the cases conditions exist to cover.
That is false precision, the counterpart of the false-clean failure this project is built
around.

**In its place now:** every IAM-derived edge carries "Statement Conditions are not
evaluated; the grant may be narrower in practice." The gap is visible to a reader.

**One exception already implemented:** the IRSA `:sub` condition *is* parsed
(`tf-irsa-serviceaccount-trust`), because it does not narrow an otherwise-known grant — it
is the only thing identifying *which* service account the trust applies to. Parsing it makes
the edge narrower and more accurate; ignoring it would make the trust look far broader than
it is.

**What would unblock it:** `policy_sentry` and Parliament (both permissive, both verified in
Phase 0) carry condition-key metadata; Cedar's `symcc` offers real SMT evaluation over a
Cedar-shaped policy set. Either is a route, and neither is a small integration.

## D2 — `policy_sentry` integration

**Status: not built. Candidate for Phase 3 or later.**

Would supply offline AWS action → access-level → ARN-format metadata, so an `s3:GetObject`
edge could be classified as a *read* rather than left as an opaque action string. MIT,
pure-Python, bundled SQLite database, verified permissive in Phase 0.

**Open question that must be answered first (carried from
`docs/SPEC_phase2_credential_mapper.md`):** whether the bundled database is current enough
for the actions TrustLens needs, and what its refresh story is. Integrating a stale action
database would produce confidently wrong access-level classifications.

**In its place now:** actions are recorded verbatim as strings, with no access-level claim.

## D3 — Network-policy reachability

**Status: not built. Candidate for Phase 3 or later.**

Would add `network.*` edges from Kubernetes `NetworkPolicy` documents, including the
link-local metadata-endpoint egress case — the one the Phase 0 example record models by hand
and that the Phase 2 contradiction machinery was designed to surface.

**In its place now:** Phase 1's scanner detects hardcoded metadata endpoints statically in
source and configuration. Nothing models whether the network *permits* reaching them, so the
Phase 0 illustrative contradiction ("description says metadata access is blocked, NetworkPolicy
permits link-local") is **not** currently detectable end to end.

That last sentence is the honest cost of this deferral and is the reason it is written down
rather than left implied.

## D4 — Bandit / external analyser integration

**Status: deferred with a written design precondition. Candidate for Phase 3 or later.**

Governed by `docs/SPEC_external_analyser_integration.md`, whose placement questions were
decided on 2026-07-22: external analysers stay out of the core scan path, each becoming its
own optional command. The `trustlens rbac` helper is the first thing built to that spec and
demonstrates the shape works.

**In its place now:** no external tool contributes to any `FOUND` or
`NOT_FOUND_WITHIN_ANALYSED_SCOPE` claim. Only Bandit has verified failure reporting; Semgrep,
gitleaks, syft and osv-scanner remain excluded.
