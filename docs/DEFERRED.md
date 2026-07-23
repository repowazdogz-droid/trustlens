# Deferred work register

Work that was **decided against for now**, not forgotten. Each item names why it was
deferred, what it would take, what currently stands in its place, and its schedule.

The distinction this file exists to preserve: a deliberate deferral has a reason and a
schedule; a forgotten item has neither, and after a few months they are indistinguishable
from the outside. Anything that leaves scope goes here with its reasoning intact.

**On the schedule column:** these were originally tagged "Phase 3+". All four phases have now
shipped *without* them — deliberately, each for the reason stated below — so the honest label
is **unscheduled**: still deferred, no longer pinned to a phase that has already passed.

| # | Item | Deferred | Schedule | Currently in its place |
|---|---|---|---|---|
| D1 | IAM condition evaluation | 2026-07-22 | unscheduled (post-v1) | A stated limitation on every IAM-derived edge |
| D2 | `policy_sentry` integration | 2026-07-22 | unscheduled (post-v1) | Actions recorded as opaque strings |
| D3 | Network-policy reachability | 2026-07-22 | unscheduled (post-v1) | Phase 1 detects metadata endpoints statically; no `network.*` edges exist |
| D4 | Bandit / external analyser integration | 2026-07-22 | unscheduled (post-v1) | No external tool in any FOUND/NOT_FOUND claim |
| D5 | `dynamic-import` builtin suffix-match (`__import__`) | 2026-07-23 | unscheduled | Left as-is; shares the fixed re.compile pattern but no benign false positive demonstrated |

---

## D1 — IAM condition evaluation

**Status: deliberately not built. Unscheduled (post-v1) — all four phases shipped without it.**

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

**Status: not built. Unscheduled (post-v1) — all four phases shipped without it.**

Would supply offline AWS action → access-level → ARN-format metadata, so an `s3:GetObject`
edge could be classified as a *read* rather than left as an opaque action string. MIT,
pure-Python, bundled SQLite database, verified permissive in Phase 0.

**Open question that must be answered first (carried from
`docs/SPEC_phase2_credential_mapper.md`):** whether the bundled database is current enough
for the actions TrustLens needs, and what its refresh story is. Integrating a stale action
database would produce confidently wrong access-level classifications.

**In its place now:** actions are recorded verbatim as strings, with no access-level claim.

## D3 — Network-policy reachability

**Status: not built. Unscheduled (post-v1) — all four phases shipped without it.**

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

**Status: deferred with a written design precondition. Unscheduled (post-v1).**

Governed by `docs/SPEC_external_analyser_integration.md`, whose placement questions were
decided on 2026-07-22: external analysers stay out of the core scan path, each becoming its
own optional command. The `trustlens rbac` helper is the first thing built to that spec and
demonstrates the shape works.

**In its place now:** no external tool contributes to any `FOUND` or
`NOT_FOUND_WITHIN_ANALYSED_SCOPE` claim. Only Bandit has verified failure reporting; Semgrep,
gitleaks, syft and osv-scanner remain excluded.

## D5 — `dynamic-import` builtin suffix-match (`__import__`)

**Status: not fixed. Deferred 2026-07-23, following the first external study's fix pass.
Unscheduled.**

The first external study surfaced a false positive where the `exec-eval-builtin` rule's bare
`compile` target suffix-matched `re.compile` (study `DIVERGENCE_CATALOGUE.md` D1). That rule was
fixed by qualifying its builtin targets to unqualified calls only (`Rule.match_suffix=False`).

The by-design matcher audit that followed (`study/POST_STUDY_FIXES.md`) checked every call rule
with a bare target. One other rule shares the same *structural shape*: `dynamic-import` targets
the bare builtin `__import__`, so `x.__import__(...)` on an arbitrary object would suffix-match.

**Why deferred rather than fixed now.** Unlike `re.compile` / `df.eval` / `model.compile` —
common, benign calls that are genuinely unrelated to code evaluation — `x.__import__(...)` is
almost always the real import mechanism, and **no benign false positive has been demonstrated**.
That absence is the reason to *defer*, not evidence the shape is fine: it shares the exact defect
pattern that was found by accident on one repo, and it has simply not yet been hit. The honest
state is "unfixed, same pattern, no demonstrated FP" — recorded here so it is a named, dated item
rather than a footnote in one session.

**What would unblock it.** Either a demonstrated benign `x.__import__` false positive (fix it),
or a deliberate decision to apply `match_suffix=False` to `dynamic-import` for consistency
(qualifying `__import__` to the builtin loses no real coverage — an unqualified `__import__()`
and `importlib.import_module` both still match exactly). Left as an explicit choice, not made
silently.

**In its place now:** the rule is unchanged; a bare `__import__` still suffix-matches, with the
FP risk assessed as negligible but non-zero.
