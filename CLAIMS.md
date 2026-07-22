# TrustLens — claims and bounds

Each component carries its own `CLAIMS.md` stating what its evidence establishes and, next
to it, what the same evidence does not establish. This file covers the project as a whole.
Component files, as each phase lands:

- `trustlens/scanner/CLAIMS.md` (Phase 1)
- `trustlens/credential_mapper/CLAIMS.md` (Phase 2)
- `trustlens/sandbox/CLAIMS.md` (Phase 3)
- `trustlens/blast_radius/CLAIMS.md` (Phase 4)

At Phase 0 only the shared evidence model exists, so only its claims are live. The rest are
listed as **not yet claimable** rather than stated in advance.

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

## Not yet claimable

Nothing in this repository currently establishes anything about scanning, credential
reachability, sandboxed execution, or blast radius. Those claims become available only
when the corresponding phase lands with its controls passing, and each will be stated in
its own component file.

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
