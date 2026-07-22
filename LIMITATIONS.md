# Limitations

Kept adjacent to the claims rather than filed away from them. Every limitation here is
live at the current phase; limitations of unbuilt components are marked as such rather
than omitted, because an empty section reads as "no limitations".

## Current phase

**Phase 0 complete. Phases 1–4 not built.** Nothing in this repository scans an artifact,
models an environment, executes anything, or simulates a blast radius. The evidence model
and its validation exist; the components that would emit real records do not.

## Limitations of the shared evidence model

**The schema constrains statement, not truth.** A record can be perfectly conforming and
completely wrong. Every structural guarantee is about how evidence is expressed — scope
recorded, strength matched to method, incompleteness propagated — and none of them is
about whether the underlying analysis was right.

**Validation is opt-in at the boundary.** The four barriers against conflating `PARTIAL`
with `NOT_FOUND_WITHIN_ANALYSED_SCOPE` cover construction, structure, aggregation and
consumption. A component that bypasses the library and writes JSON directly is caught only
by `validate_record`, and only if something calls it. Phase 1 onward must validate on
write and on read; that is a discipline the schema cannot enforce on code that refuses to
use it.

**Cross-record propagation is unchecked without a corpus.** Validating a composing record
in isolation cannot resolve parents that live in other records, so strength and
incompleteness propagation are not verified. The validator reports this explicitly rather
than returning clean, but a caller that ignores the report gets no protection. Phase 4
must call `validate_record(record, corpus=...)`.

**`description_captured_at` is unverifiable.** TrustLens records whether a capture
timestamp was asserted by an operator or exported by a tool, and cannot check either. A
confidently wrong timestamp produces a confidently wrong staleness display.

**Capability categories are a fixed vocabulary chosen in advance.** An artifact whose
behavior does not map onto one of the listed categories has nowhere to be recorded except
as an unsupported construct. The vocabulary will be wrong in ways not yet visible.

**Deterministic finding ids are scope-sensitive by design, which has a cost.** Re-running
after excluding a directory produces different finding ids, so a diff between the two runs
shows changes that are really scope changes. That is the intended behavior — a silently
narrowed scope must not look like an unchanged result — but it makes naive run-to-run
diffing noisier than a scope-insensitive id would.

**No schema migration has been exercised.** The versioning rules in `SCHEMA.md` are stated
and untested; there is exactly one schema version and no migration function yet.

## Limitations inherited from the problem, not from the implementation

These do not go away when the components are built. They are properties of static
analysis, offline configuration modelling, and sandboxed observation.

**Static analysis cannot establish runtime reachability.** A construct found in a file may
never execute. A construct absent from analysed files may be produced at runtime by code
that builds it. `FOUND` and `NOT_FOUND_WITHIN_ANALYSED_SCOPE` both stop short of the
runtime claim a reader wants.

**Obfuscated, conditional and time-delayed behavior is out of reach.** An artifact that
behaves differently on the tenth invocation, or in a different region, or only when a
particular environment variable is set, will not reveal that to a static scan or to a
single sandboxed run.

**Offline configuration analysis is only as good as the description.** It cannot discover
a policy it was not given, and it cannot know that the description no longer matches
production. Staleness is structural, not incidental.

**A sandbox observation is one run.** It establishes what happened with those inputs under
that profile. It does not establish what happens with other inputs, and no finite set of
runs establishes the absence of dormant behavior.

**A composed path is a model.** Combining a static finding with two configuration-derived
findings produces a modelled path, not a demonstrated one, and the composition cannot
establish that the path is traversable end to end.

**Scanner-evasion is a live and demonstrated failure class.** Published vulnerabilities in
existing ML artifact scanners show parse dispatch on file extension, fail-open handling of
corrupt archives, and exact-match blocklists each producing a clean verdict on a malicious
file. TrustLens is subject to the same class. Its mitigations — content sniffing rather
than extension dispatch, and a parse failure forced to `PARTIAL` rather than clean — reduce
two specific instances and do not make the tool immune to the class. See `GROUNDING.md`.

## Things TrustLens deliberately does not do

Not gaps to be closed later; boundaries.

- No exploitation, no payload generation, no evasion, no scanning of systems the user has
  not initiated analysis of.
- No claim of malicious intent. TrustLens reports capability and discrepancy; attributing
  intent to an artifact is a human judgement it does not make.
- No safety certification. There is no output of TrustLens that means "this is safe".
- No silent remote acquisition. Anything that fetches requires explicit initiation and a
  dry-run first.
