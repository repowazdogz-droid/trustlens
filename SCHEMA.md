# TrustLens shared evidence schema

**Schema version:** `trustlens/1.0.0`
**Status:** Phase 0 — defined, validated, and blocking all later phases until it holds.

Every TrustLens component — scanner, credential reachability mapper, sandbox, blast
radius simulator — emits records conforming to `schemas/evidence_record.schema.json`.
That is what makes the product's central comparison possible: declared, statically
observed, configured and dynamically observed capability can be set side by side for the
same capability identifier without a translation layer in between.

## Why the schema carries rules rather than just shapes

A schema that only describes shapes lets a component emit a well-formed record that
overstates what it checked. The rules below are therefore enforced structurally, so that
the honest reading is the only expressible one.

| Rule | Enforced where |
|---|---|
| A completed-clean result may not coexist with a failed scope item | JSON Schema conditional, semantic validator, builder |
| `PARTIAL` must name what failed and why | JSON Schema conditional, builder |
| A vacuous check (nothing to examine) is flagged as vacuous | JSON Schema conditional on `scope` |
| A `FOUND` finding has a location, or states why none exists | JSON Schema conditional, builder |
| Detection method and evidence strength must agree | JSON Schema conditionals, builder |
| A derived finding is never stronger than its weakest input | semantic validator |
| Incompleteness propagates across derivation, including across records | semantic validator (with `corpus=`) |
| Every finding carries a non-empty `limitations` list | JSON Schema `minItems`, builder |
| Configuration-derived findings carry their capture timestamp | JSON Schema conditional |
| Generic advice cannot stand in for finding-specific mitigation | JSON Schema conditional, builder |
| Contradictions are never machine-reconciled | JSON Schema `const: false` |
| An `EXPERIMENTAL` sandbox cannot list approved profiles | JSON Schema conditional |
| A blast-radius record must declare the records it composed | JSON Schema conditional, builder |

## Files

```
schemas/
  common.schema.json              shared $defs: scope, evidence location, artifact identity,
                                  tool identity, environment description reference
  finding.schema.json             one check result about one capability
  evidence_record.schema.json     one component run
  enums/
    status.schema.json            the five states, with per-state means / does-not-mean
    capability.schema.json        the shared capability vocabulary
    detection_method.schema.json  how a finding was produced
    evidence_strength.schema.json how far the evidence reaches
```

Schemas are addressed by URN (`urn:trustlens:1.0.0:evidence_record`) rather than by URL.
The identifier is stable and resolvable offline; TrustLens never fetches a schema over the
network.

## The five-state status taxonomy

This is the part of the model most likely to be quietly eroded, so it is stated
precisely.

| Status | Means | Does **not** mean |
|---|---|---|
| `FOUND` | Evidence matching a supported rule, or an observed behavior, exists. | That it is reachable at runtime, malicious, or exploitable. |
| `NOT_FOUND_WITHIN_ANALYSED_SCOPE` | No match among the files, languages, rules, configurations and execution paths actually analysed, **and** analysis completed over all of them. | That the capability is absent from the artifact. |
| `PARTIAL` | Analysis of the intended scope started but did not complete over all of it. | Anything about presence or absence. Strictly weaker than the row above. |
| `UNSUPPORTED` | The component cannot assess the construct at all. | That the construct is absent, or that it was examined and cleared. |
| `UNKNOWN` | Not attempted, ambiguous, or required information unavailable. | Anything about presence or absence. |

**No status in this taxonomy ever establishes that a capability is absent from an
artifact.** `NOT_FOUND_WITHIN_ANALYSED_SCOPE` bounds a scope, not a world.

### PARTIAL is not a weaker clean result

A parse failure and a clean scan are different claims. The first says "I did not finish
looking here"; the second says "I finished looking here and saw nothing here". Only the
second bounds anything, and merging them produces a result indistinguishable from a real
clean scan at exactly the moment someone decides an artifact is fine.

Four independent barriers keep them apart, because one barrier is one bug away from being
absent:

1. **Construction.** `make_finding` raises if asked to build
   `NOT_FOUND_WITHIN_ANALYSED_SCOPE` over a scope with failures, and raises if asked to
   build `PARTIAL` with nothing named as failed.
2. **Structure.** The JSON Schema requires `scope.failed` to be empty for
   `NOT_FOUND_WITHIN_ANALYSED_SCOPE` and non-empty for `PARTIAL`. A hand-assembled record
   carrying the invalid pairing does not validate.
3. **Aggregation.** `combine()` uses a precedence lattice in which
   `NOT_FOUND_WITHIN_ANALYSED_SCOPE` is the weakest element, so a clean aggregate is
   reachable only when every constituent was clean. `combine([])` is `UNKNOWN`, never
   clean.
4. **Consumption.** `CapabilityView.may_assume_absent` is false whenever any contributing
   check is incomplete, and `require_absent()` raises `IncompleteAnalysisError` rather
   than returning a boolean a caller can ignore.

A fifth, smaller guard: `Status` is not a `str` subclass, and comparing one to a string
raises `StatusComparisonError` instead of returning `False`. The silent `False` is the
bug — it sends control into the else-branch, which in almost every downstream shape is
the treat-as-absent branch.

Tests: `tests/schema/test_partial_is_not_absence.py`.

### Precedence ordering

```
FOUND  >  PARTIAL  >  UNKNOWN  >  UNSUPPORTED  >  NOT_FOUND_WITHIN_ANALYSED_SCOPE
```

This is an information ordering, not a severity ranking, and must never be rendered as
one. `UNKNOWN` outranks `UNSUPPORTED` because "we do not know whether this was examined"
is weaker information than "we know this cannot be examined".

## Scope

Every status claim is a claim about a recorded scope. `scope` separates three things that
are routinely conflated:

- **`analysed`** — completed successfully.
- **`excluded`** — deliberately not analysed, by policy or configuration. An exclusion is
  a choice; choices bound a clean result, they do not invalidate it.
- **`failed`** — intended to be covered but not completed. Any non-empty `failed` forces
  `PARTIAL`. This is the structural mechanism, not a convention.

`vacuous` is derived, never supplied: it is true exactly when `analysed` is empty. A
vacuous clean result carries no information and must be rendered distinctly from a
non-vacuous one, so that "we checked 17 files and found nothing" and "there was nothing
of that kind to check" cannot look the same in a report.

## Evidence strength versus detection method

These are separate axes and the schema enforces their agreement, so a
configuration-derived path cannot be recorded with an observation's weight.

| Detection method | Required strength |
|---|---|
| `declared_metadata`, `manual_assertion` | `DECLARED_ONLY` |
| `graph_derivation` | `INFERRED` (and `derived_from` non-empty) |
| `config_derivation`, `policy_evaluation` | `CONFIG_DERIVED` (and an environment description reference) |
| `static_ast`, `static_pattern`, `archive_inspection` | `STATIC_MATCH` |
| `static_ast_dataflow` | `STATIC_DATAFLOW` |
| `static_external_tool` | `STATIC_MATCH` or `STATIC_DATAFLOW` |
| `dynamic_observation`, `dynamic_blocked_observation` | `DIRECT_OBSERVATION` |

Strength ordering, weakest to strongest, used only for composition:

```
DECLARED_ONLY < INFERRED < CONFIG_DERIVED < STATIC_MATCH < STATIC_DATAFLOW < DIRECT_OBSERVATION
```

A derived finding takes the minimum strength of its inputs. The semantic validator rejects
a derived finding that exceeds any parent's strength.

## Staleness travels with the evidence

Any finding derived from an offline environment description carries an
`environment_description_ref` containing `description_captured_at` — when the environment
was *observed*, not when the file was written or parsed — plus `captured_at_basis`, which
records whether a human asserted the timestamp or a tool exported it. TrustLens cannot
verify an operator-asserted capture time and says so.

The reference is attached to the finding, not only to the record header, because findings
are re-composed downstream. A blast-radius edge derived from a Phase 2 finding carries the
same capture timestamp, so a report generated from a six-month-old description says so at
every edge that depends on it.

## Identifiers, hashing and reproducibility

**Canonical form.** JSON with sorted keys, `,`/`:` separators, no insignificant
whitespace, UTF-8, no NaN or Infinity. Floating-point values are **rejected** rather than
serialised: a float's shortest round-trip representation is not identical across
languages, and admitting one would make the hash unreproducible by an independent
implementation, which is the only property that makes computing it worthwhile.

**`content_hash`** = SHA-256 over the canonical body, where the body is the record with
`record_id`, `content_hash` and `run.completed_at` removed. Two runs producing identical
evidence produce an identical `content_hash` regardless of how long each took.

**`record_id`** = first 32 hex characters of SHA-256(`content_hash` ‖ `run.started_at`).
Distinct from `content_hash` by design: two runs with identical evidence share a
`content_hash` — that is what makes reproduction checkable — but identify as different
runs.

**`finding_id`** = `<component>:<capability>:<16 hex>` where the digest covers the source
component, capability, rule id, rule version, normalised evidence coordinates, and the
sorted `analysed` scope. Scope participates deliberately: the same rule reporting a clean
result over a *narrower* set of files is a different finding, and collapsing the two would
let a silently narrowed scope masquerade as an unchanged result. Excerpts do not
participate, so a changed excerpt window does not change the id.

**`artifact.content_hash_method: directory_manifest_v1`** = SHA-256 over a sorted,
newline-delimited list of `<relative_path>\0<sha256>` for every included file. Defined
here so a third party can recompute it.

## Cross-record composition

A record that composes earlier evidence declares its inputs in `input_records`
(`record_id`, `content_hash`, `component`). References to findings in those records are
then resolvable, and the validator checks the recorded `content_hash` against the corpus
copy so that a changed input is detected rather than assumed away.

Validate a composing record with its inputs:

```python
validate_record(blast_radius_record, corpus={r["record_id"]: r for r in inputs})
```

Without `corpus`, cross-record strength and incompleteness propagation **cannot** be
checked. The validator reports that explicitly rather than returning clean — silence is
not a pass. This is a real limitation of validating a composing record in isolation, and
it is recorded in `LIMITATIONS.md` as well as here.

## Versioning and migration

`schema_version` is `trustlens/MAJOR.MINOR.PATCH`, and the same version appears in every
schema `$id`. A test asserts the two cannot drift apart.

| Change | Bump |
|---|---|
| Adding an optional field | MINOR |
| Adding a value to `capability` | MINOR |
| Adding a value to `detection_method` or `evidence_strength` | MINOR |
| Tightening a constraint on an existing field | MAJOR |
| Adding a required field | MAJOR |
| Removing or re-meaning any enum value | MAJOR |
| **Any change to the five statuses or their semantics** | MAJOR |
| Clarifying a description with no validation effect | PATCH |

Rules:

1. **Consumers reject an unrecognised MAJOR.** A reader that does not understand the
   record's structural guarantees must not process it. Failing closed on an unknown MAJOR
   is correct; guessing is not.
2. **A record is never rewritten in place to a new version.** Migration produces a new
   record with a new `record_id`, and the original is retained. Rewriting would break
   `content_hash` and destroy the audit chain it exists to provide.
3. **Migrations live in `trustlens/evidence/migrations/` as pure functions**
   `record -> record`, with a test that migrating an example of version N produces a
   record valid under N+1.
4. **A MAJOR bump requires an entry in the table below** naming what changed and why.
5. **Status semantics are frozen within a MAJOR.** Any change to what a status means, or
   to the four barriers keeping `PARTIAL` and `NOT_FOUND_WITHIN_ANALYSED_SCOPE` apart, is
   a MAJOR change regardless of how small the edit looks.

### Version history

| Version | Date | Change |
|---|---|---|
| `trustlens/1.0.0` | 2026-07-22 | Initial shared evidence model: five-state taxonomy with structural PARTIAL enforcement, scope tri-partition, method/strength agreement, capture-timestamp propagation, cross-record composition provenance, sandbox review-state gating. |

## Worked examples

`examples/records/` contains one record per component, all generated by
`examples/generate_examples.py` so they cannot drift out of conformance:

| File | Component | Demonstrates |
|---|---|---|
| `scanner_record.json` | `scanner` | Declared-versus-reachable discrepancy; `FOUND`, `NOT_FOUND_WITHIN_ANALYSED_SCOPE`, **`PARTIAL`** (undecodable config file) and `UNSUPPORTED` (compiled extension) side by side; two recorded contradictions. |
| `credential_mapper_record.json` | `credential_mapper` | Offline configuration analysis with `description_captured_at` on every derived finding; an `UNKNOWN` where the description is silent; a contradiction between an operator assertion and a NetworkPolicy. |
| `sandbox_record.json` | `sandbox` | `EXPERIMENTAL` status with the banner carried in the evidence record; a blocked metadata attempt and an allowed scratch write. |
| `blast_radius_record.json` | `blast_radius` | Composition with declared `input_records`; one fully-evidenced path and one path that stays `PARTIAL` because an upstream check did not finish; two finding-specific mitigations. |

Regenerate and verify:

```bash
PYTHONPATH=. python3 examples/generate_examples.py
python3 -m pytest tests -q
```

Regeneration is byte-identical by design, and a test asserts it.

## What this schema does and does not establish

**Establishes.** That a conforming record states which scope was analysed, which was
excluded and which failed; which rule at which version produced each finding; how far the
evidence behind each finding reaches; when any configuration input was captured; and that
the record has not been altered since it was sealed.

**Does not establish.** That the findings are correct; that the rules that produced them
are adequate; that the analysed scope was the right scope; that an operator-asserted
capture time is accurate; or that a conforming record is a complete account of the
artifact. The schema constrains how evidence is *stated*, not whether the evidence is
*good*.
