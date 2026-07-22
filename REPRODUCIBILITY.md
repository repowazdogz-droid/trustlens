# Reproducibility

The whole workflow must be reproducible from a clean clone. If a result cannot be
re-derived by someone who was not present when it was produced, its hashes and provenance
fields are decoration.

## Verify Phase 0 from a clean clone

```bash
git clone <repo> trustlens && cd trustlens
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Regenerate every example record from source.
PYTHONPATH=. python3 examples/generate_examples.py

# Nothing should have changed: regeneration is byte-identical by design.
git diff --exit-code examples/records/

# Run the evidence-model test suite, including the PARTIAL enforcement tests.
python3 -m pytest tests -q
```

Expected: `examples/generate_examples.py` writes four records, `git diff --exit-code`
returns 0, and the test suite passes. A non-zero diff means determinism has been broken
and the `content_hash` guarantee no longer holds.

## What makes the records reproducible

**Canonical serialisation.** Sorted keys, no insignificant whitespace, UTF-8, and
floating-point values rejected rather than serialised. A float's shortest round-trip form
differs across languages, so admitting one would make hashes unreproducible by an
independent implementation.

**Derived fields excluded from the hash.** `content_hash` covers the record with
`record_id`, `content_hash` and `run.completed_at` removed, so two runs producing identical
evidence hash identically regardless of how long each took.

**Deterministic identifiers.** `finding_id` is a digest over the component, capability,
rule id, rule version, normalised evidence coordinates and the sorted analysed scope. Two
runs of the same rules over the same files produce the same ids, so runs can be diffed.

**Fixed inputs in the generator.** Example timestamps, commits and hashes are constants.
The generator calls no clock and no random source.

## What is recorded so a run can be repeated

Every evidence record carries:

- `tool.version`, `tool.commit`, and `tool.commit_dirty` — a dirty working tree means the
  record is *not* reproducible from the recorded commit alone, and the flag says so.
- `tool.external_tools[]` — each third-party analyser with the version actually executed
  and how that version was established (`reported_by_tool`, `declared_in_lockfile`, or
  `unknown`; `unknown` is permitted and is more honest than a guess).
- `run.invocation` — the argv used.
- `run.config_hash` — SHA-256 of the configuration file, or null.
- `artifact.content_hash` with `content_hash_method`, and `artifact.immutable_reference`
  (commit or revision). A null immutable reference means the acquisition is not
  reproducible, and that must appear in the record's limitations.
- `input_records[]` — for composing components, the `record_id` and `content_hash` of every
  input, so a changed input is detected rather than assumed away.

## Known reproducibility gaps

**Third-party analyser versions are recorded, not pinned.** From Phase 1 the scanner will
invoke external tools. Their rule sets change, so an identical TrustLens version can
legitimately produce different findings on different days. The record captures which
version ran; it does not freeze it. Comparing two runs requires comparing
`tool.external_tools` as well as `content_hash`.

**Remote acquisition is only as immutable as the source allows.** A git commit or a Hub
revision pins content; a plain HTTP download does not. Where no immutable reference is
obtainable, the record says so rather than implying reproducibility it does not have.

**Sandbox runs are not bit-reproducible** and will not be. Phase 3 records the exact
profile, image hash, isolation version and host kernel so a run can be *repeated*; two
repetitions are not expected to produce identical records, and the schema does not pretend
otherwise.

**Schema migrations are untested.** There is one schema version and no migration has been
exercised.
