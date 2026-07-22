# TrustLens

**TrustLens compares what an ML dataset or repository is declared to be with what static
analysis, deployment configuration, and controlled execution show it can actually do. It
maps potential credential and network reachability and simulates evidence-supported blast
radius. It does not determine malicious intent, certify artifacts as safe, or guarantee
containment.**

---

## Status: Phase 0 complete. No scanning yet.

| Phase | Component | Status |
|---|---|---|
| 0 | Grounding + shared evidence model | **complete** |
| 1 | Dataset and repository trust scanner | not started |
| 2 | Credential reachability mapper | not started |
| 3 | Sandboxed dry run | not started — `EXPERIMENTAL` by construction when it lands |
| 4 | Blast radius simulator and mitigation engine | not started |

Nothing in this repository currently scans an artifact, models an environment, executes
anything, or simulates a blast radius. What exists is the evidence model every component
will emit into, its validation, and the reuse-versus-build decisions recorded in
[`GROUNDING.md`](GROUNDING.md).

## Why the schema came first

The product is the *comparison* — declared against static against configured against
dynamic. That comparison only works if four components describe the same capability with
the same identifier and the same honesty about scope. A vocabulary retrofitted after four
components exist becomes a lossy translation layer, and the losses land exactly where the
value is.

## The one rule the model is built around

A check that could not complete must never be reportable as a check that completed and
found nothing.

```
FOUND                            evidence exists
NOT_FOUND_WITHIN_ANALYSED_SCOPE  analysis completed over this scope and matched nothing
PARTIAL                          analysis started and did not complete over all of it
UNSUPPORTED                      this construct cannot be assessed at all
UNKNOWN                          not attempted, ambiguous, or information unavailable
```

Five states, not four. `PARTIAL` is the one that gets lost, and losing it turns a parse
failure into a clean bill of health. Four independent barriers keep it apart from
`NOT_FOUND_WITHIN_ANALYSED_SCOPE`:

1. **Construction** — the builder raises rather than emitting the invalid pairing.
2. **Structure** — the JSON Schema requires `scope.failed` to be empty for a clean result
   and non-empty for `PARTIAL`.
3. **Aggregation** — the precedence lattice makes a clean aggregate reachable only when
   every input was clean; an empty aggregate is `UNKNOWN`, never clean.
4. **Consumption** — `require_absent()` raises instead of returning a boolean a caller can
   ignore, and comparing a `Status` to a string raises rather than silently returning
   `False`.

**No status in this taxonomy ever establishes that a capability is absent from an
artifact.** `NOT_FOUND_WITHIN_ANALYSED_SCOPE` bounds a scope, not a world.

Tests: [`tests/schema/test_partial_is_not_absence.py`](tests/schema/test_partial_is_not_absence.py).

## Try it

```bash
git clone <repo> trustlens && cd trustlens
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

PYTHONPATH=. python3 examples/generate_examples.py
git diff --exit-code examples/records/     # regeneration is byte-identical by design
python3 -m pytest tests -q
```

Four example records — one per component, including a `PARTIAL` result and an
`EXPERIMENTAL` sandbox record — are written to `examples/records/`.

## What a record looks like

```
Declared:
  Repository type: dataset
  Dataset card describes tabular passive data
  No custom execution requirement declared

Reachable within analysed scope:
  [FOUND]     execution.dynamic_import      loader.py:14   importlib.import_module
  [FOUND]     network.outbound              loader.py:31   urllib.request.urlopen
  [NOT_FOUND_WITHIN_ANALYSED_SCOPE] process.shell
              analysed 17 Python files · rules process-shell v1.2.0 · excluded vendor/
  [PARTIAL]   template.injection_surface
              analysed 4 of 5 config files
              not analysed: config/legacy.yaml (decode error: not valid UTF-8)
  [FOUND]     filesystem.write_outside_scratch  loader.py:52

Structural discrepancy:
  Declared passive data; execution and network behavior statically reachable
```

The risk label decomposes into independently visible findings and never replaces them.

## Documents

| File | Contents |
|---|---|
| [`GROUNDING.md`](GROUNDING.md) | What already exists, what to reuse, integrate, or not rebuild, and the remaining gap |
| [`SCHEMA.md`](SCHEMA.md) | The shared evidence model, the status taxonomy, hashing, versioning |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How the four components compose |
| [`CLAIMS.md`](CLAIMS.md) | What the evidence establishes, and next to it what it does not |
| [`LIMITATIONS.md`](LIMITATIONS.md) | Live limitations, including ones inherent to the approach |
| [`SECURITY.md`](SECURITY.md) | Safe-operation rules and handling of untrusted artifacts |
| [`SANDBOX_THREAT_MODEL.md`](SANDBOX_THREAT_MODEL.md) | Placeholder — the sandbox does not exist |
| [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) | Clean-clone verification and known reproducibility gaps |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Controls every check must ship with, and claims discipline |

## What TrustLens does not claim

- That it prevented, or would have prevented, any security incident.
- That it detects all malicious ML artifacts.
- That a clean result means an artifact is safe.
- That a sandbox result certifies containment.
- That a finding indicates malicious intent.
- That a simulated path is a proven exploit chain.

On the July 2026 Hugging Face disclosure specifically, the permitted framing — and the
only one used here — is: *this class of tool could surface execution, credential, and
reachability gaps of the kind involved in the incident.* See [`CLAIMS.md`](CLAIMS.md).
