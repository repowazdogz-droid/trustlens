# TrustLens

**TrustLens compares what an ML dataset or repository is declared to be with what static
analysis, deployment configuration, and controlled execution show it can actually do. It
maps potential credential and network reachability and simulates evidence-supported blast
radius. It does not determine malicious intent, certify artifacts as safe, or guarantee
containment.**

---

## Status: all four phases built.

| Phase | Component | Status |
|---|---|---|
| 0 | Grounding + shared evidence model | **complete** |
| 1 | Dataset and repository trust scanner | **complete** — 10 check families, CLI, clean-clone verified |
| 2 | Credential reachability mapper | **complete** — Terraform + Kubernetes RBAC ingest, cross-domain IRSA join, optional Go RBAC helper; partial-but-closed against scope (see [`docs/DEFERRED.md`](docs/DEFERRED.md)) |
| 3 | Sandboxed dry run | **complete** — gVisor, `EXPERIMENTAL` by construction; 12-probe conformance suite; SO-1 + SO-2 signed off (see [`docs/SIGN_OFF.md`](docs/SIGN_OFF.md)) |
| 4 | Blast radius simulator | **complete** — composes static + configured + dynamic evidence into reachability paths, each labelled by how it was established |

**The sandbox is `EXPERIMENTAL` and gVisor-scoped.** It was signed off for artifacts whose
threat model is hostile *userspace* code — not for kernel-exploitation artifacts, which is
the class the July 2026 incident actually represented. That boundary is enforced in code,
not just documented: `status.promote()` refuses to leave `EXPERIMENTAL` on a gVisor-only
configuration. See [`SANDBOX_THREAT_MODEL.md`](SANDBOX_THREAT_MODEL.md) §2.1.

TrustLens is four components over one evidence model, each with its own guarantee. The
**scanner** performs static analysis only — it spawns **no processes at all** while
scanning, demonstrated by `tests/scanner/test_inertness.py` (detonate live payloads to prove
they fire, then scan them with `subprocess`, `os.system` and `socket` replaced by objects
that raise). The **mapper** models credential reachability from offline configuration and
spawns nothing. The **sandbox** observes execution inside gVisor and is `EXPERIMENTAL`. The
**blast-radius** simulator composes all three offline into reachability paths.

```bash
pip install -e .
trustlens scan ./some-dataset-repo                 # static analysis; 0 clean · 1 findings · 2 did not complete
trustlens map-credentials ./env-description.json   # offline credential reachability; spawns nothing
trustlens rbac ./k8s-manifests                     # OPTIONAL: upstream Kubernetes authorizer (Go helper), explicit
trustlens plan  https://host/org/repo              # dry run; writes nothing, pins a commit
trustlens acquire https://host/org/repo ./dest --i-am-authorised   # explicit fetch at a pinned commit
trustlens blast-radius --scan scan.json --env env.json   # offline composition of the above into paths
```

The sandbox has no CLI subcommand: running untrusted code is gated behind the `EXPERIMENTAL`
lock and a human sign-off, so it is a library surface, not a one-command entry point.

Exit code `2` matters: an incomplete analysis never exits `0`, because a caller reading only
the exit code would otherwise treat "could not finish" as "found nothing".

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

## A note on the synthetic "unsafe" fixtures

`examples/repos/unsafe_*` and `tests/fixtures/` ship deliberately dangerous-looking code —
`subprocess(..., shell=True)`, `pickle.loads`, unsafe YAML tags, credential-shaped paths.
They exist because a scanner's positive controls must contain what it claims to detect: a
control set that has never fired on a real trigger is not evidence that it works. Every
dangerous call sits inside a **never-invoked method**, points at **nothing real** (config
that resolves nowhere, canary paths), uses **no live credentials**, and makes **no external
network contact**; each file is labelled in-source as a TrustLens fixture. The inertness
harness proves the point by detonating armed copies in a temp directory and then showing the
scanner touches none of it (`tests/scanner/test_inertness.py`).

Because these files carry malware-shaped *patterns*, **automated scanners — GitHub's, an
AV engine, a corporate proxy — may flag them.** That is expected, not a compromise: the
patterns are the fixtures' whole purpose. Nothing here is executable as an exploit.

## Documents

| File | Contents |
|---|---|
| [`GROUNDING.md`](GROUNDING.md) | What already exists, what to reuse, integrate, or not rebuild, and the remaining gap |
| [`SCHEMA.md`](SCHEMA.md) | The shared evidence model, the status taxonomy, hashing, versioning |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How the four components compose |
| [`CLAIMS.md`](CLAIMS.md) | What the evidence establishes, and next to it what it does not |
| [`LIMITATIONS.md`](LIMITATIONS.md) | Live limitations, including ones inherent to the approach |
| [`SECURITY.md`](SECURITY.md) | Safe-operation rules and handling of untrusted artifacts |
| [`SANDBOX_THREAT_MODEL.md`](SANDBOX_THREAT_MODEL.md) | The sandbox's attacker model, boundary, and the gVisor scope — `SIGNED OFF — SCOPED` |
| [`docs/SIGN_OFF.md`](docs/SIGN_OFF.md) | The human sign-off record (SO-1 isolation choice, SO-2 probe suite) and what remains ungranted |
| [`docs/DEFERRED.md`](docs/DEFERRED.md) | Work deliberately deferred, with reasons and what stands in its place |
| [`docs/COVERAGE_GAPS.md`](docs/COVERAGE_GAPS.md) | Defects found by running rather than by tests — where current coverage ends |
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
