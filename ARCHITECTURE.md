# Architecture

## The shape of the problem

An artifact arrives presented as data — a dataset repository, a model repository, an
archive. Processing it inside ML infrastructure can execute code, read credentials, and
reach services. Four questions follow, and they are answered by different kinds of
evidence that are usually produced by different tools and never combined:

| Question | Evidence kind | Component |
|---|---|---|
| What does it say it is? | declared | scanner (declared surface) |
| What can its code do? | static | scanner (static checks) |
| What could that reach here? | configured | credential reachability mapper |
| What does it actually do? | dynamic | sandbox |
| What follows if it does? | composed | blast radius simulator |

TrustLens's structural bet is that the *comparison* between these is the product, not any
one of them. Existing tools produce fragments in incompatible shapes; a fragment cannot be
compared with another fragment.

## The evidence spine

Everything hangs off one shared record format (`SCHEMA.md`). Each component reads
artifacts or descriptions and emits evidence records; the simulator consumes records
rather than re-analysing anything.

```
                  ┌──────────────────────────────────────────────┐
   artifact ─────▶│ Phase 1  SCANNER                             │
   (dir/zip/git/  │   declared surface  →  declared_capabilities │
    HF repo)      │   static checks     →  findings (static)     │──┐
                  └──────────────────────────────────────────────┘  │
                                                                    │
   environment    ┌──────────────────────────────────────────────┐  │
   description ──▶│ Phase 2  CREDENTIAL REACHABILITY MAPPER      │  │
   (+ captured_at)│   offline policy/config evaluation           │──┤
                  │   → findings (configured) + contradictions   │  │
                  └──────────────────────────────────────────────┘  │
                                                                    │  evidence
   artifact ─────▶┌──────────────────────────────────────────────┐  │  records
   (opt-in)       │ Phase 3  SANDBOX          [EXPERIMENTAL]     │  │
                  │   one recorded execution under one profile   │──┤
                  │   → findings (dynamic + dynamically blocked) │  │
                  └──────────────────────────────────────────────┘  │
                                                                    ▼
                  ┌──────────────────────────────────────────────────────────┐
                  │ Phase 4  BLAST RADIUS SIMULATOR                          │
                  │   compose records → paths, each edge labelled by kind    │
                  │   → finding-specific mitigations + residual uncertainty  │
                  └──────────────────────────────────────────────────────────┘
```

Each component is independently useful and independently verifiable. Phase 4 adds no new
observation; it only composes, which is why it must declare its `input_records` and why a
composed edge can never be stronger than its weakest input.

## Why the schema is the first thing built

The comparison only works if all four components describe the *same capability* with the
*same identifier* and the *same honesty about scope*. A shared vocabulary bolted on after
four components exist becomes a lossy translation layer, and the losses land exactly where
the product's value is: in the discrepancy between what was declared and what was found.

So Phase 0 defines the vocabulary (`capability`), the reach of evidence
(`evidence_strength`), how it was produced (`detection_method`), and — most importantly —
the five-state status taxonomy, which is what stops a comparison being drawn against a
check that did not finish.

## Design rules that shaped the code

**Evidence at the point of reachability.** A finding anchors where the behavior becomes
reachable — `loader.py:14`, a policy statement, a network event — not at the top of a
file. Inherited from `mcp-boundary-audit`, along with the `declared_*` versus `observed_*`
split, deterministic content hashing, dry-run defaults, and explicit skip records with
per-item reasons.

**Fail closed, structurally.** Wherever an honest and a flattering reading both exist, the
flattering one is made inexpressible rather than discouraged. A completed-clean status
cannot coexist with a failed scope item. An `EXPERIMENTAL` sandbox cannot list approved
profiles. Generic advice cannot exist without a specific mitigation. A vacuous check is
flagged vacuous. These are schema conditionals, not conventions.

**Method and strength must agree.** A configuration-derived edge cannot be recorded with
an observation's weight, because the schema binds `detection_method` to
`evidence_strength`. This is what keeps a Phase 2 modelled path visually and structurally
distinct from a Phase 3 observed one when Phase 4 renders them together.

**Staleness travels with the evidence, not with the document.** Every configuration-derived
finding carries the `description_captured_at` of the description it came from, and so does
everything derived from it. A six-month-old model says so at every edge that depends on
it, rather than once in a file the reader may never open.

**Contradictions are recorded, never reconciled.** When declared, configured, static and
dynamic evidence disagree, that disagreement is the finding. The schema pins `reconciled`
to `false` in machine-produced records.

## Component boundaries

**Phase 1 — scanner.** Reads an artifact. Never imports, executes, unpickles or
deserialises it; structural inspection only. Dispatches parsers on content, not on file
extension. Emits declared capabilities with verbatim evidence, plus one finding per check
per capability.

**Phase 2 — credential reachability mapper.** Reads an offline environment description and
policy documents. No live credentials, no cloud API calls. Builds a typed node/edge graph
and distinguishes configured, inferred, blocked and unknown reachability. Every input
carries a mandatory `description_captured_at`.

**Phase 3 — sandbox.** Optional, opt-in, and `EXPERIMENTAL` in a machine-readable state
the runtime enforces. Records one execution under one recorded profile. Leaving
`EXPERIMENTAL` requires a validated review record; editing documentation changes nothing.

**Phase 4 — blast radius simulator.** Consumes records. Adds no observation. Labels every
edge with its evidence kind and refuses to render an inferred or incomplete path with the
confidence of an observed one. Produces mitigations tied to specific finding ids.

## Integration boundary

TrustLens integrates rather than reimplements wherever an established tool performs a
function reliably, offline, under a workable licence. What it builds is the connective
tissue those tools do not provide: a shared record format, declared-versus-observed
comparison, contradiction reporting, evidence provenance with propagating staleness, and
finding-specific mitigation.

Integrated tools are invoked as subprocesses or imported as libraries, and every run
records the tool name, the version actually executed, and how that version was
established. A third-party verdict enters TrustLens as *evidence with a version attached*,
never as an oracle — existing ML artifact scanners have documented, exploited false-clean
failure modes, so a clean third-party verdict is recorded as what that tool reported at
that version, and nothing more.

Per-tool reuse-versus-build decisions are in `GROUNDING.md`.

## Repository layout

```
schemas/            versioned JSON Schema: record, finding, shared defs, enums
trustlens/evidence/ status taxonomy, canonical hashing, builders, validation, consumption
examples/           generated example records, one per component
tests/schema/       evidence-model tests, incl. the four PARTIAL barriers
docs/               per-component documentation as phases land
```

Components are added as `trustlens/scanner/`, `trustlens/credential_mapper/`,
`trustlens/sandbox/`, `trustlens/blast_radius/`, each with its own `CLAIMS.md`, fixtures
and controls.
