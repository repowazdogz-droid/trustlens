# Phase 4 — blast radius simulator (spec)

Combines the three upstream evidence sources into reachability paths from an entry point to an
asset, **with every edge labelled by how it was established**, and with a hard rule that a path
is never shown at a higher confidence than its weakest edge.

## Inputs

Evidence records, not live systems. Phase 4 is `execution_mode: offline_modelling` — it reads
records the other components already produced and composes them. It acquires nothing and
executes nothing.

1. A **scanner** record (Phase 1) — static findings about what the artifact's code does.
2. A **credential mapper** record / graph (Phase 2) — configured reachability edges.
3. Optionally a **sandbox** record (Phase 3) — dynamic observations, including blocked ones.

Each input is referenced in the output by `record_id` + `content_hash`, so the composition is
reproducible and its sources are auditable.

## The edge provenance labels — the core of this phase

Every edge in the blast-radius graph carries exactly one label saying **how the edge was
established**. This is the requirement the whole phase is built around:

| Label | Meaning | Source |
|---|---|---|
| `declared` | the artifact's own metadata asserts it | declared capabilities |
| `statically_found` | static analysis found the mechanism in code | scanner finding |
| `configured` | a policy or configuration grants it | mapper `CONFIGURED` edge |
| `inferred` | composed/deduced, not directly evidenced | Phase 4 composition |
| `dynamically_observed` | the sandbox watched it happen | sandbox `FOUND` |
| `dynamically_blocked` | the sandbox watched it be refused | sandbox blocked observation |
| `unknown` | the basis could not be determined | anything else |

## Confidence, and the invariant that must not be violated

**A path is rendered at the confidence of its weakest edge. Full stop.** The labels carry a
confidence rank; a path's rank is the minimum over its edges (weakest link). One `inferred`
edge caps an otherwise fully-observed path at `inferred`. This is not a heuristic to be tuned —
it is the invariant that keeps a composed guess from being read as a measurement.

Rank (higher = stronger evidence that the hop is real and traversable):

```
dynamically_observed  5
configured            4
statically_found      3
declared              2
inferred              1
unknown               0
```

`dynamically_blocked` is not on this scale because it is a **negative** observation: an edge
labelled `dynamically_blocked` means the sandbox saw the hop *refused*. A path containing a
blocked edge is a **blocked path** — it is retained and shown, but as cut, never as a live
reachable path. Dropping it silently would read as "no such path was considered".

Two further caps, both from the five-state taxonomy already in the project:

- **PARTIAL edges cap the path.** An edge derived from a finding whose status is `PARTIAL`
  (analysis did not finish) marks the path `PARTIAL`; such a path can never be top-tier,
  regardless of provenance labels. "inferred **or** PARTIAL" is the pair the brief names.
- **Path status = the WEAKEST edge status**, by completeness (`weakest_status`), *not*
  `combine()`. `combine()` takes the strongest status because it answers "did any source find
  the capability"; a path asks the opposite — "is every hop established?" — so a single PARTIAL
  or UNKNOWN edge degrades the whole path. A path is `FOUND` only when every edge is `FOUND`.
  (An early draft used `combine()` here; it let one FOUND edge mask a PARTIAL one — the silent
  upgrade this project exists to prevent — and was corrected.)

So each path carries two independent, both-honest facts: a **provenance confidence tier** (the
weakest-link label) and a **five-state status** (the lattice combination). Neither is allowed
to launder the other.

## Rendering requirement

The human-readable report groups paths by confidence tier and never presents an `inferred`,
`unknown`, `PARTIAL`, or `blocked` path with the same visual weight as a fully
`dynamically_observed` one. The tier label is on every path. A reader skimming must not be able
to mistake a composed path for an observed one.

## Output

A `blast_radius` evidence record (schema already sketched in
`examples/records/blast_radius_record.json`):

- `input_records` — the source records by id + hash.
- `findings` — one per reachability path, `source_component: "blast_radius"`,
  `detection_method: "graph_derivation"`, `evidence.kind: "graph_edge"`, `derived_from` listing
  the composing findings, `evidence_strength` set from the weakest-link label, and
  `limitations` stating plainly what the composition does not establish (e.g. "No edge in this
  path was dynamically observed", "Composition does not establish the path is traversable end
  to end", "This is a simulation, not a penetration test").
- `mitigations` — proposed changes that would remove a path, each with residual risk and
  trade-offs, and `dynamically_verified: false` unless a sandbox observation supports it.

## What Phase 4 must NOT do

- Never render a composed or configured path as observed. (The weakest-link rule.)
- Never drop a blocked or partial path silently. (Retain and label.)
- Never claim a path is traversable end-to-end from the fact that each edge exists. Edge
  existence is not path traversability, and the limitations say so on every composed path.
- Never claim TrustLens would have prevented the July 2026 incident. The record's `claims`
  block carries only the permitted framing.
