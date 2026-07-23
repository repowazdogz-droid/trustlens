# Blast radius simulator — claims and bounds

**Status: Phase 4 built.** `execution_mode: offline_modelling` — it reads evidence records
and composes them. It acquires nothing, executes nothing, observes nothing itself, and spawns
no processes. See [`docs/SPEC_phase4_blast_radius.md`](../../docs/SPEC_phase4_blast_radius.md).

## What it establishes

- It composes the **scanner (static)**, **mapper/environment (configured)**, and **sandbox
  (dynamic)** evidence into reachability paths from an entry principal to an asset.
- **Every edge is labelled by how it was established** — one of `declared`, `statically_found`,
  `configured`, `inferred`, `dynamically_observed`, `dynamically_blocked`, `unknown`.
- **Every path is rendered at the confidence of its weakest edge.** The path's tier is the
  *minimum* edge rank, so one `inferred` edge caps an otherwise fully-observed path at
  `inferred`, and a `PARTIAL` upstream status caps the path regardless of provenance. This is
  structural: `BlastPath` has only an `edges` field — there is no confidence argument a caller
  could set to assert an unearned strength.
- **A blocked edge marks the path cut, and it is retained and labelled, never dropped.**
  Dropping a blocked or partial path would read as "no such path was considered."
- **A composed path cannot be recorded with an observation's weight.** The record builder's
  `detection_method`↔`evidence_strength` binding forces a composed multi-edge path to
  `graph_derivation` → `INFERRED`; only a single fully-observed edge records as
  `DIRECT_OBSERVATION`. There is no path shape that dresses a composition as an observation.
- The sealed `blast_radius` record conforms to the shared evidence schema and regenerates
  byte-identically.

## What it does not establish

- **That any composed path is traversable end to end.** Edge existence is not path
  traversability; every composed path states this in its own limitations.
- **That a path absent from a record does not exist.** Only the supplied edges were
  considered, and the enumeration is depth-bounded — a hit bound is logged as a coverage
  limit, never as an absence claim.
- **That it prevented, or would have prevented, any incident.** The record's `claims` block
  carries only the permitted framing: this class of tool could surface gaps of the kind
  involved in the July 2026 incident.
- **That the confidence tier reflects real-world likelihood.** It reflects the strength of the
  *evidence for each edge*, capped at the weakest — not a probability that an attacker
  traverses it.

## Known gaps, stated rather than discovered later

- **The capability→node mapping is operator-supplied.** Which principal a scanner capability
  acts as, and which grants exist, are operator facts given in the `--env` file — the tool
  does not infer them from the artifact. A capability with no mapping is skipped, never joined
  to a guessed node.
- **Path enumeration is depth-bounded** (default 8) and cycle-free; the bound-hit case is
  surfaced, not silently truncated.
- **Path status is weakest-link, not `combine()`.** `combine()` takes the strongest status
  ("did any source find it"); a path asks the opposite — "is every hop established?" — so a
  single `PARTIAL` or `UNKNOWN` edge degrades the whole path. Using `combine()` here would let
  one `FOUND` edge mask a `PARTIAL` one, and it was corrected to `weakest_status`.

## Controls

- **Weakest-link invariant** (`tests/blast/test_weakest_link.py`) — a single `inferred` edge
  caps an otherwise fully-observed path; a `PARTIAL` edge flags the path and denies top tier;
  a `blocked` edge cuts it. There is no confidence override to abuse.
- **Blocked-not-dropped and composed-cannot-be-observation**
  (`test_combine_and_paths.py`, `test_record_end_to_end.py`) — a blocked observation becomes a
  labelled path; a graph-derived path records as `INFERRED`, never `DIRECT_OBSERVATION`.
- **End-to-end** — real example records compose into a schema-valid, byte-identical record,
  and the CLI returns an honest exit code (a blocked-only or no-path result is not a finding).
