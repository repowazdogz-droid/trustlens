# Contributing

## The rule that matters most

**A check that could not complete must never be reportable as a check that completed and
found nothing.**

Most of the review burden in this project is on that one rule. It is enforced at four
independent points — construction, JSON Schema, semantic validation, and the consumption
API — and a change that weakens any of them is a breaking change even if every test still
passes. If you find yourself wanting to make a `PARTIAL` "just be a `NOT_FOUND`" because it
is producing noisy reports, the report is correct and the noise is the finding.

## Before you add a check

1. **Search first.** Phase 0 established which existing tools already do which jobs. If an
   established tool performs the function reliably, integrate it rather than
   reimplementing it, and record the decision in `GROUNDING.md`. Reimplementation needs a
   reason: licence, offline operation, output shape, or a coverage gap.
2. **State the invariant.** What does this check assert, and what is it blind to? The
   blind spot goes in the finding's `limitations`, which is a required non-empty field.
3. **Decide the failure mode.** What does the check do when a file will not parse, a tool
   exits non-zero, or a timeout fires? The answer is `PARTIAL` with the path and reason
   recorded. It is never a silent skip and never a clean result.

## Every check needs controls

A check with no controls is an assertion, not a check. Ship all of:

- **Positive control** — a fixture the check must flag, with the specific expected
  capability, rule id and evidence location.
- **Negative control** — a clean fixture the check must not flag.
- **False-positive controls** — the constructs that look like the target but are not: a
  string containing `subprocess`, a comment naming a dangerous function, safe YAML
  loading, a network library imported but never called, a write confined to a declared
  scratch directory.
- **A `PARTIAL` control where applicable** — a fixture that cannot be fully analysed, to
  prove the distinction is enforced in code rather than described in prose.
- **A test that the control actually executes.** A fixture sitting in the repository is
  not evidence the tool detects it. The test must assert the finding, not the exit code.

Synthetic unsafe fixtures must contain no real malware, use no live credentials, make no
external network contact, be clearly labelled as test fixtures, and be safe to run only
where runtime execution is explicitly under test.

## Claims discipline

Any prose that ships — README, reports, CLI output, docstrings — follows the same rule:
state what the evidence establishes, and next to it what the same evidence does not
establish. Not in a footnote, not in a distant disclaimer.

Specific bans:

- Never write that TrustLens prevented, or would have prevented, any incident.
- Never write that a clean result means an artifact is safe.
- Never write that a sandbox result certifies containment.
- Never present a simulated path as a proven exploit chain.
- Never present an inferred edge with the same visual weight as an observed one.

If a claim needs a caveat to be true, rewrite the claim to be true without one.

## Schema changes

Read the versioning rules in `SCHEMA.md` first. In particular: any change to the five
statuses, their semantics, or the barriers keeping `PARTIAL` and
`NOT_FOUND_WITHIN_ANALYSED_SCOPE` apart is a MAJOR change regardless of how small the edit
looks. Adding a capability category is MINOR. Records are never rewritten in place to a new
version; migration produces a new record and retains the original.

## Running the checks

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 examples/generate_examples.py
git diff --exit-code examples/records/     # regeneration must be byte-identical
python3 -m pytest tests -q
```

Every phase is verified from a clean clone before it is committed, and phases are
committed separately. Do not merge phases.

## Code conventions

- Python 3.11+. No dependency is added to the base install unless Phase 0 needs it;
  analysis engines belong to the phase that integrates them, so that a clean clone can
  verify the evidence model without installing a scanner.
- Build records through `trustlens.evidence.builder`, never by assembling dicts. The
  builder raises where a hand-built dict would merely fail validation later, when the
  context has been lost.
- Validate on write and on read. Composing components validate with
  `corpus=` so that cross-record propagation is actually checked.
- Never store a credential value. Record variable names and mount paths; set `redacted`
  where a value would otherwise appear.
- Never dispatch a parser on a file extension. Sniff content. Extension-based dispatch is
  a documented, exploited evasion against existing ML artifact scanners.
