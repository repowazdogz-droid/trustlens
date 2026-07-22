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
- **Never bundle, vendor, or `--config`-reference a Semgrep registry rule.** The engine is
  LGPL-2.1 and is invoked as a subprocess; the registry rules are under the Semgrep Rules
  License v1.0, which permits internal business use only and explicitly excludes vendors.
  Ship TrustLens-authored rules only. This is one flag away and looks like reuse.
- Do not claim `STATIC_DATAFLOW` for a flow crossing functions or files. Semgrep CE is
  intra-procedural; interfile taint is a proprietary feature TrustLens does not use.

## Reported numbers come from the tools, never from memory

A stated test count drifted from reality twice in this project — a commit claimed 91 when
the suite ran 84, then 316 when it ran 525. Two instances is a pattern, and a pattern needs
a mechanism.

```bash
python3 scripts/stats.py          # verified stats block; nothing in it is typed
python3 scripts/stats.py --tests  # the collected count alone
git config core.hooksPath .githooks   # required once per clone
```

`.githooks/commit-msg` rejects any commit message whose claimed test count disagrees with a
fresh run. Quote **collected**, not passed: the external-tool probes skip when no analyser
is on `PATH`, so `passed` differs between environments while `collected` does not.

`core.hooksPath` is a per-clone git setting that the repository cannot carry, so
`tests/test_stats_mechanism.py` asserts it is configured. A failure there means the
mechanism is present but inactive.

## The structured-input heuristic for tool reuse

**If consuming an external tool's output requires first producing input more structured
than what that tool itself returns, the tool is not load-bearing — do not adopt it,
regardless of licence, maintenance status, or popularity.**

This generalises from the Phase 2 RBAC survey and applies to every future reuse decision.
Both offline RBAC graph tools (`rback`, `rbac-tool viz`) take structured RBAC JSON and
return *presentation* DOT: node IDs, colours, shapes, legend nodes. To call either,
TrustLens must already have parsed the manifests into typed objects — at which point
constructing the typed edge set directly is strictly less work than parsing the tool's
output back into one, and it yields better data.

The trap the heuristic defends against is that such a tool looks like a strong reuse
candidate on every metric a survey normally checks. `rbac-tool` is Apache-2.0, actively
maintained, backed by a vendor, and does exactly the job by name. It still fails, because
the direction of information flow is wrong: it consumes more structure than it produces.

Ask, before adopting any tool:

1. What structure must I build to call it?
2. What structure do I get back?
3. If (1) is richer than (2), the tool is a renderer or a reporter — useful for humans,
   not load-bearing for evidence. Adopt it for presentation only, or not at all.

A tool that *adds* information — a maintained rule set, a vulnerability database, an
authoritative decision procedure — passes. `picklescan` passes: TrustLens hands it bytes
and gets back opcode analysis it could not produce itself. The upstream Kubernetes
`RBACAuthorizer` passes: TrustLens hands it decoded objects and gets back authorisation
semantics it would otherwise approximate badly.

## Required: verify every parser against real tool-generated input

**Any new parser or ingester must be verified against input produced by the real tool,
format, or ecosystem it targets — before a hand-written fixture is trusted for anything.**
This is a required step, not a matter of diligence. It has caught something every single
time it has been applied, and its absence has caused every parser defect this project has
shipped and then had to fix.

The record, which is why this is a rule and not a habit:

| Parser | Input used | What it caught |
|---|---|---|
| Declared-surface extractor | hand-written fixtures **only** | Four bugs, including false contradictions manufactured on perfectly consistent cards |
| Terraform plan ingester | **real** `tofu plan -out` + `show -json` | `format_version` is 1.2, not the 1.0 in the grounding note |
| Terraform plan ingester | same | `policy` is a JSON **string** needing double-decode, not a nested object |
| Kubernetes RBAC helper | **real** cert-manager release + kubectl `--dry-run=client` | `creationTimestamp: null`, real `nonResourceURLs` rules |

Three confirmed instances is enough. The pattern is that hand-written fixtures encode *what
the author believes the format to be*, so they cannot surface a belief that is wrong — which
is precisely the failure mode a parser test is supposed to catch.

### What counts as real input

In descending order of preference:

1. **Output from the actual tool**, generated locally and committed with provenance —
   `tofu plan`, `kubectl --dry-run=client -o yaml`, `pip download`, a real export.
2. **A released artifact from a real project** — cert-manager's shipped manifests,
   kube-prometheus's ClusterRoles. Real-world quirks included.
3. **A hand-written fixture**, only for cases the above cannot produce: malformed input,
   adversarial input, and deliberately unreachable states. These are legitimate and
   necessary — a corrupt file is easier to write than to obtain — but they may not be the
   *only* input a parser was ever tested against.

### Required with it

- **Record provenance.** Every real-input fixture directory carries a `PROVENANCE.md` naming
  the tool, its version, the exact command, and the date. A fixture whose origin is unknown
  is a hand-written fixture with extra steps.
- **State what the real input caught.** If it caught nothing, say so — that is a real result
  and worth knowing.
- **Never contact anything live to generate it.** Mock credentials, `--dry-run`, published
  release artifacts. The Terraform fixture was generated with `access_key = "mock"` and was
  never applied.
