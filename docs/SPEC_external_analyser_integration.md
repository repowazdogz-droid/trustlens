# Mini-spec: integrating an external analyser (Bandit first)

**Status: DRAFT — UNREVIEWED. No code exists against this spec, and none may be written
until it has been reviewed.** Written 2026-07-22 as the design precondition recorded in
`trustlens/scanner/CLAIMS.md`.

## Why this needs a spec rather than a wiring commit

TrustLens's scanner currently **spawns no processes at all**, and that is not an incidental
property — it is enforced by `tests/scanner/test_inertness.py`, which replaces
`subprocess.run`, `os.system` and `socket.socket` with objects that raise and then scans a
hostile repository. The test passes because the scanner genuinely never calls them.

Integrating Bandit means the scanner spawns a process for the first time. Done carelessly,
the harness would be relaxed to accommodate it, and the guarantee would silently become
"the scanner spawns some processes, and we no longer check which". That is a worse outcome
than not integrating Bandit at all, because it converts a proven property into an assumed
one.

## What Bandit buys, so the trade is explicit

- `B614` (`torch.load` without the pickle guard) and `B615` (unpinned Hugging Face
  download) — already implemented in TrustLens, so this is corroboration rather than new
  coverage.
- A large, maintained rule set for general Python security smells that TrustLens does not
  and should not duplicate.
- **Verified failure reporting.** Bandit is the only one of the five surveyed tools whose
  `errors[]` distinguishes `"syntax error while parsing AST from file"` from
  `"Permission denied"` (`docs/PHASE1_ENTRY_CONDITIONS.md`). It is the only external tool
  eligible for a `FOUND`/`NOT_FOUND_WITHIN_ANALYSED_SCOPE` claim.
- Its raw output is ~78% `B101` (assert) noise on real corpora (arXiv 2601.14163), so an
  explicit test subset is mandatory, not optional.

## Required design, all five parts

### 1. Allowlisted binary, resolved not inherited

The analyser is invoked by absolute path, resolved once at startup from an explicit
allowlist. `PATH` is not consulted at call time. An unresolvable or unexpected binary is a
recorded failure, never a silent skip and never a fallback to "assume nothing to report".

### 2. Version recorded from the tool, not assumed

The executed version is captured by running the analyser's own version command and stored
in `tool.external_tools[]` with `version_source: "reported_by_tool"`. A version that cannot
be established is recorded as `unknown` — the schema already permits that and it is more
honest than a guess. A finding sourced from an external tool without a recorded version is
invalid.

### 3. Exit code and stderr are evidence

Both are captured and retained. Bandit's `errors[]` is trustworthy, but the exit code still
carries information the JSON does not (`0` clean, `1` issues, `2` scan error, `3` no
supported files, `4` usage). **Exit code 3 — "no supported files" — must map to a vacuous
scope, not to a clean result.** That is the single most likely place to reintroduce a
false-clean.

### 4. The harness distinguishes the approved analyser from anything else

This is the part that gates everything. `test_inertness.py` must be extended so that the
replacement `subprocess.run` does not simply raise, but:

- **allows** an invocation whose argv[0] is the resolved, allowlisted analyser path, and
  records it;
- **raises** on any other invocation, exactly as today;
- asserts afterwards that the recorded invocations are a subset of the allowlist, and that
  every one carries a recorded version.

The existing guarantee must survive verbatim for every non-analyser call. If extending the
harness turns out to require weakening any current assertion, that is a signal to stop and
not integrate.

### 5. Scope remains TrustLens's own

Per `docs/PHASE1_ENTRY_CONDITIONS.md`, TrustLens establishes parseability itself. Bandit's
`errors[]` may be **merged into** `scope.failed`, but Bandit's view of what it analysed must
never become `scope.analysed`. TrustLens decides scope; the analyser contributes findings
and failures within it.

## Acceptance criteria

Before any code is written against this spec, a reviewer should agree that:

1. The harness extension in §4 is written and passing **before** the invocation code exists,
   and it fails if the invocation code spawns anything unexpected.
2. A planted-case control demonstrates exit code 3 producing a vacuous scope rather than a
   clean result.
3. A control demonstrates that a finding sourced from Bandit without a recorded version is
   rejected.
4. The selected test subset is enumerated explicitly in code, with a stated reason per test
   id, and a test asserts the subset is non-empty and contains no `B101`.
5. Disagreement between Bandit and TrustLens's own rules on the same construct is recorded
   as a contradiction, not resolved by preferring either source.

## Open questions for the reviewer

- Should Bandit be a hard dependency, or optional with its absence recorded as `UNSUPPORTED`
  for the capabilities it would have covered? The latter preserves the clean-clone property
  that Phase 0 deliberately established, at the cost of variable coverage between runs.
- Is corroboration from a second tool worth a contradiction record when the two disagree, or
  does that add noise without adding information? The evidence model supports it; whether it
  helps a reader is not established.
- Does spawning any process at all belong in the scanner, or should external analysis be a
  separate command that produces its own record, the way acquisition is separate? That would
  preserve the scanner's no-subprocess property entirely and is the more conservative option.

**Until this document is reviewed, Bandit remains deferred and no integration code exists.**
