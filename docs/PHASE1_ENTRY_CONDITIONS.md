# Phase 1 entry conditions — verified before any scanner logic was written

Four items were left open at the end of Phase 0. Each was verified from a primary source or
a real run before Phase 1 began. One of them overturned a documented assumption and changed
the Phase 1 architecture.

**Date: 2026-07-22.** Versions are the ones actually executed on this machine.

---

## EC1 — Read arXiv 2601.14163 in full ✅

*An Empirical Study on Remote Code Execution in Machine Learning Model Hosting Ecosystems*
— Siddiq, Romel, Sekerak, Casey, Santos. Submitted 20 Jan 2026. Identity confirmed against
the arXiv abstract page (title, five authors, date); full text read from
`https://arxiv.org/html/2601.14163v1`.

### What TrustLens takes from it

**Entry-point criteria, adopted directly.** A repository requires custom code execution if
it is tagged `custom_code`, **or** contains `tokenizer.py`, `__init__.py` or `hubconf.py`,
**or** contains a Python file whose name begins with `modeling_`, `tokenization_` or
`configuration_`. Grounded in the PyTorch Hub and `transformers` documentation.

**Reachability is entry-point-rooted, and most repository code is not reachable.** Their
call-graph analysis reduced 128,487 Python files to 67,009 execution-relevant ones — a
little over half. A scanner that flags every construct in every file over-reports by
roughly a factor of two.

**Divergence from their method, deliberately.** They *discard* code outside the reachable
set. TrustLens will not: it records reachability as a **property of a finding**, not as a
filter, because a filter's exclusions become invisible in the output. A construct in
unreachable code is weaker evidence, not absent evidence, and the Phase 0 schema already
has the fields to say so.

**Bandit's raw output is mostly noise, and this changes how we wire it.** On Hugging Face,
CWE-703 accounts for 80.52% of findings, driven by `B101` (assert used) at 78.16% of all
issues. Running Bandit with its default test set would make four fifths of TrustLens's
output `assert` statements. **Phase 1 selects an explicit Bandit test subset rather than
running everything.** Real signal in their data: `B615` (unsafe Hugging Face download) is
the top medium-severity finding at 4.00%.

**Semgrep's profile is materially better than Bandit's** — CWE-502 (unsafe deserialization)
at 65.45% and CWE-95 (eval injection) at 19.48% on Hugging Face. The paper states Semgrep
"reveals a strong concentration of security-critical issues" where Bandit "primarily
surfaced low-severity coding smells". Their top Semgrep rules are registry rules
(`numpy in pytorch`, `pickles in pytorch`, `eval detected`) which TrustLens cannot ship —
see the Semgrep Rules License hazard in `GROUNDING.md`.

**YARA generic rule sets are not adopted.** 82.54% of their Hugging Face YARA matches are a
single `JT 3D Visualization format` signature, with the remainder dominated by VM-detection
rules. The paper's own reading: these "primarily indicate the presence of specific binary
artifacts or environment checks rather than confirmed malicious behavior."

**Their framing of their own results matches ours.** Construct validity: because Python's
dynamic features resist static resolution, they "conservatively interpret our results as
lower-bound estimates of execution-relevant security exposure." Note also that their use of
CodeQL was permissible *because they are academic researchers* — the exact carve-out that
`GROUNDING.md` records as unavailable to TrustLens.

**Bandit precision** is cited as 90.79%, from Siddiq et al. 2022 — a cited prior measurement,
not something this paper measured.

---

## EC2 — Semgrep's actual `errors[]` on a malformed file ✅ **ASSUMPTION OVERTURNED**

Tested with **Semgrep 1.163.0** against a fixture set containing three files that Python
genuinely cannot parse and one that cannot be read.

Ground truth established independently with `ast.parse`:

| File | `ast.parse` |
|---|---|
| `broken_syntax.py` | `SyntaxError` |
| `legacy_py2.py` | `SyntaxError` |
| `bad_encoding.py` | `UnicodeDecodeError` |
| `good_but_bad.py` | parses |

What Semgrep reported:

```
errors:  []          <- zero, even with --strict
skipped: []
scanned: [bad_encoding.py, broken_syntax.py, good_but_bad.py, legacy_py2.py]
exit:    0
stderr:  "Parsed lines: ~100.0%"
```

**Semgrep listed all three unparseable files as `scanned`, reported no errors, and claimed
~100% of lines parsed.** `unreadable.py` was **absent from the JSON entirely** — neither
scanned nor skipped. The only trace of it was a human-readable stderr line, "Files without
read access: 1". `--strict` changed nothing.

### Consequences, binding on Phase 1

1. **`scope.analysed` and `scope.failed` must never be derived from Semgrep's JSON.**
   TrustLens establishes parseability itself, per file, before invoking any external tool.
2. **Semgrep's findings are usable as `FOUND` evidence. Semgrep's silence is not usable as
   `NOT_FOUND_WITHIN_ANALYSED_SCOPE`.**
3. Had the `PARTIAL` mapping been coded against the documented `errors[]` — as Phase 0's
   documentation-based reading suggested — TrustLens would have mapped "0 errors" to a clean
   scope and reported three unparseable files as successfully analysed. That is precisely
   the false-clean failure the entire evidence model exists to prevent, and no test of ours
   would have caught it, because the tool would have been reporting success.

---

## EC3 — Do gitleaks, syft and osv-scanner distinguish "nothing found" from "could not read"? ✅

Verified by real runs against malformed and unreadable fixtures. **Bandit was re-tested too,
since EC2 established that documentation is not reliable here.**

| Tool | Version | Distinguishes in machine-readable output? | Where failure actually surfaces |
|---|---|---|---|
| **Bandit** | 1.9.4 | **YES** | `errors[]` in JSON, per file, with a reason that distinguishes `"syntax error while parsing AST from file"` from `"Permission denied"` |
| **Semgrep** | 1.163.0 | **NO** | Human-readable stderr only; unparseable files reported as scanned |
| **gitleaks** | 8.30.1 | **NO** | JSON is a flat findings list with no scope or error fields at all; a `WRN skipping file: permission denied` line on stderr |
| **syft** | 1.49.0 | **NO** | No `errors` key in the schema; malformed `package-lock.json` and a malformed requirements line were silently dropped, exit 0, **stderr empty** |
| **osv-scanner** | 2.4.0 | **NO** | Extraction error on stderr only; `'error'` appears nowhere in the JSON |

Detail worth stating separately, because it is the most dangerous shape found:

**osv-scanner with `--offline` and no downloaded database returned `results: []` — identical
to a clean scan — with exit code 127.** The only evidence that nothing was actually checked
was the exit code and a stderr line, "no offline version of the OSV database is available".
Run online for comparison, the same fixture set produced exit 1 and 8 real vulnerabilities
across two packages, while the malformed `package-lock.json` failure remained stderr-only.
So two independent failure modes — *database never loaded* and *manifest could not be
parsed* — both present in JSON as an empty, healthy-looking result.

**gitleaks positive control.** Its initial zero findings could have meant "detects nothing".
A control with realistic fake credentials produced 2 findings (`github-pat`,
`slack-bot-token`), confirming the tool works and that the zero was a genuine negative. An
untested negative would have been a vacuous result.

### Consequence, binding on Phase 1

Every external tool invocation is wrapped in a result type that captures **exit code,
stdout, stderr, and the version actually executed** — and TrustLens determines file
readability and parseability itself rather than inferring either from any tool's output.
Only Bandit's `errors[]` maps directly onto `scope.failed`. For the other four, a clean
machine-readable result is treated as *evidence of nothing*, not evidence of absence, and
the tool's own scope report is not accepted as the scope.

---

## EC4 — RedisGraph status ✅ **EOL — `krane` rejected**

`RedisGraph/RedisGraph` README, fetched directly:

> ### RedisGraph is no longer maintained.

with a pointer to `https://redis.com/blog/redisgraph-eol/`. The GitHub API reports
`archived: false` and `pushed_at: 2025-07-21` — **which is exactly why the archived flag
alone was insufficient evidence**, and why Phase 0 recorded this as unverified rather than
guessing.

Licence is additionally RSALv2 / SSPLv1 / AGPLv3 — no permissive option.

**Decision: `krane` is rejected on two independent grounds** — it hard-depends on an
end-of-life graph database, and that dependency carries no permissive licence. Phase 2 will
build its Kubernetes RBAC graph rather than adopt krane's. This removes the only offline
RBAC-graph tool the survey found, which strengthens rather than weakens gap 4.3 in
`GROUNDING.md`.

---

## Reproducing these checks

```bash
python3 -m pytest tests/entry_conditions -v
```

The probe rebuilds the fixture set, runs each tool, and asserts the behaviours recorded
above. It is a **characterisation test**: if a future tool version starts reporting parse
failures properly, the probe fails and the corresponding mapping in
`trustlens/scanner/external.py` should be revisited. A failure here is good news that
requires work, not a regression.
