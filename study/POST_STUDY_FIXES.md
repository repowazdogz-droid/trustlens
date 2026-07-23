# Post-study fixes — the two defects the first external evaluation found

> **Addendum — 2026-07-23.** Both defects the study found are now fixed, as additive commits
> after the study (the study record stands unchanged at `19d5c5a`):
> - **Fix 1** (`re.compile` false positive) and **Fix 2** (UTF-8 BOM) — commit `696ce00`.
> - Corpus re-scan and matcher-audit record — commit `91d0434`.
>
> Re-scanning the study's own 8 repos with the fixed scanner: **github-code 3 → 2** FOUND
> (the false `execution.dynamic_eval` removed); **k9cli 1 FOUND / 30 PARTIAL → 5 FOUND / 0
> PARTIAL** (BOM resolved, repo now analysed). The other six repos are identical.
>
> **The five newly-parseable k9cli findings are unadjudicated relative to the study's scope.**
> The published study adjudicated the run at `19d5c5a`, where those capabilities were PARTIAL;
> this addendum claims only that the repo now parses, not that each new FOUND is a true
> positive. `WRITEUP.md`'s original findings and numbers are unchanged — this is an addendum,
> not a correction of the record.


This document records the fixes made **after** the first external study and their effect on the
study corpus. **It does not replace or edit the study.** The study
(`study/PRE_REGISTRATION.md`, `study/WRITEUP.md`, `study/results/`) stands unchanged at commit
`19d5c5a` as the record of what TrustLens did at that commit. This is a separate, later record.

Both defects were pre-committed as post-study actions and were **not** fixed during the study,
because fixing mid-run would have invalidated the pre-registered evaluation.

## Fix 1 — `re.compile` false positive (soundness)

**Defect** (study D1): the `exec-eval-builtin` rule targeted the bare name `compile`, and the
call matcher exposed the last segment of a qualified call, so `re.compile(r'\s+')` matched the
builtin `compile` and was reported `execution.dynamic_eval` = FOUND. Broader than the one study
instance: `df.eval` (pandas), `model.compile` (Keras), and the chained `get_model().eval()`
(PyTorch) all false-matched the same way — all common ML idioms.

**Fix.** `call_names()` now returns the *exact* names of a call only (raw + alias-resolved); the
bare last segment is returned separately by a new `call_suffix()`. A `Rule.match_suffix` flag
(default `True`) controls whether a bare target also matches a call's last segment.
`exec-eval-builtin` sets it `False`, so its builtin targets match an **unqualified** call only.

**Verified both directions** (`tests/scanner/test_exec_eval_builtin_fp.py`): `re.compile`,
`df.eval`, `model.compile`, and chained `.eval()` now return NOT_FOUND; unqualified `eval()`,
`exec()`, `compile()` and the explicit `builtins.eval` still return FOUND. A fix that silenced
the false positive by matching nothing would fail the second half.

## Fix 2 — UTF-8 BOM parse failure (robustness)

**Defect** (study V2): the scanner read source with `encoding="utf-8"`, which leaves a leading
BOM as a `U+FEFF` character that `ast.parse` rejects. `k9cli/video-vec2wav2-tokenizer` shipped
BOM-prefixed files, so 30 of 33 capabilities came back PARTIAL — effectively unanalysed. The
scanner *failed closed* (PARTIAL, never false-clean), so its honesty guarantee held; the
robustness gap was the defect.

**Fix.** `encoding="utf-8-sig"` at all 8 scanner read sites. `utf-8-sig` strips a leading BOM
and is a no-op otherwise, and it **still raises `UnicodeDecodeError` on genuinely invalid
bytes** — so the failing-closed guarantee is preserved.

**Verified** (`tests/scanner/test_bom_decoding.py`, with a real `ef bb bf` fixture): the BOM file
now parses; a byte-identical non-BOM twin is unchanged; and a genuinely unparseable input (bad
syntax, invalid bytes) *still* fails closed to a `scope.failed` / PARTIAL.

## Matcher audit (requested: does any other rule share the defect?)

The defect was the bare-last-segment match. Every call rule with a bare (no-dot) target was
audited; findings, grounded by running each shape through the scanner:

| Rule | Bare target(s) | Verdict |
|---|---|---|
| **exec-eval-builtin** | eval, exec, compile | **Same defect — FIXED** (re.compile/df.eval/model.compile are common, unrelated, benign) |
| dynamic-import | `__import__` | Same *pattern*, negligible risk — `x.__import__()` is almost always a real import; no benign FP demonstrated. **Recorded for follow-up, not fixed** (fixing it removes no real coverage; left for a deliberate decision) |
| open-for-write | open | **Not a defect** — the suffix matches (`gzip.open(f,'wb')`) are *real* writes, and the write-mode predicate skips non-writes (`conn.open()`, `db.open('readonly')` → nothing) |
| keras-safe-mode-false | load_model | **Not a defect** — fires only with `safe_mode=False`, a Keras-specific argument; `custom.load_model()` → nothing |
| socket-listen; path-write; filesystem-delete; archive-extraction; setuptools-build-hook | bind, listen; write_text, write_bytes; unlink; extract, extractall; setup | **Intentional, documented over-reporters** (CLAIMS.md) — deliberately match any object's method; kept |
| remote-artifact-fetch; cloud-sdk-credential-discovery; k8s-api-client; torch-safe-globals-widening | hf_hub_download, snapshot_download; DefaultAzureCredential; load_incluster_config; add_safe_globals | Specific function names, low collision — kept |

**Conclusion: one rule had the same defect and is fixed; one (`dynamic-import`) shares the
pattern at negligible risk and is recorded for a follow-up decision; the rest are either
predicate-narrowed, specific-named, or deliberate over-reporters.** The defect was found on one
repo by accident, not by design — this audit is the by-design pass.

## Effect on the study corpus (re-scan with the fixed scanner)

The 8 study repositories re-scanned with the fixed scanner, diffed against the published records
(`study/results/*/trustlens_record.json`). Only the two repos with the triggering conditions
changed; the other six are identical.

| Repo | Published | Fixed | Change |
|---|---|---|---|
| codeparrot/github-code | F=3 P=0 NF=30 | F=2 P=0 NF=31 | **`execution.dynamic_eval` FOUND → NOT_FOUND** (Fix 1) |
| k9cli/video-vec2wav2-tokenizer | F=1 **P=30** NF=2 | F=5 **P=0** NF=28 | **BOM PARTIALs resolved** (Fix 2); 4 capabilities now assessable and FOUND: `process.subprocess`, `filesystem.write`, `filesystem.archive_extraction`, `package.install_at_runtime` |
| the other 6 (incl. both controls) | — | — | identical |

**Honest scope of this delta.** Fix 1's effect is fully adjudicated: `re.compile` is not a
dynamic eval, so removing that FOUND is a correct change, and github-code's remaining two
findings (loader_script, filesystem.write) are unaffected. Fix 2's effect is that k9cli is **no
longer unanalysed** — 30 capabilities moved from PARTIAL (unknown) to assessed. The 5 resulting
FOUND capabilities have **not** been individually re-adjudicated here (the study's per-finding
adjudication was of the published run); the claim is only that the repo now parses and is
analysed, which the study said it was not. Whether each of those 5 is a true positive is the
subject a future run would examine, not a claim made here.

## What did NOT change

- The published study and its write-up are untouched at `19d5c5a`.
- No finding was dropped on any example fixture (unsafe-repo FOUND counts unchanged at 9 and 8);
  `examples/control_runs/` were regenerated for the one changed rule-metadata field
  (`blind_spot` text), and `examples/records/` are unchanged.
- The failing-closed guarantee is intact (Fix 2 verification (c)).
