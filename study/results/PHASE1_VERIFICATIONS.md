# Phase 1 verifications (before analysis)

Three manual verifications requested after the raw results, plus a pre-registration scoring
note. No divergence-catalogue analysis yet.

## V1 — HuggingFaceFW/fineweb (0 FOUND): CORRECT NEGATIVE

`lighteval_tasks.py` (272 lines) was **actually analysed** — `scope.analysed = [README.md,
lighteval_tasks.py]`, `scope.failed = []`, `vacuous = false` — so the 0 FOUND is not vacuous.

Reading the file: it imports only `re`, `typing`, and `lighteval.*`; its body is a list of
`LightevalTaskConfig(...)` metadata declarations plus pure prompt-formatting functions
(`commonsense_qa_prompt`, `hellaswag_prompt`, …) that build prompt strings from dataset fields
with f-strings and `re`. There is **no** `eval`/`exec`/`subprocess`/`os.system`/`open`-write/
network/`pickle`/deserialization/`importlib` construct. It is **not** a `datasets` loader
script (fineweb is parquet; this file is a *lighteval* eval-task helper, imported by a
different framework), so `execution.loader_script` correctly did not fire.

**Verdict: correct negative.** TrustLens looked at a code-bearing repo and correctly reported
no execution capability because there is none. This is discrimination, not a miss — the
strongest single row in favour of the tool.

## V2 — k9cli BOM: a GENUINE TrustLens DEFECT (the study's most prominent finding)

TrustLens PARTIALed on 30 of k9cli's `.py` files with
`SyntaxError: invalid non-printable character U+FEFF`. Verified this is a real defect, not an
inherent un-parseability:

- **The files carry a UTF-8 BOM.** `audio/extractor.py`, `__init__.py`, `main.py`,
  `pipeline.py`, `tests/test_config.py`, `training/train_wav2vec2.py`, … all begin with bytes
  `ef bb bf` (U+FEFF).
- **Bandit parsed the exact same files successfully.** Bandit reported **0 parse errors** on
  the whole repo and returned findings on `audio/extractor.py` (2), `training/train_wav2vec2.py`
  (2), `tests/test_config.py` (12), etc. — **every one a BOM file that TrustLens listed in
  `scope.failed`.** Same file, same input: bandit read it, TrustLens did not.

**Root cause.** The scanner reads Python with `path.read_text(encoding="utf-8")` at ~5 sites
(`pysource.py:119`, `loader_scripts.py:93`, `template_injection.py:440`,
`declared_surface.py:286/360`) and passes the string to `ast.parse`. `encoding="utf-8"` leaves
a leading BOM as a U+FEFF character, which `ast.parse` rejects. Bandit avoids this with
BOM-aware reading.

**Fixable: yes.** Change `encoding="utf-8"` → `encoding="utf-8-sig"` at those read sites
(`utf-8-sig` strips a leading BOM, no-op if absent). Small and localized.

**POST-STUDY ACTION — NOT APPLIED.** Fixing the tool mid-study would invalidate the
pre-registered run. Recorded here as a finding and a post-study action to be done after the
write-up ships.

**Honest framing.** The scanner **failed closed** — PARTIAL, never a false-clean — so the
honesty guarantee held. But the underlying robustness gap is real, was invisible to every
prior test (all fixtures were written BOM-free and parseable), and was found only on real-world
input. That is exactly what this study existed to surface.

## V3 — k9cli coverage: effectively UNANALYSED, not a success

Of 33 capabilities, **only 3 were assessable** (not PARTIAL):

| Capability | Status | Source |
|---|---|---|
| execution.loader_script | FOUND | loader-scripts **repo-shape** check (filenames/structure — parse-independent) |
| execution.build_hook | NOT_FOUND | loader-scripts repo-shape check |
| execution.dynamic_import | NOT_FOUND | loader-scripts repo-shape check |

The other **30 capabilities are PARTIAL** (BOM). The single FOUND came from the
**parse-independent** repo-shape check ("9 repository-shape indicators matched:
custom-code-entry-point"), not from analysing code.

**Therefore k9cli must NOT be counted among repos where a declared-vs-reachable gap was
established by analysis.** Its 1 FOUND is a structural detection out of only 3 assessable
capabilities, with 30 unassessed. An effectively-unanalysed repo is not a discrimination
result and will be reported as such — the gap "detection" there rests on structure alone.

## Pre-registration scoring note — PARTIAL prediction MISSED

Predicted (§2): **2–4 of 8** repos PARTIAL on ≥1 file (flagged high uncertainty). **Actual: 1
of 8** (k9cli only). This is a **miss** — below the predicted range. Recorded explicitly here
so the successful predictions do not carry the report on their own. The single PARTIAL was
severe (30/33) rather than the broad-but-shallow distribution the prediction imagined; real
Python in the top-downloaded loader repos parsed cleanly more often than predicted, with one
repo failing hard on a single systematic cause (BOM).
