# Divergence catalogue (Phase 1 analysis)

Per-repo, qualitative, no aggregate score (§4 of the pre-registration — a score between tools
that answer different questions is the category error this study refuses). Each divergence is
adjudicated against the code, and divergences where **TrustLens is noisy and a comparator is
right** are weighted equally with the reverse.

## What each tool was answering

| Tool | Question | Claim-kind |
|---|---|---|
| **TrustLens** | Does the artifact's *declared* surface match its *reachable* surface? | declared-vs-reachable capability inventory |
| **picklescan** | Does any pickle file contain a malicious opcode/global? | known-bad pattern in pickle files |
| **modelscan (ProtectAI OSS)** | Does any *model file* perform a suspicious action? | known-bad pattern in model files |
| **Bandit** | Does the Python contain a known-insecure pattern? | Python SAST rule-match |

## Per-repo results

| Repo | TrustLens (FOUND) | picklescan | modelscan | Bandit |
|---|---|---|---|---|
| codeparrot/github-code | loader_script✓, filesystem.write(os.mkdir), **dynamic_eval✗FP** | 0 files | 0 files | B324 MD5 **HIGH**, B615 unpinned-download MED, B101×4 |
| espnet/yodas | loader_script✓, archive_extraction(dl_manager.extract, broad) | 0 files | 0 files | 0 |
| cais/mmlu | loader_script✓ | 0 files | 0 files | 0 |
| KakologArchives | loader_script✓ | 0 files | 0 files | B314 xml.parse MED, B405 LOW |
| k9cli/video-vec2wav2-tokenizer | loader_script✓ (structural) — **30/33 PARTIAL (BOM)** | 0 infected /919k | 0 files | 69 (65×assert, B615 MED, …) |
| HuggingFaceFW/fineweb | **none (correct negative)** | 0 files | 0 files | 0 |
| anisoleai/fineweb-tokenized *(control)* | none | 0 files | 0 files | 0 |
| Benjy/typed_digital_signatures *(control)* | none | 0 files | 0 files | 0 |

✓ = adjudicated correct · ✗FP = adjudicated false positive · (broad) = real but over-broad matcher

## The load-bearing divergences, adjudicated

### D1 — TrustLens FALSE POSITIVE: `re.compile` flagged as `execution.dynamic_eval` (github-code)
`github_preprocessing.py:27` is `PATTERN = re.compile(r'\s+')` — compiling a **regular
expression**. TrustLens reported `execution.dynamic_eval` = **FOUND**. The `exec-eval-builtin`
rule targets the bare name `compile` (`targets={eval,exec,compile,builtins.*}`), and the
last-segment matcher fires on `re.compile`. **This is a false positive on a `FOUND`** — a
soundness issue, because TrustLens's stated contract is "FOUND = a true violation," and it is
**systematic** (any `re.compile`, one of the most common calls in Python). Neither bandit,
picklescan, nor modelscan made this error. **Comparator-correct / TrustLens-noisy — reported
with full prominence.** (Post-study fix: qualify the `compile` target to the builtin only.)

**Deterministic, confirmed across the corpus:** the single repo using `re.compile`
(github-code, 1 occurrence) is the *only* repo with `execution.dynamic_eval` = FOUND; the four
other cleanly-parsed repos use `re.compile` 0 times and all correctly report NOT_FOUND. The FP
is perfectly correlated with `re.compile` presence — a systematic rule bug, not an artifact of
one file.

### D2 — Bandit-correct, TrustLens-silent: real issues outside TrustLens's model (github-code, KakologArchives)
Bandit found, and TrustLens does not model:
- `github_preprocessing.py:31` **weak MD5 hash (B324, HIGH)** — a real, if low-stakes, crypto
  finding.
- `github_preprocessing.py:95` **`load_dataset()` without revision pinning (B615, MED)** — a
  supply-chain finding (unpinned remote fetch).
- `KakologArchives.py` **`xml.etree` parse (B314/B405)** — XML-parsing attack surface.

None are "declared-vs-reachable" questions, so TrustLens's silence is **correct for its
claim-kind** — but a maintainer running only TrustLens would miss all three. **This is the
symmetric result the pre-registration required: bandit is genuinely useful where TrustLens is
silent.**

### D3 — TrustLens-correct, comparators-silent: capability surface bandit/picklescan don't cover
- `espnet/yodas`: `dl_manager.extract(...)` — TrustLens flags `filesystem.archive_extraction`.
  Extraction genuinely occurs; bandit reported nothing. **However** this is TrustLens's
  bare-method-name matcher (`.extract`), which its own CLAIMS.md lists as an over-report — it
  is framework-managed extraction (lower security signal than an unfiltered `tarfile.extractall`).
  Verdict: **real capability, over-broad matcher, low security signal.** A weak TrustLens win.
- `loader_script` across github-code / mmlu / yodas / KakologArchives: correctly identifies HF
  dataset loaders (`GeneratorBasedBuilder` subclass / custom-code entry point). picklescan and
  modelscan are structurally blind to this — **there are no pickle or model files to scan** in
  a loader-script repo, so both scanned 0 files and returned 0. This is the core claim-kind
  divergence: TrustLens sees the *execution surface* of a code-bearing data repo; picklescan
  and modelscan see *nothing* because their target file classes are absent.

### D4 — `os.mkdir` as `filesystem.write` (github-code)
`os.mkdir(args.out_path + "/data")` → `filesystem.write` FOUND. Defensible (mkdir modifies the
consumer's filesystem) but the label "write" is broad for directory creation. **Correct-but-broad**,
not a false positive.

## False-positive tally (against the §2 prediction of 1–3)

| # | Finding | Verdict |
|---|---|---|
| 1 | github-code `execution.dynamic_eval` on `re.compile` | **clear false positive** (soundness) |
| 2 | yodas `filesystem.archive_extraction` on `dl_manager.extract` | over-broad matcher, real capability — borderline |
| 3 | github-code `filesystem.write` on `os.mkdir` | correct-but-broad — not a false positive |

**One clear FP, one borderline over-report** — within the predicted 1–3 range.

## The picklescan / modelscan structural result

On **all 8 repos**, picklescan and modelscan scanned **0 relevant files** (7/8 had no pickle
or model files at all; k9cli's 919k files were data, 0 pickles). This is not a failure of
those tools — it is the claim-kind boundary made concrete: **picklescan and modelscan target
malicious *pickle/model files*, and a loader-script dataset repo's risk lives in its *Python
code*, which those tools do not analyse.** A maintainer relying on picklescan/modelscan alone
would see "0 files scanned, clean" on a repo whose loader executes arbitrary code — which is
exactly the declared-vs-reachable gap TrustLens is built to surface. This is the study's
clearest *complementarity* result (not superiority): the tools do not compete; they cover
disjoint surfaces.

## Honest summary (no score)

- **TrustLens uniquely surfaces** the execution surface of code-bearing data repos (loader
  scripts) that picklescan/modelscan are structurally blind to.
- **TrustLens is noisier than its contract claims**: one clear false positive on a `FOUND`
  (`re.compile`), plus over-broad matchers (`os.mkdir`, `.extract`), and one repo (k9cli)
  effectively unanalysed due to the BOM defect.
- **Bandit is genuinely useful where TrustLens is silent** (weak crypto, unpinned downloads,
  XML surface) — different claim-kind, real findings.
- **picklescan / modelscan found nothing anywhere** — correct for their claim-kind, because
  their target file classes are absent from these repos.
