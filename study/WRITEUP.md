# TrustLens — first external evaluation

A pre-registered study of TrustLens against 8 Hugging Face repositories not authored by the
project, with picklescan, Bandit, and modelscan (ProtectAI's open-source scanner) as
comparators. Pre-registration and raw evidence: `study/PRE_REGISTRATION.md`,
`study/results/`. Committed before any repository was fetched; published regardless of
outcome, as pre-committed.

---

## Headline: two defects, and a scope finding — all from leaving the fixtures behind

Three findings lead this study: two defects surfaced by real input, and a scope result that
bounds what the tool can do on a public artifact at all. The first two are about correctness;
the third is about applicability, and it is the most consequential for anyone deciding to use
the tool.

### Defect 1 — false positive on a `FOUND`: `re.compile` flagged as dynamic code evaluation

In `codeparrot/github-code`, the line `PATTERN = re.compile(r'\s+')` — compiling a regular
expression — was reported as `execution.dynamic_eval` = **FOUND**. TrustLens's contract is that
a `FOUND` is a *true* violation; this is a false one. The `exec-eval-builtin` rule targets the
bare name `compile` (`{eval, exec, compile, builtins.*}`) and the matcher fires on the final
attribute of `re.compile`. It is **systematic and deterministic**: across the five cleanly
parsed repos, the *only* one using `re.compile` (github-code, one occurrence) is the *only* one
that reported `dynamic_eval` FOUND; the other four use `re.compile` zero times and all correctly
report NOT_FOUND. Any repository using `re.compile` — one of the most common calls in Python —
would trip this. **This is a soundness defect.**

### Defect 2 — parse failure on a UTF-8 BOM: 30 of 33 capabilities unassessable

In `k9cli/video-vec2wav2-tokenizer`, every Python file begins with a UTF-8 byte-order mark
(`ef bb bf`). TrustLens reads source with `read_text(encoding="utf-8")`, which leaves the BOM as
a `U+FEFF` character, and `ast.parse` rejects it — so 30 of 33 capabilities came back `PARTIAL`.
**Bandit parsed the identical files with zero errors** and returned findings on them, proving
this is TrustLens's defect, not inherent un-parseability. **This is a robustness defect** — and
notably, TrustLens *failed closed* (PARTIAL, never a false-clean), so its central honesty
guarantee held even as the robustness gap bit.

### Finding 3 — scope: three of four components had no input; TrustLens reduced to its scanner

**Zero of the 8 repositories shipped mapper-ingestible environment configuration** — no
Terraform plan, no Kubernetes RBAC, no credential/environment description — and not a single
credential, cloud, or environment capability was FOUND anywhere in the corpus. TrustLens is four
components (scanner, credential mapper, sandbox, blast-radius) over one evidence model, but
**three of the four had nothing to operate on.** The credential mapper builds edges only from a
deployment environment description; the sandbox was off by construction and, in any case, is not
signed off for arbitrary untrusted public artifacts; and the blast-radius simulator composes the
other three, so with no credential edges it had nothing to compose.

Stated plainly: **for public-artifact analysis without a deployment environment, TrustLens
reduces to its static scanner.** The mapper, sandbox, and blast-radius layers require an analyst
working on *their own infrastructure* — with access to both the artifact **and** the credential
topology it would run against, which lives in the deploying organisation, not in the artifact.
This is not a defect; it is the operating envelope of the tool, made concrete by real data, and
it is the single most important thing for a prospective user to know before running the full
pipeline and finding three components idle.

**Why these three lead.** Neither defect could appear on the project's own fixtures — they were
written parseable, BOM-free, and without an `re.compile` standing in for an eval — so both were
invisible until the tool met code it did not author. And the scope result could not appear in
any test at all, because every prior test supplied a fabricated environment; only real public
artifacts, which carry no deployment environment, could reveal that three of four components sit
idle without one. All three are products of leaving the fixtures behind.

**Neither defect has been fixed.** Fixing mid-study would invalidate the pre-registered run.
Both are recorded as post-study actions in the last section.

---

## What the study was, and the comparison it refused

TrustLens answers: *does an artifact's declared surface match its reachable surface?*
picklescan and modelscan answer: *does a pickle/model file match a known-malicious pattern?*
Bandit answers: *does the Python match a known-insecure pattern?* These are different
claim-kinds. **No aggregate score was computed** — a "TrustLens caught N, picklescan caught M"
comparison between tools answering different questions is a category error, and refusing it is a
design commitment of this study. The comparison is a per-repo divergence catalogue
(`study/results/DIVERGENCE_CATALOGUE.md`), and divergences where a comparator is right and
TrustLens is noisy are weighted equally with the reverse.

## The corpus (n = 8)

Selected by download rank from the HF Hub, pre-registered, pinned by commit SHA. Six
code-bearing datasets (repo-root Python execution surface) + two passive-data negative controls.
Full identities, download counts, SHAs, and the 51-repo consideration log:
`study/results/selection_log.md`.

## Predictions vs outcomes — misses reported as prominently as hits

The pre-registered predictions (§2) and what actually happened. **The author over-predicted how
much TrustLens would find: the two headline "how much did it flag" predictions both missed low.**

| Prediction | Predicted | Actual | Verdict |
|---|---|---|---|
| Declared-vs-reachable gaps (formal DVR contradictions) | **4–6 / 8** | **2 / 8** (mmlu, yodas) | **MISS — low.** And one of the two (mmlu) rests on the scanner *inferring* "loader not required" from metadata structure, not an explicit card claim; only yodas ("card says raw data, loader executes") is an unambiguous gap |
| Clean (no findings) | 2–3 / 8 | 3 / 8 (2 controls + fineweb) | HIT |
| PARTIAL on ≥1 file | **2–4 / 8** | **1 / 8** (k9cli) | **MISS — low.** One repo failed hard (30/33) on a single systematic cause (BOM) rather than the broad-but-shallow spread predicted |
| False positives | 1–3 | 1 clear (`re.compile`) + 1 borderline (`.extract`) | HIT |
| TrustLens-only divergence (surfaces what picklescan/modelscan can't) | most Stratum A | 4 repos (loader surface) | HIT |
| Comparator-only divergence (bandit right where TL silent) | ≥ 1 | ≥ 1 (weak MD5, unpinned download, XML) | HIT |
| End-to-end case exists | 40–70% | **NONE** | **MISS — reported as a finding per A1, below** |

**The prediction bias is itself a finding: three of seven predictions missed, and all three
missed in the same direction — the author over-predicted the tool's yield** (declared-vs-reachable
gaps predicted 4–6, got 2; PARTIAL predicted 2–4, got 1; end-to-end predicted 40–70%, got none).
A directionally consistent miss is more informative than any single one: it says the person who
built and pre-registered the study systematically expected TrustLens to find more than it did.
That is the pre-registration working exactly as intended — it recorded an honest prior *before*
the data, so the data could contradict it, and it did. Had these predictions been written after
seeing the results, the write-up would report a tool that performs as expected; because they were
written before, it reports a tool that flags less than its own author believed it would, and that
is the more trustworthy result.

## The divergence catalogue, in brief

Full version: `study/results/DIVERGENCE_CATALOGUE.md`.

- **TrustLens uniquely surfaces loader execution surface** on the 4 real loader repos. picklescan
  and modelscan scanned **0 relevant files on all 8** — a loader-script data repo contains no
  pickle or model files, so those tools are structurally blind to its risk, which lives in
  Python. This is the clearest *complementarity* result: the tools cover disjoint surfaces, and a
  maintainer running only picklescan/modelscan sees "clean" on a repo whose loader runs code.
- **Bandit is genuinely useful where TrustLens is silent**: weak MD5 (HIGH), `load_dataset()`
  without revision pinning, `xml.etree` parsing — real findings TrustLens does not model.
- **TrustLens is noisier than its contract claims**: the `re.compile` false positive (defect 1),
  plus over-broad matchers — `os.mkdir` → `filesystem.write` (correct-but-broad) and
  `dl_manager.extract` → `archive_extraction` (real capability, framework-managed, low signal).

## Phase 2 — the end-to-end path: no qualifying case (finding, per A1)

**The corpus contained no case where the full evidence chain (static finding → credential
reachability → blast radius) changed what a reasonable engineer would conclude relative to the
card plus a clean scanner.** This is reported as a finding, not softened, and no marginal case
was constructed. Detail: `study/results/PHASE2_END_TO_END.md`.

The reason is structural and was verified, not assumed: the credential-reachability layer builds
edges only from an operator-supplied environment description (Terraform/K8s/credential config),
and **no public dataset repo ships one** — zero across all 8. Not a single credential/cloud/env
capability was even FOUND anywhere (k9cli's are all PARTIAL). So the mapper and blast-radius
layers had no input, and **for pure artifact analysis with no operator environment, TrustLens
reduces to its static scanner.** This maps a real boundary: the end-to-end proposition needs
credential topology that lives in the deploying organisation's infrastructure, not in the
artifact.

**Structural ceiling (stated here, where the case would be, not only in limitations):** the
sandbox is off by construction, so even had a case existed, no blast-radius path could reach the
`OBSERVED` tier — every edge would be `configured` or `inferred`. Any end-to-end claim in this
study would be a composed inference about reachability, never a demonstration of it.

## What this study does NOT establish

- **No base rates.** n = 8 supports no claim about how common declared-vs-reachable gaps,
  parse failures, or false positives are in the wild. Every count here is "in this corpus of 8."
- **The FOUND rate is not a population estimate.** The corpus was *selected on having execution
  surface* (Stratum A) — finding execution surface in repos chosen for having it establishes
  nothing about repos in general. The two controls are the only unconditioned sample, and both
  came out clean.
- **One repo was effectively unanalysed.** k9cli returned 30 of 33 capabilities `PARTIAL` (the
  BOM defect); its single FOUND is the parse-independent repo-shape check. It contributes almost
  no analytic signal and is not counted as a declared-vs-reachable success.
- **The comparison is qualitative by design** and yields no measure of relative accuracy —
  refusing that measure is the point.
- **No dynamic observation** (sandbox off), so no reachability was demonstrated, only inferred.
- **Single unblinded analyst** adjudicated false-positive / structural / correct verdicts; the
  classification rules were pre-fixed to limit latitude, and every divergence shows the code so a
  reader can re-adjudicate.

## Protocol deviations

All logged in `study/PRE_REGISTRATION.md` §9: the control re-verification (A4 — both controls are
genuine passive-data datasets; my in-flight "empty" claim was a non-recursive-listing artifact
and was wrong), the enumeration-fidelity and ranking-drift note (A5), and the modelscan flag fix
(A6). The end-to-end-absence-is-a-finding rule (A1) and the structural ceiling (A2) were fixed
before scanning.

## Post-study actions (NOT done — recorded for after publication)

Neither defect was fixed during the study; fixing mid-run invalidates the pre-registered
evaluation. After this write-up ships:

1. **Defect 1 (`re.compile` false positive):** qualify the `exec-eval-builtin` rule's `compile`
   target to the builtin only (require an unqualified `compile` or `builtins.compile`, not a
   module attribute like `re.compile`). Add `re.compile` as a false-positive regression control.
2. **Defect 2 (UTF-8 BOM):** decode Python source with `encoding="utf-8-sig"` at the ~5 read
   sites (`pysource.py:119`, `loader_scripts.py:93`, `template_injection.py:440`,
   `declared_surface.py:286/360`). Add a BOM-carrying fixture to the parser tests.

## One-line verdict

TrustLens sees an execution surface that pickle/model scanners are structurally blind to, and
its fail-closed honesty held throughout — but this first contact with code it did not author
surfaced one soundness false positive and one robustness parse failure, its author over-predicted
how much it would flag, and its distinctive end-to-end layer had no input to work on in a corpus
of artifacts analysed without an operator environment.
