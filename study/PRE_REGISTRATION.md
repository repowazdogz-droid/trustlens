# TrustLens external evaluation — pre-registration

**Status: PRE-REGISTERED. Committed before any candidate repository was fetched, listed, or
scanned.** The git commit that introduces this file is the pre-registration seal: its
timestamp precedes every artifact in `study/results/`. Nothing in the corpus had been looked
at when this was written — not its contents, not its file list, not its card.

**Commitment, made now and binding regardless of outcome:** the write-up
(`study/WRITEUP.md`) will be published whatever the result. If TrustLens produces mostly
noise, finds nothing the comparison tools miss, or PARTIALs out on half the corpus, those are
the findings and they get published. A null or embarrassing result is a result.

**Amendments:** any change to this protocol after this commit is appended to §9 with its
date and reason, never edited in silently. A selection or prediction changed after seeing data
measures the change, not the tool.

---

## 0. What this study is, and the comparison it refuses

TrustLens answers one question: **does an artifact's *declared* surface match its *reachable*
surface?** — what a dataset/model card says the thing is, versus what static analysis,
configuration, and (where available) execution show it can do.

picklescan, ProtectAI's scanner (modelscan), and Bandit answer a **different kind of
question**: *does this artifact match a known-malicious or known-dangerous pattern?* — a
malicious pickle opcode, a suspicious import, a hardcoded-secret regex.

These are different claim-kinds. A head-to-head *score* between them — "TrustLens caught N,
picklescan caught M" — is a category error, and it is the exact false comparison this project
exists to refuse. A tool that answers "is this a known-bad pattern" is not worse or better
than one that answers "does the declaration match reachability"; they answer different
questions, and a repo can be clean under one and flagged under the other with both correct.

**So the comparison in this study is per-repo and qualitative** (§4), never a count. And a
divergence where a comparison tool is right and TrustLens is noisy is recorded with **equal
prominence** to the reverse. That symmetry is pre-committed.

---

## 1. Selection criteria — fixed now, before any repo is seen

### Population

Public Hugging Face **dataset or model repositories that ship custom Python execution
surface** — a repo-root loading script, or a config declaring remote code (`auto_map`,
custom `modeling_*.py`/`configuration_*.py` intended to run under `trust_remote_code=True`).
This is the population TrustLens's declared-vs-reachable claim is most about, and the one
where all three comparison tools have something to say (they scan ML artifacts / the Python
that loads them).

**Why not IaC/Terraform/K8s repos in this first study:** two reasons. (1) The named comparison
tools (picklescan, ProtectAI, Bandit) do not address infrastructure-as-code — the coherent
comparators there are checkov/tfsec, a different pairing, and mixing them would produce a
corpus where half the rows have no meaningful comparison. (2) A first external evaluation
should test **one claim cleanly**: mixing dataset repos with infrastructure configs makes an
ambiguous result unattributable — a mixed signal could not be traced to either the scanner or
the mapper. The credential-mapper evaluation against **checkov and tfsec** is therefore a
**separate planned study**, recorded here as deliberate future work, **not an omission**. This
scoping decision was made now, before any results.

### Sampling method (deterministic; not random, so stated exactly)

1. Enumerate via the Hugging Face Hub API, **sorted by downloads descending** — datasets:
   `https://huggingface.co/api/datasets?sort=downloads&direction=-1&limit=1000`; models:
   `https://huggingface.co/api/models?sort=downloads&direction=-1&limit=1000`.
2. Walk the ranked list. For each candidate, retrieve its **file list only** (the API
   `/tree/main` endpoint — filenames, not contents) to apply inclusion. Retrieving a filename
   list is not "seeing results"; the scan is never run during selection.
3. Apply inclusion/exclusion (below). Take repos in **download-rank order** — the first that
   qualify, no discretion — until each stratum is full.

Selection is therefore reproducible from the ranked list: anyone re-running the enumeration
gets the same set (modulo download-rank drift over time, which is recorded by pinning each
repo's commit SHA at fetch).

### Strata and target n (fixed now)

**n = 8 total.**

- **Stratum A — code-bearing (n = 6):** repos meeting the population definition (custom Python
  execution surface). The primary corpus.
- **Stratum B — negative controls (n = 2):** top-downloaded **dataset** repos shipping **no**
  `.py` and no remote-code config — pure data (parquet/CSV/JSON/images). Included so that
  "how many come out clean" is a real, testable prediction and so false positives on genuinely
  passive data are caught. Without these, selecting only code-bearing repos would trivially
  guarantee findings and the study could not measure discrimination.

### Inclusion (Stratum A)

- Public, ungated, retrievable without authentication.
- Contains at least one of: a repo-root `*.py` loading script; a `config.json`/`*.json`/YAML
  declaring `auto_map` or referencing custom `modeling_*.py`/`configuration_*.py`.
- The custom code is **Python** (the scanner's call rules are Python-only; a non-Python loader
  is out of the tool's stated scope and would be an unfair PARTIAL, not a finding).

### Exclusion (both strata)

- Gated, private, or auth-required repos.
- Repos whose total retrievable code+config exceeds what can be fetched without downloading
  large data blobs (data files are not fetched; if code/config cannot be isolated, exclude).
- Repos flagged by the Hub as NSFW/abuse, or whose content is plausibly harmful to retrieve.
- Forks or near-duplicates of an already-selected repo (first by rank wins).
- Repos authored by the study author or by Anthropic (none expected; stated for completeness).

### Fallback (fixed now, to prevent post-hoc substitution)

HF deprecated dataset loading scripts in `datasets` 4.0, so high-download *dataset* repos with
loaders may be sparse. If fewer than 6 Stratum-A repos are found within the **top 1000 by
downloads across datasets AND models combined**, the shortfall is filled from **model** repos
with `auto_map`/remote code, still in strict download-rank order. If still short of 6, n for
Stratum A drops to what qualifies and the reduced n is reported — the target is **not** met by
reaching further down the ranking than the top 1000 or by relaxing inclusion.

### Pinning

Each selected repo is fetched at its current `main` HEAD **commit SHA**, recorded as the
immutable reference. All scans and all comparison-tool runs use that same SHA.

---

## 2. Predictions — committed before scanning

Stated as falsifiable ranges. I do not know these answers; several I expect to be wrong,
which is the point. Corpus n = 8 (Stratum A = 6, Stratum B = 2).

| Prediction | Committed estimate | Basis / what would refute it |
|---|---|---|
| **Declared-vs-reachable gap** (card implies passive/no-code, scanner finds execution surface) | **4–6 of 8** — essentially most of Stratum A, ~0 of Stratum B | Refuted if most code-bearing repos' cards *do* clearly declare code execution, or if the scanner misses the execution surface |
| **Clean** (no capability findings) | **2–3 of 8** — the 2 controls, maybe 1 Stratum-A whose "loader" is inert | Refuted if a control shows execution findings (false positive) or if >3 come out clean |
| **PARTIAL on ≥1 file** (real-world parse failure) | **2–4 of 8** — HIGH uncertainty; this is the first real-world parse test, every prior input was written to parse | Refuted at either extreme: 0 (parser is more robust than feared) or ~all (parser is fragile on real code) |
| **False positives** (flagged construct confers no capability on any path a competent reviewer accepts) | **1–3 across the corpus** — from known over-reporting rules (bare method names, string-in-prose) | Refuted by 0 (cleaner than the known blind spots suggest) or by many (a systematic FP source) |
| **Comparison divergence, TrustLens-only** | most Stratum-A repos: TrustLens surfaces a declared-vs-reachable gap that picklescan/modelscan (no malicious pickle) report clean on | — |
| **Comparison divergence, comparison-tool-only** (the symmetric result) | **≥1** repo where Bandit or picklescan/modelscan flags something material that TrustLens does not model | If this is 0, I state it — but I *expect* ≥1 and will report it as prominently as the reverse |
| **Phase 2 end-to-end case exists** | **uncertain — 40–70%** that ≥1 qualifying case is present in n=8 | Requires a repo where the card underclaims, picklescan/modelscan are clean, AND execution reaches a credential/network sink. If absent, **its absence is itself a reported finding** (see below), not a manufactured case and not a study failure |

**Stated limitation baked into these predictions:** because Stratum A is *selected on having
code*, near-zero code-bearing repos will be "clean," so the clean-count is dominated by the
controls and this study **cannot** speak to how often passive-data repos are misclassified
beyond the 2 controls. That is a limitation, not a result.

---

## 3. Disclosure protocol — written before anything is found

Every finding is classified into exactly one of two classes, by the rules below (fixed now to
remove post-hoc latitude):

### STRUCTURAL — the artifact does what its design implies

The capability is the evident, documented purpose of the file. A repo-root `{name}.py` that
executes code **is** a loader; a model repo with `auto_map` **is** meant to run custom code
under `trust_remote_code=True`. This is **not a vulnerability**, it is the mechanism working
as designed. **Publishable immediately, named, no notification.** The finding of interest here
is the *gap* between this structural reality and what the card declares — which is a statement
about documentation, not a security defect in the artifact.

### POTENTIALLY EXPLOITABLE — something the maintainer would likely not expect and want to fix

Examples: a template-injection surface reaching an evaluating/rendering sink; a credential
path or secret read reachable from data an untrusted caller controls; an archive extraction
without a filter that a maintainer plausibly believes is safe. The test is: *would a competent
maintainer be surprised, and want to change it?*

For this class:
- **Do not publish the specifics.** Not the repo name, not the file, not the payload, in the
  public write-up, until the window below has elapsed or the maintainer agrees.
- **Notify the maintainer.** Contact route, in order of preference: (1) a `SECURITY.md` /
  security contact in the repo; (2) the Hugging Face repo **Community/Discussions** tab
  opened as a private/security report where supported; (3) the maintainer's listed
  email/handle on their HF profile or linked homepage. If none exists, the finding is held and
  reported only in **fully anonymised aggregate** (class and mechanism, no identifying detail).
- **Window: 45 days** from notification before any non-anonymised publication, extendable at
  the maintainer's request. 45 rather than 90 because the expected findings are low-severity
  configuration/reachability issues, not remote code execution in shipped infrastructure;
  extendable if a maintainer needs longer.
- **Default publication form: aggregate or anonymised.** The public write-up reports the
  *count* and *mechanism class* of exploitable findings and one anonymised worked example
  (mechanism only, sanitised), unless a maintainer explicitly agrees to be named.

**Operational honesty:** the study author is an AI agent and cannot itself send email or open
external reports. Any maintainer notification is **drafted by the agent and sent by the human
operator (Warren)**; the write-up records the date the human sent it and the date the window
opened. No notification is claimed as sent unless the human confirms it was.

**No exploitation, ever.** Findings are established by static analysis and configuration
reading. Nothing is executed against a maintainer's artifact. See §5.

---

## 4. Comparison design — per-repo, qualitative, symmetric

For each repo, a row records:

| Field | Content |
|---|---|
| Repo (pinned SHA) | identity + commit |
| TrustLens | what it reported, per capability, with status (FOUND / NOT_FOUND / PARTIAL / UNKNOWN) |
| picklescan | what it reported |
| modelscan (ProtectAI OSS) | what it reported |
| Bandit | what it reported |
| **The question each answered** | stated explicitly per tool, so the divergence is legible |
| **Divergence** | where they disagree, and **which tool is correct on that point** — adjudicated against the code, both directions weighted equally |

**No aggregate score. No "winner."** The output is a divergence catalogue.

**On the comparison tools, stated now:** the concrete comparators are **picklescan** (pip),
**Bandit** (pip), and **modelscan (ProtectAI's open-source scanner)** (pip). modelscan is
evaluated **as a comparator in its own right**, under that exact label throughout. **ProtectAI
Guardian — the hosted commercial platform — was not evaluated in this study, and no claim of
any kind is made about it.** modelscan is not a stand-in for Guardian and its results are never
presented as Guardian's. If any comparator cannot be installed or run on a given repo, that is
recorded as "not run: reason," never silently omitted.

**Adjudication of "which is correct" is manual and by the study author** — a real limitation
(single, unblinded analyst). Mitigations: every divergence shows the code excerpt so a reader
can adjudicate independently; the classification rules (§3) and FP definition (§2) were fixed
before data.

---

## 5. Scope boundaries — what will and will not run on external artifacts

- **The Phase 3 sandbox will NOT be run on any external repository.** It is `EXPERIMENTAL`,
  gVisor-scoped, and signed off only for hostile-userspace artifacts under a controlled
  profile — not for arbitrary untrusted public repos, and not for kernel-exploitation-class
  input. This study uses **static analysis (scanner), configuration modelling (mapper), and
  offline blast-radius composition only.** Any "dynamically observed" edge is therefore
  **absent** from this study by construction; blast-radius runs on static + configured
  evidence, and its paths are labelled accordingly (no `dynamically_observed` provenance).
- **Fetching is read-only and via TrustLens `acquire`** (pins a commit, hashes after fetch) or
  an equivalent read-only clone. These are public repos; analysis of public artifacts is
  authorised. Only code/config text is retrieved; large data blobs are not.
- **The artifact is never executed, imported, unpickled, or deserialised.** The scanner's
  inertness guarantee holds on external input exactly as on fixtures.

---

## 6. What this study cannot establish — fixed now

- **No base rates.** n = 5–10 supports **no** claim about how common declared-vs-reachable
  gaps are in the wild. Every rate in the write-up is "in this corpus of 8," never "in HF
  repos."
- **Selection is popularity-ranked and code-conditioned**, not random; results describe the
  top-of-ranking code-bearing repos, not the population.
- **Single unblinded analyst** adjudicates FP/structural/exploitable and comparison
  correctness. The classification rules were pre-fixed to reduce latitude, but bias is not
  eliminated.
- **The comparison is qualitative by design** and produces no measure of relative accuracy —
  refusing that measure is the point, not a gap.
- **No dynamic observation** (§5), so blast-radius paths in this study are composed
  inferences, never observed reachability.
- **Structural confidence ceiling, stated before results.** Because the sandbox is excluded by
  construction (§5), **no blast-radius path in this study can reach the `OBSERVED` tier** under
  the weakest-link rule — a path is `OBSERVED` only if *every* edge is `dynamically_observed`,
  and no edge in this study is. Every path this study produces is therefore at best
  `configuration_derived` or `statically_derived`, and most will be `inferred`. This bounds
  what the study can establish: it can show that a *composed, evidence-labelled* reachability
  path exists and what its weakest link is, but it cannot demonstrate that any path is actually
  traversed. A reader must not read a blast-radius path here as observed behaviour; by design,
  none is.

---

## 7. Execution procedure (Phase 1) — recorded now so it cannot drift

1. Enumerate (datasets, then models) via the Hub API, sorted by downloads desc, limit 1000.
2. Apply §1 inclusion/exclusion in rank order; fill Stratum A (6) then Stratum B (2); record
   the ranked candidate log (every repo considered and the include/exclude reason) to
   `study/results/selection_log.md`.
3. For each selected repo: fetch at pinned SHA (read-only), record SHA + content hash.
4. Run `trustlens scan` (and, where an operator-supplied environment description can be
   *legitimately* constructed from the repo's own declared config, `map-credentials` and
   `blast-radius`); capture **full evidence records**, not summaries, to
   `study/results/<repo>/`.
5. Record every PARTIAL and UNKNOWN **with its cause** (the `scope.failed` reason) — a
   first-class result.
6. Run picklescan, modelscan, Bandit on the same fetched tree at the same SHA; capture raw
   output.
7. Build the per-repo divergence catalogue (§4).
8. Phase 2: search the corpus for an end-to-end case (§ predictions); report present or absent.
9. Phase 3: write up against §2 predictions, log every §9 deviation, count and exemplify false
   positives, state §6 limits.

---

## 8. Success/interest is independent of TrustLens looking good

This is pre-committed: the study **succeeds** if it produces an honest per-repo comparison and
a truthful account of where TrustLens helps, where it is noise, and where it fails to parse —
whether that account flatters the tool or not. "TrustLens found a gap every scanner missed" and
"TrustLens PARTIALed on half the corpus and Bandit was more useful" are equally publishable,
and the write-up commitment in the header covers both.

**The Phase 2 end-to-end case, specifically.** It is the only deliverable without a committed
numeric prediction and the most interesting one, which is exactly where the temptation to
manufacture lives. So it is pre-committed that **the absence of such a case is a finding in its
own right** — reported as "the corpus contained no case where the full evidence chain (static
finding → credential reachability → blast radius) changed what a reasonable engineer would
conclude relative to the card plus an existing scanner's verdict." That sentence is a
publishable result. A found case must meet the §7 bar against the actual repo; a case that
requires inventing an environment description the repo does not itself declare **does not
count** and is reported as absence.

---

## 9. Amendments log

Every post-commit protocol change is appended here with date and reason. The entries below
were made **after the seal commit but before any repository was fetched or scanned** — the
no-data-before-pre-registration invariant is intact; these are review refinements, not
post-hoc reactions to results.

- **A1 (2026-07-23, pre-scan, from human review).** §2/§8: the **absence** of a Phase 2
  end-to-end case is now explicitly a reported finding in its own right, not a study failure —
  removing the incentive to manufacture one. A case requiring an invented environment
  description the repo does not itself declare does not count.
- **A2 (2026-07-23, pre-scan, from human review).** §6: added the **structural confidence
  ceiling** — with the sandbox excluded, no path can reach `OBSERVED`; every path is at best
  configuration/statically-derived, most inferred. Stated in limitations, before results.
- **A3 (2026-07-23, pre-scan, from human review).** §1: IaC recorded as a **separate planned
  study** against checkov/tfsec (one-clean-claim rationale added), not an omission. §4:
  modelscan labelled "modelscan (ProtectAI's open-source scanner)" throughout and evaluated as
  a comparator in its own right; **Guardian-the-platform explicitly not evaluated, no claim
  made**; both negative controls retained (selecting on execution surface would otherwise make
  the result tautological).
