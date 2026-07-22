# GROUNDING

**Phase 0. Retrieval date for every source: 2026-07-22.**

The purpose of this document is not to establish novelty. It is to decide what TrustLens
should reuse, what it should invoke, what it should not rebuild, and what operational gap
is left over. A useful component is not rejected merely because its underlying idea is
already occupied.

## How to read the provenance markers

Every factual claim below carries one:

| Marker | Meaning |
|---|---|
| **[V]** | I fetched the primary source directly in this session and read the relevant bytes myself. |
| **[L]** | A grounding lane fetched the primary source and reported it. I did not independently re-fetch. Treat as sourced but single-verified. |
| **[E]** | Established empirically by running it on this machine. |
| **[?]** | Not verified. Stated as open, and nothing downstream rests on it. |

Search-engine summaries were not accepted as evidence anywhere. Where a lane's
summariser and an authoritative registry disagreed, the registry won — that happened
twice, and both corrections are recorded below.

---

## 0. The finding that reframes Phase 1

The brief lists "Hugging Face `datasets` custom loader scripts" as static check #1. That
check is **legacy and version-gated**, not live, and the live equivalent has moved.

**[V] Verified by me at the tags.** Fetching `src/datasets/load.py` at each tag:

| Tag | `"Dataset scripts are no longer supported"` | `trust_remote_code` mentions |
|---|---|---|
| `3.6.0` | 0 occurrences | 42 |
| `4.0.0` | 3 occurrences (raises `RuntimeError`) | 4 |

**[V]** On `main`, `load.py` raises `RuntimeError(f"Dataset scripts are no longer supported, but found {filename}")` at lines 1068, 1070 and 1177, and `trust_remote_code` is popped with a `logger.error` reading "`trust_remote_code` is not supported anymore." — it is ignored, not honoured.

**[V] The live vector moved to `transformers`.** On `main`,
`src/transformers/dynamic_module_utils.py` defines `get_class_from_dynamic_module` (line
516) whose own docstring states "Calling this function will execute the code in the module
file found locally or downloaded from the Hub", and `resolve_trust_remote_code` (line 712).
**[L]** Repository code is reached via the `auto_map` key in `config.json`.

**Consequence for Phase 1.** Check #1 is implemented as two distinct checks:

1. `execution.loader_script` — a dataset loader `.py`, reported with the observation that
   it is inert under `datasets >= 4.0.0` and live under a pinned older version. The
   finding must record which, because the same file is dangerous or dead depending on a
   version TrustLens cannot see from the artifact alone. Where the consuming version is
   unknown, that is an `UNKNOWN`, not a downgrade to safe.
2. `execution.dynamic_import` via `auto_map` in `config.json` plus the `*.py` it
   references — the live vector, in **model** repositories.

**[V] This does not contradict the July 2026 incident.** The Hugging Face disclosure says
the initial vector was "a remote-code dataset loader and a template-injection in a dataset
configuration" in *their own dataset processing*. That is a statement about Hugging Face's
production pipeline, not about the public `datasets` library at version ≥ 4.0.0. Which
code path their pipeline ran is **[?]** not something I can determine, and nothing here
assumes it.

---

## 1. Existing capability to REUSE

Imported or invoked directly. TrustLens wraps the output into evidence records; it does
not reimplement the analysis.

| Capability | Tool | Version | Licence | Basis |
|---|---|---|---|---|
| Pickle opcode / unsafe-globals scan | picklescan | 1.0.5 | MIT | [L] |
| Broader model formats (H5, Keras v3, TF SavedModel) | modelscan | 0.8.8 | Apache-2.0 | [L] |
| Pickle symbolic execution + allowlist mode | fickling | 0.1.12 | **LGPL-3.0** | [L] |
| Python security checks | Bandit | 1.9.4 | **Apache-2.0** | **[V]** licence read from `LICENSE`; plugin entry points read from `setup.cfg`; [L] version and test IDs |
| Pattern + taint rules, **TrustLens-authored rules only** | Semgrep CE (engine) | 1.170.0 | **LGPL-2.1** engine / rules see warning below | **[V]** engine licence read from `LICENSE`; [L] rules licence |
| Python parsing, happy path | stdlib `ast` | 3.14.4 | PSF | **[E]** |
| Python parsing, failure path → `PARTIAL` | tree-sitter + tree-sitter-python | 0.26.0 / 0.25.0 | MIT | [L] |
| Dependency vulnerabilities, genuinely offline | osv-scanner | v2.4.0 | Apache-2.0 | [L] |
| SBOM from a directory | syft | v1.49.0 | Apache-2.0 | [L] |
| Secrets in the repo tree | gitleaks | v8.30.1 | MIT | [L] |
| AWS action / access-level / ARN metadata, offline | policy_sentry | 0.16.0 | MIT | [L] |
| IAM policy lint and grammar validation | Parliament | 1.64 | BSD-3-Clause | [L] |
| Per-policy IAM risk classification, offline | Cloudsplaining | 0.9.1 | BSD-3-Clause | [L] |
| Rule evaluation engine | OPA | v1.18.2 | Apache-2.0 | [L] |
| Multi-format config parsing front end | Conftest | v0.68.2 | Apache-2.0 | [L] |
| Kubernetes manifest linting, offline | KubeLinter | v0.8.3 | Apache-2.0 | [L] |
| K8s RBAC rule coverage | Checkov | 3.3.8 | Apache-2.0 | [L] |
| Terraform plan/state/config query, offline | Steampipe `terraform` plugin | v1.2.0 | Apache-2.0 | [L] |

### Why these, specifically

**Pickle scanning is a solved and actively maintained problem, and TrustLens must not
re-solve it.** [L] picklescan carries 59 non-duplicate published advisories, with fixes
shipping as recently as version 1.0.4 — that is a *maintained* blocklist under adversarial
pressure, and a reimplementation would start with none of that history. TrustLens imports
it and records the version alongside every verdict, because [L] a clean verdict from a
blocklist scanner is a statement about that blocklist at that version, not about the file.

**Three pickle scanners, not one, because their architectures differ.** [L] picklescan is
blocklist-default-allow; fickling's ML mode is allowlist-default-deny; modelscan covers
formats the other two do not touch. Where they disagree, the disagreement is recorded as
a contradiction rather than resolved by picking a favourite.

**[E] `ast` fails hard per file, which is exactly the behaviour the schema wants.** Tested
on this machine: a syntax error, a Python-2 `print` statement, and an embedded null byte
each raise `SyntaxError`; non-UTF-8 bytes raise `UnicodeDecodeError` at decode time before
parsing. `ast.parse` never returns a partial tree. Each failure maps to one
`scope.failed` entry and therefore forces `PARTIAL`. Python-2-syntax files are common in
older dataset repositories, so `PARTIAL` will fire on realistic inputs rather than
contrived ones.

**[L] Bandit already ships the two ML-specific checks TrustLens most needs**, which is
exactly the kind of thing a reuse survey exists to find before writing a rule:
`B614 pytorch_load` ("unsafe use of `torch.load` and `torch.serialization.load`… can lead
to arbitrary code execution", CWE-502) and `B615 huggingface_unsafe_download`
("Downloading models, datasets, or files without specifying a revision based on an
immutable revision (commit) can lead to supply chain attacks"). Those cover mechanisms 8
and 11 in §5 at source level. Do not author replacements.

**[L] `ast` and tree-sitter are complementary, not alternatives.** `ast` **[E]** raises and
returns nothing; tree-sitter always returns a tree carrying queryable `(ERROR)` and
`(MISSING)` nodes plus `Node.has_error`. That is the documented primitive for "we parsed
some of this file but not all of it", so Phase 1 parses with `ast` first, falls back to
tree-sitter on failure, and marks the file `PARTIAL` when `has_error` is true — recording
which construct defeated the parse rather than only that one did.

### ⚠ Licence hazards recorded deliberately

**Semgrep: the engine and the rules have different licences, and the rules are the trap.**
**[V]** The CE engine is LGPL-2.1. **[L]** The `semgrep-rules` registry is under the
**Semgrep Rules License v1.0**, which is *not* OSI-approved and states verbatim: "You may
use the rules **only for your own internal business purposes**. This license does not allow
you to distribute the rules, or to make them available to others as a service." The
documentation adds: "**Vendors cannot use Semgrep-maintained rules in competing products or
SaaS offerings.**"

Consequence, binding on Phase 1: **TrustLens invokes the Semgrep engine as a subprocess and
ships only TrustLens-authored rules.** No registry rule is vendored, referenced by
`--config=p/...`, or reproduced in a TrustLens rule file. This is the single most likely
licence mistake for a future contributor, because pulling a registry rule is one flag away
and looks like reuse.

**[L] Semgrep CE is intra-procedural.** Interfile and interprocedural taint analysis is a
Pro (proprietary) feature. Phase 1's dataflow findings are therefore bounded to
single-function, single-file flows, and `STATIC_DATAFLOW` must not be claimed for anything
wider.

**Copyleft positions.** Semgrep engine **[V]** LGPL-2.1 and fickling **[L]** LGPL-3.0 are
invoked or dynamically imported, which is workable for an Apache-2.0 TrustLens; neither may
be vendored or modified into the distribution without redoing that analysis.

---

## 2. Existing capability to INTEGRATE

Outputs consumed as **evidence with a version attached**, never as an oracle.

| Source | What TrustLens takes | Why not an oracle |
|---|---|---|
| Hugging Face Hub per-file `securityFileStatus` (`/api/models/{repo}/tree/main?expand=true`) | Five sub-scanner verdicts per file: `protectAiScan`, `avScan`, `pickleImportScan`, `virusTotalScan`, `jFrogScan` | [L] Observed `pickleImportScan.version` values on one repo ranged `0.0.0`–`0.0.32` while current picklescan is `1.0.5`, indicating verdicts are cached at upload-time scanner version. A `safe` from an old scanner is not `safe` under the current one. [L] Statuses of `unscanned` were also observed and are absence of evidence, not evidence of absence. |
| Hugging Face security documentation | The platform's own stated scope | [L] The docs state plainly: "this is not 100% foolproof... the safe/unsafe imports lists we have are maintained in a best-effort manner." |
| Trivy, KICS | Config/misconfiguration breadth | [L] Trivy needs its checks bundle; the embedded fallback bundle is the air-gap path and must be pinned and verified for zero egress. [L] KICS documents no air-gap mode and has a flag implying default egress. |
| MITRE ATLAS | Capability-category alignment | [L] ATLAS v5.6.0. Anchor technique **AML.T0112.001** (Machine Compromise → AI Artifacts). Note the technique **AML.T0010** is now named **"AI Supply Chain Compromise"**, not "ML Supply Chain Compromise" — [L] the old website path 404s; cite the `atlas-data` repository. **AML.T0109** (rug pull) is why scanning is revision-pinned rather than repo-named. |
| CWE | Finding classification | [L] **CWE-502** now lists AI/ML as "Often Prevalent". Scanner-evasion classes: CWE-20, CWE-693, CWE-755. |
| CycloneDX 1.7 / ECMA-424 | Service and dependency-graph layer of the environment description | [L] Carries services, endpoints, trust-boundary traversal and directional data flow — but no principal, permission or action model. The authorization layer is a TrustLens extension, not an adoption. |
| Terraform JSON output format (`format_version` 1.0) | The Terraform input contract | [L] `configuration.references` gives dependency edges already unwrapped, so consumers need not parse expressions. This is where Phase 2's Terraform edges come from. |

### The correction log

Two claims arrived from page summarisers and were overturned by authoritative registries.
Both are recorded because the failure mode matters more than the facts:

1. [L] `datasets` 4.0.0 reported as released July 2024; the GitHub releases API gives
   **2025**-07-09.
2. [L] Three picklescan CVEs reported with an identical CVSS of 9.3; NVD gives
   **7.8 / 9.8 / 7.8**. An identical score across three different bugs was the tell.

Neither error would have been caught by reading a well-formatted summary. Both were caught
by resolving the identifier against a registry.

---

## 3. Existing capability that is SUFFICIENT — do not rebuild

| Function | Adequate existing tool | Decision |
|---|---|---|
| Pickle opcode inspection and unsafe-global detection | picklescan, fickling, modelscan | Do not write a pickle parser. |
| Python AST construction | stdlib `ast` | Do not write a Python parser. |
| Generic Python security patterns | Bandit, Semgrep | Do not write generic rules; write only the ML-specific ones no existing rule set covers. |
| AWS IAM policy grammar and action metadata | Parliament, policy_sentry, the AWS policy grammar spec | Do not hand-roll IAM semantics. [L] The incomplete-ARN completion rule (`arn:aws:sqs` ≡ `arn:aws:sqs:*:*:*`) is exactly what a hand-rolled parser gets wrong. |
| Kubernetes manifest hygiene linting | KubeLinter, kube-score, Checkov | Do not write K8s linters. |
| IaC misconfiguration breadth | Checkov, Trivy, KICS | Do not write IaC rules. |
| SBOM / SCA | syft, grype, trivy, osv-scanner | Out of scope; integrate if needed. |
| Formal policy equivalence / subsumption | `cedar-policy-symcc` + cvc5 | [L] Genuine offline Zelkova-class analysis — but over **Cedar**, not IAM JSON. Translating IAM to Cedar is a project, not a wiring job. Not adopted in Phase 2. |
| Graph rendering | Powerpipe | [L] AGPL-3.0. Usable as a separate process against a local database; licence-flagged. |

### Deliberately not used

| Tool | Reason |
|---|---|
| Terrascan | [L] Repository **archived**; banner states no further updates. |
| tfsec | [L] Superseded — repository description states "Tfsec is now part of Trivy". |
| rbac-tool, kubectl-who-can, KubiScan, rakkess | [L] All require a live cluster. Only `auditgen -f` takes a file, and it takes audit logs, not manifests. KubiScan is additionally GPL-3.0. |
| IAM Access Analyzer, Amazon Verified Permissions, CloudFox | [L] Network APIs. Incompatible with the offline constraint, and Access Analyzer's custom checks are billed per call. |
| PMapper, awspx | [L] Graph *construction* requires live ingest; PMapper is AGPL-3.0 and stale since Aug 2024, awspx is GPL-3.0 and stale since 2021. Their on-disk graph layouts are worth copying as formats; their code is not. |
| Cartography | [L] The most mature OSS cloud asset graph, but ingest is live-credential only. Schema studied, ingest not used. |
| **CodeQL** | **[L] Verified DO-NOT-USE, on licence.** The GitHub CodeQL Terms and Conditions permit use only for academic research, demonstration, and analysis of an "Open Source Codebase" (defined as released under an OSI-approved licence). They explicitly prohibit "To otherwise or in any other context generate any CodeQL database for or during automated analysis, CI or CD", and prohibit making the software "available as a hosted solution (whether on a standalone basis or combined, incorporated or integrated with other software or services) for others to use". TrustLens performs automated analysis of untrusted repositories that are frequently not OSI-licensed, and would ship the tool integrated. All three conditions are violated. The GHAS carve-out is per-customer and cannot be relied on by a tool. |
| trufflehog | [L] **AGPL-3.0**, a distribution hazard for a shipped or hosted TrustLens; and its headline capability is active network verification against live APIs, which an offline scanner must disable — leaving the weaker half of the tool. Use gitleaks (MIT, embedded rules, SARIF) instead. |
| Semgrep registry rules | [L] Semgrep Rules License v1.0 — internal business use only, no distribution, vendors excluded. See the licence hazard above. The engine is used; the rules are not. |
| krane | [L] The only offline K8s RBAC *graph* tool found, which makes it attractive — but it is v0.1.3, last released Dec 2024, and hard-depends on RedisGraph, whose lifecycle status is **[?]** unverified. Evaluate before depending on it. |

---

## 4. The operational gap TrustLens will fill

Existing tooling does not block TrustLens where the workflow is fragmented, outputs cannot
be combined, provenance is lost, or negative results do not expose the analysed scope.
Each gap below is stated as something no fetched tool does, not as something novel.

### 4.1 Nothing compares declared against static against configured against dynamic

Every tool surveyed answers one of those questions. None compares them, because none
shares a capability vocabulary with the others. The comparison is the product, and it
requires exactly what Phase 0 built: one capability enum, one evidence-strength scale, one
status taxonomy, one record format.

### 4.2 Negative results do not expose their scope, and scanners fail open

This is the sharpest gap, and it is evidenced by the failure history of the incumbents.
[L] Three published picklescan CVEs are all *scanner* failures rather than format failures:

| CVE | CVSS (NVD) | Mechanism |
|---|---|---|
| CVE-2025-10155 | 7.8 | Parser dispatched on **file extension**; the scanner skips, the loader loads by content. |
| CVE-2025-10156 | **9.8** | A **bad CRC** halts the scanner; PyTorch's loader disables CRC validation. |
| CVE-2025-10157 | 7.8 | Unsafe-globals check does **exact module-name match**; `asyncio.unix_events` evades an `asyncio` blocklist. |

All three produce a **clean verdict on a malicious file**. Two of the three are precisely
the failure the five-state taxonomy exists to prevent: an analysis that did not complete,
reported as an analysis that completed and found nothing.

TrustLens's response is structural rather than aspirational:

- Parsers dispatch on **content**, never on extension.
- A parse failure, a halt, or a timeout produces `PARTIAL` with the path and reason, and
  the schema makes the clean alternative **inexpressible** — not discouraged, inexpressible.
- Matching is prefix/submodule-aware where the underlying tool permits.

Honest bound: this closes two specific instances and does not make TrustLens immune to the
class. It is subject to the same class as any scanner. [L] The PickleBall paper
(arXiv 2508.15987, CCS 2025) states plainly that "evaluated model scanners fail to identify
known malicious models", and [L] JFrog reports >96% false positives from pickle-import
scanning — a vendor claim about a competing method, cited as their characterisation rather
than as measurement.

### 4.3 Cross-domain credential edges, offline

[L] No fetched tool joins Kubernetes RBAC to cloud IAM from supplied descriptions.
Cartography does this shape only from live ingest. This is the clearest single gap and it
is what makes an attack path from a dataset worker to a cloud resource expressible at all.

### 4.4 Blast radius from a supplied description

[L] BloodHound, awspx and PMapper all perform reachability, and all do it over graphs
produced by their own live collectors. None accepts an operator-authored offline
description.

### 4.5 IAM evaluation over a *planned* rather than deployed environment

[L] IAMSpy and iam-lens both start from data collected from a live account
(`get-account-authorization-details`, `iam-collect`). Nothing evaluates IAM semantics from
a Terraform plan — i.e. before the environment exists.

### 4.6 Docker/Compose credential and mount graph

[L] Every compose-aware tool found (KICS, Conftest, Trivy) emits flat findings only.

### 4.7 An environment-description schema carrying principals, permissions and edges

[L] CycloneDX carries services and directional flows but no authorization model; OSCAL
carries control implementations; SCIM carries identities; OCSF carries events. None carries
principals, permissions and reachability edges together. TrustLens extends CycloneDX rather
than inventing a format from scratch.

### 4.8 Staleness that travels

No surveyed tool carries a capture timestamp through a derived conclusion. TrustLens makes
`description_captured_at` mandatory on every environment description, attaches it to every
config-derived finding rather than only to the run header, and propagates it through
composition — so a six-month-old model says so at every edge that depends on it.

### 4.9 Contradiction reporting

No surveyed tool reports that two of its inputs disagree; they reconcile silently or
consume one source. TrustLens records contradictions as findings and pins `reconciled` to
`false` in machine-produced records.

### 4.10 The incident's own vector has no off-the-shelf check

Worth stating on its own, because it inverts the expected result of a reuse survey.

[L] Bandit's template checks — `B701 jinja2_autoescape_false`, `B702`, `B703`, `B704` — are
**autoescape and XSS checks, not server-side template injection checks**. They do not cover
user-controlled template *source* reaching `Template()` or `render_template_string()`.
[L] Semgrep's registry does carry SSTI rules, but the Semgrep Rules License forbids
TrustLens shipping them. [L] No permissively-licensed engine with an SSTI check was located,
and **no engine at all was found documenting a check for expression evaluation in
TOML/YAML configuration reaching a sink**.

So the mechanism Hugging Face named as one of two initial vectors — "a template-injection
in a dataset configuration" — is the one mechanism in §5 for which no existing tool can be
reused. Phase 1 must author that rule itself, and it is the check least able to lean on
prior art. The distribution of tooling attention and the distribution of exploited surface
are not the same, and this is where they come apart most sharply.

### 4.11 Finding-specific mitigation

Surveyed tools emit rule-keyed remediation text. TrustLens ties each mitigation to the
finding ids that triggered it, the resource affected, the path expected to be removed, the
trade-off, and whether it was dynamically verified — and the schema forbids generic advice
from existing without at least one specific mitigation.

---

## 5. Attack mechanism → check, with the source that supports it

Rows with no fetched primary source were dropped rather than carried as plausible.

| # | Mechanism | Check | Source |
|---|---|---|---|
| 1 | pickle `__reduce__` RCE on load | `GLOBAL`/`STACK_GLOBAL`/`REDUCE` opcode scan + unsafe-global resolution | [L] JFrog 2024-02-27; HF security-pickle; arXiv 2508.15987 |
| 2 | Extension-based parser evasion | Content sniffing, never extension dispatch | [L] CVE-2025-10155 (NVD) |
| 3 | Corrupt-CRC archive halts scanner | Parse failure ⇒ `PARTIAL`, never clean | [L] CVE-2025-10156 (NVD) |
| 4 | Submodule evasion of a blocklist | Prefix/submodule-aware matching | [L] CVE-2025-10157 (NVD) |
| 5 | `trust_remote_code` via `auto_map` in **model** repos | Flag `auto_map` in `config.json` + referenced `*.py` | **[V]** transformers source; [L] arXiv 2601.14163 |
| 6 | Legacy dataset loader scripts | Version-gated; live only under `datasets < 4.0.0` | **[V]** datasets source at tags 3.6.0 / 4.0.0 / main |
| 7 | Keras Lambda layer arbitrary code | Flag Lambda in `.keras`/H5; flag `safe_mode=False` | [L] keras.io saving docs |
| 8 | `weights_only=False` / `add_safe_globals` widening | Flag both in caller code | [L] PyTorch 2.13 docs, which also state `weights_only=True` "does not guard against denial of service attacks" |
| 9 | Repo-as-CDN, private dataset as exfil sink | Flag non-model binaries and outbound `resolve/main` URLs in scripts | [L] JFrog 2026-04-23 |
| 10 | Package build hooks in data-presenting repos | Flag `postinstall`, `setup.py`, build hooks | [L] JFrog 2026-04-23 |
| 11 | Rug pull — clean now, malicious later | Pin and re-scan by **revision** | [L] ATLAS AML.T0109 |
| 12 | Template injection in dataset configuration | Expression-bearing values in YAML/JSON/TOML reaching a sink — **TrustLens-authored; no reusable engine check exists (§4.10)** | **[V]** HF incident disclosure names this vector explicitly |
| 13 | Over-flagging on import presence alone | Severity depends on **use**, not on import presence | [L] JFrog; arXiv 2508.15987 |

Considered and **dropped as unsupported**: unsafe YAML deserialization in ML configs, and
chat-template/Jinja injection in `tokenizer_config.json` — no primary source was located
for either. GGUF prediction-stage execution and ONNX architectural backdoors are attested
only in a vendor product blog and are carried as low-confidence, not implemented as checks.

Note the tension worth stating: mechanism 12 is named by the incident disclosure but had
no dedicated technical literature located, while mechanism 1 has abundant literature and
is not what the incident used. Tooling attention and exploited surface are not the same
distribution.

---

## 6. Nearest prior art

[L] **arXiv 2601.14163** — *An Empirical Study on Remote Code Execution in Machine Learning
Model Hosting Ecosystems* (Siddiq, Romel, Sekerak, Casey, Santos; 2026-01-20). Five
platforms, `trust_remote_code`/`trust_repo` explicitly covered, method is Bandit + CodeQL +
Semgrep with findings categorised by CWE. This is the closest published work to Phase 1's
static half and its tool selection independently matches the reuse decisions above.

It is a study, not a tool: it does not produce a shared evidence record, does not model
credential reachability, does not compare declared against observed, and does not ship
mitigations. **[?] I have read only the abstract as reported.** It must be read in full
before Phase 1 finalises its rule set, and that is recorded as a Phase 1 entry condition.

[L] **arXiv 2508.15987** — *PickleBall* (CCS 2025). Reports 44.9% of popular HF models
still use pickle, and that evaluated scanners have both false positives and false
negatives. Supports the decision to treat any single scanner's verdict as evidence rather
than as an oracle.

---

## 7. Reuse-versus-build decision log

| # | Decision | Verdict | Reason |
|---|---|---|---|
| D1 | Pickle opcode scanning | **Reuse** (picklescan + fickling + modelscan) | Maintained under adversarial pressure; reimplementation starts with no advisory history. |
| D2 | Reconcile disagreeing scanners | **Build** | No tool records inter-scanner disagreement; TrustLens emits it as a contradiction. |
| D3 | Python parsing | **Reuse** stdlib `ast` | [E] Hard per-file failure maps cleanly to `PARTIAL`. |
| D4 | Generic Python security rules | **Reuse** Bandit + Semgrep | Mature and offline-capable; write only the ML-specific rules. |
| D5 | Evidence record format | **Build** | No surveyed format carries scope, strength, staleness and five-state status together. |
| D6 | Status taxonomy | **Build** | The failure it prevents is a documented, exploited CVE class in the incumbents. |
| D7 | IAM semantics | **Reuse** Parliament + policy_sentry | Hand-rolled IAM parsing gets ARN completion and condition semantics wrong. |
| D8 | IAM reachability graph | **Build** | All offline evaluators start from live-collected account data. |
| D9 | Cross-domain K8s→IAM edges | **Build** | No offline tool does this. |
| D10 | Terraform ingest | **Reuse** the documented JSON format + Steampipe plugin | `configuration.references` already supplies unwrapped dependency edges. |
| D11 | Environment description schema | **Extend** CycloneDX 1.7 | Carries services and flows; authorization layer is the extension. |
| D12 | Rule engine | **Reuse** OPA/Rego + Conftest | Evaluates rules over a graph; TrustLens supplies the graph. |
| D13 | Blast-radius simulation | **Build** | Existing path engines require their own live collectors. |
| D14 | Formal policy equivalence | **Defer** | Cedar-only; IAM→Cedar translation is a project in itself. |
| D15 | CodeQL | **Reject** | [L] Licence prohibits automated analysis of non-OSI codebases and prohibits integrated distribution. Verdict is settled, not deferred. |
| D17 | Semgrep registry rules | **Reject; author our own** | [L] Semgrep Rules License v1.0 excludes vendor use and distribution. Engine reused, rules not. |
| D18 | Parse-failure handling | **Reuse** tree-sitter as the `ast` fallback | [L] `(ERROR)`/`(MISSING)`/`has_error` is the documented primitive for `PARTIAL`. |
| D19 | ML-specific source checks (`torch.load`, unpinned HF revision) | **Reuse** Bandit `B614`, `B615` | Already exist and are maintained; authoring replacements would be duplication. |
| D20 | SSTI and config-borne expression evaluation | **Build** | [L] No permissively-licensed engine check exists. This is the incident's own vector. |
| D21 | Dependency vulnerabilities | **Reuse** osv-scanner `--offline` | [L] The only surveyed scanner with a documented single-flag no-network mode. |
| D22 | Secret detection | **Reuse** gitleaks (MIT); reject trufflehog | [L] AGPL-3.0 plus network-verification-by-default. |
| D16 | Graph rendering | **Reuse** Powerpipe, out of process | AGPL-3.0; acceptable across a process boundary, flagged. |

---

## 8. What Phase 0 did not establish

- **[?]** RedisGraph's lifecycle status, which gates any use of krane.
- **[?]** The exact shape of Semgrep's JSON `errors[]` record for a Python syntax error.
  Its existence in CE is documented; the record shape is not, and Phase 1's `PARTIAL`
  mapping depends on it. Determine empirically.
- **[?]** Behaviour of gitleaks, syft and osv-scanner on undecodable or malformed input
  files. Undocumented; each must be tested before its output is trusted to distinguish
  "nothing found" from "could not read".
- **[?]** Whether gitleaks emits telemetry. Not documented either way.
- **[?]** Whether Hugging Face re-scans existing blobs when its scanners are upgraded. The
  staleness conclusion is inferred from observed per-file version values, not from a
  documented policy.
- **[?]** Whether Checkov's in-memory resource graph can be exported as an artifact.
- **[?]** Full text of arXiv 2601.14163 — abstract only.
- **[?]** Which code path Hugging Face's own dataset processing pipeline ran in July 2026.
- **[?]** Whether modelscan resists the picklescan bypass classes. It has zero published
  advisories, which is not evidence of robustness — researchers file against picklescan and
  fickling.

None of these blocks Phase 1. Each is recorded so that a later decision does not quietly
assume one was settled.

## 9. On the July 2026 Hugging Face incident

**[V]** Fetched and verified directly: `https://huggingface.co/blog/security-incident-july-2026`,
HTTP 200, title "Security incident disclosure — July 2026", published 16 July 2026.
Verbatim, the initial vector: "A malicious dataset abused two code-execution paths in our
dataset processing (a remote-code dataset loader and a template-injection in a dataset
configuration) to run code on a processing worker." The page also states: "We have found no
evidence of tampering with public, user-facing models, datasets, or Spaces."

That second sentence constrains the framing. Any account of this incident as a
model-artifact compromise miscites the source — which matters, because the model-artifact
surface is where nearly all existing tooling points.

The permitted framing, used everywhere in this repository:

> This class of tool could surface execution, credential, and reachability gaps of the
> kind involved in the incident.

TrustLens did not exist at the time, was not deployed, and makes no claim about what would
have happened had it been. The incident is cited for one reason: it is primary evidence
that dataset-processing execution, credential exposure from a processing worker, and
lateral movement between them are real and were exploited together — which is why the four
components are scoped as they are, and why Phase 2 exists at all rather than the project
stopping at a scanner.
