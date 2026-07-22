# Scanner — claims and bounds

**Status: all ten Phase 1 check families implemented.** Static analysis only; the scanner
does not acquire, execute, or model an environment.

| # | Family | Module | Capabilities emitted |
|---|---|---|---|
| 1 | Loader scripts and remote-code entry points | `checks/loader_scripts.py` | `execution.loader_script`, `execution.dynamic_import`, `execution.build_hook` |
| 2 | Dynamic execution | `checks/python_surface.py` | `execution.dynamic_eval`, `execution.dynamic_import` |
| 3 | Process and shell invocation | `checks/python_surface.py` | `process.subprocess`, `process.shell` |
| 4 | Network access | `checks/python_surface.py` | `network.outbound`, `network.listen`, `network.dns`, `network.package_fetch` |
| 5 | Template and expression injection | `checks/template_injection.py` | `template.injection_surface`, `template.expression_evaluation`, `execution.deserialization` |
| 6 | Dangerous deserialization | `checks/python_surface.py` | `execution.deserialization` |
| 7 | Environment access | `checks/python_surface.py` | `env.named_read`, `env.enumeration`, `env.credential_pattern_read` |
| 8 | Filesystem behavior | `checks/python_surface.py` | `filesystem.write`, `.delete`, `.permission_change`, `.archive_extraction`, `.read_sensitive_path`, `.path_traversal` |
| 9 | Package installation and build triggers | `checks/python_surface.py` | `package.install_at_runtime`, `package.manager_invocation`, `execution.build_hook` |
| 10 | Cloud and orchestration surfaces | `checks/python_surface.py` | `cloud.metadata_endpoint`, `.sdk_credential_discovery`, `.credential_file_access`, `k8s.api_access`, `k8s.serviceaccount_token_access`, `container.docker_socket` |

## Scanning is inert, and that is demonstrated

`tests/scanner/test_inertness.py` builds a repository whose payloads fire on import, on
unpickle, and on unsafe YAML load; **proves each payload is live by detonating it
deliberately**; then runs every check with `subprocess`, `os.system` and `socket` replaced
by objects that raise. No canary appears, nothing enters `sys.modules`, and no file in the
scanned tree is modified. Proving the planted case is live is what stops the control being
vacuous — an inert file staying inert would demonstrate nothing.

TrustLens parses Python and YAML itself rather than inheriting an external tool's view of
what parsed. `ast.parse` runs behind a recursion fence because the documented
interpreter-crash vector takes attacker-chosen input, and hitting it produces a recorded
failure rather than a crash.

## The assembler cannot report clean for work it did not do

`assemble.scan()` runs every family and reconciles **declared coverage against delivered
findings**. Each family states up front which capabilities it is responsible for; anything
promised and not delivered becomes an `UNKNOWN` finding plus a recorded coverage gap.

| Failure injected | Result |
|---|---|
| A family silently drops a finding | coverage gap + `UNKNOWN` for that capability; `analysis_complete` false |
| A family raises | scope failure naming the exception; every promised capability becomes `UNKNOWN` |
| A family emits a schema-invalid finding | finding rejected, recorded as an `internal_error` scope failure, capability becomes `UNKNOWN` |
| A family hand-assembles `NOT_FOUND` over a failed scope | rejected by schema validation, leaving a coverage gap |
| A family raises while others succeed | the working families' findings are preserved |

Tested in `tests/scanner/test_assemble.py`. The property in one sentence: **the overall
verdict cannot be clean unless every declared capability was actually reported on.**

This reconciliation immediately caught a real gap: `env.credential_pattern_read` is derived
at match time and was only ever emitted when it matched, so a clean repository made no
statement about it at all. It is now emitted unconditionally.

**Per-finding scope may be narrower than record scope, deliberately.** The loader-scripts
family reads only `.py` and `.json`, so an undecodable `.yaml` is genuinely outside its
scope and its clean result is honest. To stop that being misread, `summarise()` surfaces
`scope_failures` and `scope_complete` at the top level, so a reader sees that something in
the artifact could not be analysed without cross-referencing every finding.

## External tools

**No external tool is wired into any `FOUND` or `NOT_FOUND_WITHIN_ANALYSED_SCOPE` claim.**
Every finding comes from TrustLens's own analysis, and the scanner spawns no processes at
all — a property the inertness harness verifies by making `subprocess.run` raise.

Of the five surveyed tools, only Bandit has verified failure reporting
(`docs/PHASE1_ENTRY_CONDITIONS.md`). Semgrep, gitleaks, syft and osv-scanner remain
excluded from status claims until each is independently verified against malformed input.
Re-checked 2026-07-22: no shipped code references or invokes any of them, and the
entry-condition probe still reproduces all five characterisations unchanged.

**Bandit integration deferred, 2026-07-22.** Not a passive TODO — a decision with a reason.
Introducing Bandit means the scanner spawns a subprocess for the first time, which requires
its own design: an allowlisted binary, the executed version recorded in
`tool.external_tools`, exit code and stderr captured as evidence (Bandit's `errors[]` is
trustworthy but its exit code still carries information), and the inertness harness taught
to distinguish "spawns the one approved analyser" from "spawns anything". Until that design
exists, adding Bandit would weaken the strongest property the scanner currently has.
Revisit when the harness can express the distinction.

## What the template-injection check establishes

- The configuration files listed in `scope.analysed` were parsed successfully, and the
  files listed in `scope.failed` were not, each with a reason.
- Where a finding is `FOUND`, a value matching the named detector exists at the recorded
  file, line and key path. The excerpt shown is drawn from that value.
- Where a `template.expression_evaluation` finding cites a flow, a name bound from a
  configuration loader reaches a rendering or evaluating sink **within the same function**
  of the cited file.
- Where a `execution.deserialization` finding is `FOUND`, a YAML tag constructing an
  arbitrary Python object is present at the recorded position. **TrustLens recorded that tag
  without constructing it**, and this is demonstrated rather than asserted — see
  `test_dangerous_yaml_tag_is_not_executed`, which fails if the object is ever constructed.
- Where a finding is `NOT_FOUND_WITHIN_ANALYSED_SCOPE`, every file in the recorded scope
  parsed successfully and no detector matched in any of them.

## What it does not establish

- **That any matched expression is rendered or evaluated at runtime.** A surface match is a
  statement about a file's contents, not about program behavior.
- **That a detected flow executes.** The flow is a syntactic path within one function; it
  says nothing about whether that function is called.
- **That an unmatched repository is free of template injection.** Detection is syntactic. An
  expression assembled at runtime from fragments, stored in a format this check does not
  parse, or expressed through a resolver not in the detector set, is not matched.
- **That a `FOUND` result indicates malice.** Conventional template syntax is common and
  usually benign; the `template.injection_surface` finding is an inventory, not an
  accusation.
- **That the configuration is ever loaded at all.** A YAML object tag is dangerous only
  under a constructing loader; under `yaml.safe_load` it raises.

## Known gaps, stated rather than discovered later

- **Interprocedural and cross-file flows are not detected**, and a test asserts they are not
  claimed. A config value passed between functions before reaching a sink is a known miss.
- **Backtick shell substitution is not matched.** The detector existed in the first version
  and was removed when the false-positive control caught it firing on `` `--verbose` `` in a
  prose description field. Inline code in prose is far more common in ML configuration than
  backtick substitution, so the pattern cost more soundness than it bought completeness. A
  backtick payload is a deliberate, recorded miss.
- **Single-brace format fields (`{name}`) are not matched.** Too common in prose and regex
  to be sound without a flow to a `.format()` sink; deferred until that flow analysis exists.
- **Only YAML, JSON and TOML are parsed.** INI, `.env`, XML, Jsonnet and HCL configuration is
  out of scope for this check and appears in neither `analysed` nor `failed` — it is simply
  not a configuration file as far as this check is concerned.
- **JSON and TOML line numbers are best-effort.** Their parsers discard positions, so the
  line is located by searching the source text for the matched value. If the same string
  appears twice, the first occurrence is reported. YAML line numbers come from the parser
  and are exact.
- **The `chat_template` suppression is a judgement call.** Conventional Jinja in a known
  template field is suppressed because `transformers` renders those templates in an
  `ImmutableSandboxedEnvironment` (verified in `utils/chat_template_utils.py`). If a
  consumer renders a chat template *outside* that sandbox, this check under-reports. The
  suppression is counted and surfaced in the finding rather than applied silently.

## Deliberate gaps in families 1–4 and 6–10

Recorded as they were made, not discovered later.

**Rules that deliberately do NOT fire on an omitted argument.** Flagging the default would
produce noise on ordinary modern code, so these fire only on a literal:

| Construct | Fires on | Deliberate miss |
|---|---|---|
| `torch.load` | `weights_only=False` written literally | An artifact pinned to a PyTorch old enough to default `weights_only=False`. The consuming version is not visible in the artifact. |
| `numpy.load` | `allow_pickle=True` written literally | Same shape; the default is safe. |
| Keras `load_model` | `safe_mode=False` written literally | Lambda layers inside a `.keras` archive are a separate, unimplemented check. |
| `subprocess(...)` | `shell=True` written literally | `shell` supplied via a variable or `**kwargs`. |
| `open(...)` | a literal mode containing `w`, `a`, `x` or `+` | A computed mode string is claimed in neither direction. |
| `yaml.load` | no Loader, or a non-safe Loader | A Loader passed through a variable is treated as unsafe, which over-reports. |

**Rules that knowingly over-report.** Matched on a bare method name, so any object exposing
that method matches. None is escalated:

- `bind`, `listen` (`network.listen`)
- `write_text`, `write_bytes`, `unlink` (`filesystem.*`)
- `extractall`, `extract` (`filesystem.archive_extraction`)
- `setup` (`execution.build_hook`) — the repository-shape check distinguishes a real `setup.py`

**Archive extraction — resolved 2026-07-22, previously an over-reporting gap.** The rule
now distinguishes three cases and no longer fires on code that has already done the right
thing:

| Written | Reported |
|---|---|
| `extractall(...)` with no `filter=` | `archive-extraction-unfiltered`, **not** escalated, with the version condition stated |
| `extractall(..., filter='data')` or `filter='tar'` | not reported |
| `extractall(..., filter='fully_trusted')` | `archive-extraction-fully-trusted`, escalated |
| `extractall(..., filter=some_variable)` | not reported — a recorded miss |
| `tarfile.open(...)` / `zipfile.ZipFile(...)` | `archive-open` only; opening is not extracting |

**Correction to an earlier claim in this file:** it previously said the constrained default
arrived in Python 3.12. That was wrong. Verified from the `tarfile` documentation
(retrieved 2026-07-22): "Changed in version **3.14**: Set the default extraction filter to
`data`... Previously, the filter strategy was equivalent to `fully_trusted`." So an
unfiltered `extractall` is unsafe by default on 3.13 and earlier and safe by default from
3.14 — and the consuming Python version is not visible in the artifact, so the finding
states the condition rather than asserting which applies. This is the same version-gate
shape as the `datasets` loader-script finding.

A computed `filter=` is deliberately not flagged: the finding's own wording is "without an
explicit extraction filter", and firing when one *was* supplied would make the finding text
false. Missing that case is preferable to reporting something untrue.

**String rules match text, including documentation.** `cloud-metadata-endpoint`,
`sensitive-path-literal`, `package-install-command` and the credential-path rules match a
substring anywhere in a string literal or configuration value. A README-style config field
quoting `pip install` matches. Pair with `process.subprocess` evidence before treating a
package-install match as live.

**Environment classification is by variable NAME only.** A credential held in a variable
with an ordinary name is not classified as one; a non-secret variable whose name contains
`TOKEN` is over-classified. TrustLens records variable names and never their values.

**Known misses, stated rather than implied:**

- `dict(os.environ)` and `{**os.environ}` are not matched as enumeration.
- Indirect calls — `getattr(builtins, "ev" + "al")()` — are not matched by any rule.
- Interprocedural and cross-file flow is not performed by any check.
- Only Python is analysed for call rules. A loader written in another language is out of
  scope and appears in neither `analysed` nor `failed`.
- The `loader_scripts` builder-class scan re-parses files and silently skips ones that fail;
  those failures are recorded once by the caller rather than double-counted, so a file that
  fails to parse contributes to `scope.failed` but not to a second failure entry.

**Version-conditional findings.** `execution.loader_script` reports presence and explicitly
does not assert liveness: `datasets` honours loading scripts before 4.0.0 and raises
`RuntimeError` from 4.0.0 onward, and the consuming version is not visible in the artifact.
`execution.dynamic_import` from `auto_map` records reachability, not activation, since
`transformers` executes it only when the consumer passes `trust_remote_code=True`.

## Detector inventory

| Detector | Capability | Escalated | Suppressed in known template fields |
|---|---|---|---|
| `ssti-gadget` | `template.expression_evaluation` | yes | no |
| `resolver-eval` | `template.expression_evaluation` | yes | no |
| `yaml-python-tag` | `execution.deserialization` | yes | no |
| `jinja-block` | `template.injection_surface` | no | yes |
| `jinja-expression` | `template.injection_surface` | no | yes |
| `resolver-env` | `template.injection_surface` | no | no |
| `shell-substitution` | `template.injection_surface` | no | no |

"Escalated" means the construct has essentially no benign use inside a configuration value.
It changes the stated confidence basis, not the status.

## Controls

`tests/scanner/test_template_injection.py`, against `tests/fixtures/template_injection/`:

| Fixture | Role | Expected |
|---|---|---|
| `clean_dataset` | negative control | all clean |
| `clean_chat_template` | false-positive control (real HF chat template) | all clean, suppressions recorded |
| `fp_lookalikes` | false-positive control (prose backticks, braces, the word "Jinja") | all clean, zero matches |
| `unsafe_resolver_eval` | positive control | surface + evaluation `FOUND` |
| `unsafe_ssti_gadget` | positive control | evaluation `FOUND` via gadget inside a suppressed field |
| `unsafe_yaml_tag` | positive control | deserialization `FOUND` |
| `unsafe_flow` | positive control | evaluation `FOUND` via dataflow |
| `partial_config` | PARTIAL control | all `PARTIAL`, naming the undecodable file |

A test asserts the fixture directories on disk and the expectation table are the same set,
so a fixture cannot sit in the repository without being asserted on.

Synthetic unsafe fixtures contain no real malware, use no live credentials, make no external
network contact, and are labelled in-file as TrustLens fixtures.

## Defects this control set has already caught

Recorded because a control set that has never caught anything is not evidence that it works.

1. **False negative on a planted case.** `!!python/object/apply:os.system` resolves to the
   tag `tag:yaml.org,2002:python/object/apply:os.system` — it carries the *standard* YAML
   prefix. The first implementation tested for a non-standard prefix and therefore missed
   the single most dangerous construct in YAML. Fixed by allowlisting the standard YAML
   types instead. This is exactly the shape of CVE-2025-10157 (exact-match blocklist evaded
   by a submodule) recorded in `GROUNDING.md`.
2. **False positive on prose.** `` `--verbose` `` in a description field matched shell
   substitution. Detector narrowed to `$(...)`.
3. **Duplicate findings.** The same flow was reported once at module scope and once at
   function scope. Deduplicated.
4. **Corrupted resolved names in evidence.** `import urllib.request` was mapped as
   `urllib -> urllib.request`, rewriting `urllib.request.urlopen` into
   `urllib.request.request.urlopen` in the recorded evidence. Detection still worked, so
   only reading the evidence caught it. A plain `import a.b` binds `a`, not `a.b`.
5. **A detection that produced no finding.** `env.credential_pattern_read` is derived at
   match time from the subscript key rather than declared by a static rule, and the
   capability list was built from the static rules alone — so the hit existed and no
   finding was emitted for it. Silently dropped detections are worse than misses, because
   the tool reports a clean result for something it did detect.
6. **A fixture asserting a capability nothing scanned.** `unsafe_cloud/deploy.yaml` carried
   a metadata endpoint in YAML while the string rules ran only over Python, so the fixture
   passed on the strength of an unrelated match in a `.py` file. String rules now run over
   configuration values as well, which is the likelier location for a hardcoded endpoint.

## Bundled example repositories and stored control-run evidence

`examples/repos/` ships six examples; `examples/control_runs/` stores the evidence record
the full scanner actually produced for each, regenerable and byte-identical.

| Example | Role | Result |
|---|---|---|
| `clean_tabular` | negative control | 0 findings, scope complete |
| `clean_jsonl` | negative control (includes a benign helper module) | 0 findings |
| `clean_imagefolder` | negative control (no code at all) | 0 findings |
| `unsafe_dataset_loader` | positive control — presented as passive data | 9 capabilities `FOUND` |
| `unsafe_model_repo` | positive control — `auto_map` remote code | 8 capabilities `FOUND` |
| `partial_encoding` | PARTIAL control | `legacy.yaml` undecodable; scope incomplete |

**Negative controls are non-vacuous at the full-scanner level.** The unsafe examples are
committed inert — every dangerous call sits inside a function — so the controls
*materialise* a live variant in a temp directory, arming it with an import-time payload, a
malicious pickle and an unsafe YAML tag pointed at canary paths. The suite then
**detonates** that variant to prove the payloads fire, and only then scans a fresh copy
with `subprocess`, `os.system` and `socket` replaced by raising objects. No canary appears,
nothing enters `sys.modules`, and the armed YAML tag is still detected — so inertness was
not achieved by declining to look.

Stored control-run evidence is compared against a fresh scan on every test run, so it
cannot silently go stale.

## Rule-target coverage — the audit run one level below rule liveness

`test_rule_liveness.py` proves each rule fires on *a* trigger. That left each rule's other
targets unproven: a measurement found **60 of 212 targets (28%)** had ever been matched. A
mistyped target string would sit in the rule set forever, matching nothing, and producing
output identical to a target that was checked and absent.

`tests/scanner/test_target_coverage.py` generates a trigger per target from the target's own
shape and asserts the rule fires. Coverage is now **178 of 201 targets (88%)** by generation,
with 23 excluded and a stated reason for each — all of them bare method or builtin names
(`extractall`, `bind`, `eval`) that cannot be expressed as an import and are exercised
through the hand-written liveness triggers instead. A test asserts the exclusion list stays
below 20% so the check cannot be hollowed out, and another asserts no exclusion names a
target that no longer exists.

All 210 generated targets matched on the first run: no mistyped targets were found. The
security-relevant outcome is that the metadata-endpoint rule's IPv6, GCP, ECS, Alibaba and
Oracle forms — which the brief asks for explicitly and which had **never** been exercised —
now each have a test.

**One level further down is deliberately not covered.** Within a single target, the
interaction between a predicate and an unusual call shape (a target invoked through
`functools.partial`, a keyword passed via `**kwargs`) is untested. That is stated here as a
deferral rather than left silent; the blind spots are already recorded per rule.

## Exit codes are part of the evidence

The CLI's exit code is what a pipeline reads instead of the report, so it carries the same
discipline: `0` clean, `1` findings, **`2` analysis did not complete**, `3` usage error. An
incomplete scan deliberately does not exit `0`, because a caller that treats it as clean
reproduces the false-clean failure at the process boundary, where none of the in-process
guards can see it.

## External analysers: decided 2026-07-22

External analysers stay **out of the scan path**. Each becomes its own command emitting its
own record, composed through `input_records[]` — the same separation already applied to
acquisition. `scan()` therefore keeps its no-subprocess guarantee **absolute and unchanged**,
and the inertness harness needs no modification.

An analyser is **optional**. Its absence makes the capabilities it would have covered
`UNSUPPORTED` with the reason recorded, preserving the clean-clone property: the evidence
model verifies with no analysis toolchain installed. Coverage therefore varies between runs,
and comparing two records of the same artifact must account for that.

Disagreement between two analysers is recorded as a contradiction rather than reconciled,
consistent with `reconciled: false` being pinned in machine-produced records.

This decision governs Phase 2 as well: the upstream Kubernetes RBAC authorizer is reusable
but is Go, so it becomes a separate command rather than an in-process dependency.

## Phase 2 status (2026-07-22)

Built and tested: `trustlens map-credentials` (pure Python, inert, core path), the
Terraform and Kubernetes RBAC ingesters, the cross-domain K8s→IAM join via the IRSA `:sub`
condition, and the optional `trustlens rbac` Go helper wrapping the upstream Kubernetes
authorizer.

Not built, and carried forward as named items in **`docs/DEFERRED.md`** (D1 IAM condition
evaluation, D2 `policy_sentry`, D3 network-policy reachability, D4 external analysers) —
each with its reason, its candidate phase, and what stands in its place. They are deferred,
not forgotten, and the register exists so the two stay distinguishable.

**Phase 2 is partial-but-closed against its stated scope.** The mapper, both ingesters, the
cross-domain join and the optional RBAC helper are built, tested and clean-clone verified.
One honest cost is recorded in D3: because network-policy reachability is unbuilt, the
Phase 0 illustrative contradiction — description says metadata access is blocked while a
NetworkPolicy permits link-local — is not yet detectable end to end.
