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

## External tools

**No external tool is currently wired into any `FOUND` or `NOT_FOUND_WITHIN_ANALYSED_SCOPE`
claim.** Every finding above comes from TrustLens's own analysis. Of the five surveyed
tools, only Bandit has been verified to distinguish "nothing found" from "could not read"
in machine-readable output (`docs/PHASE1_ENTRY_CONDITIONS.md`), so only Bandit is eligible;
its integration is not yet built. Semgrep, gitleaks, syft and osv-scanner remain excluded
from status claims until each is independently verified the same way.

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
- `archive-extraction` does **not** yet distinguish a Python 3.12+ `filter=`-constrained
  `extractall` from an unconstrained one, so it over-reports on modern, safe code.

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
