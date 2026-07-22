# Scanner — claims and bounds

**Status: Phase 1 in progress.** One check family of the ten in scope is implemented:
template and expression injection in configuration. The other nine are not built, and this
file will grow with them rather than being written in advance.

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
