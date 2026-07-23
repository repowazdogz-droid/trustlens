"""Template and expression injection surfaces in ML dataset/model configuration.

This check is authored from scratch rather than delegated to an existing engine, because
`GROUNDING.md` §4.10 established that no reusable one exists: Bandit's `B701`-`B704` are
autoescape and XSS checks rather than server-side template injection checks, Semgrep's
registry SSTI rules cannot be shipped under the Semgrep Rules License, and no surveyed
engine documents a check for expression evaluation in configuration reaching a sink.

It is also the vector Hugging Face named as one of two initial vectors in the July 2026
disclosure ("a template-injection in a dataset configuration"), which is why it is built
first.

## What the check does

Two halves, kept separate because they support different claims.

**Half A — the surface.** Configuration values are scanned for template and expression
syntax. A match establishes that an expression-bearing value exists at a location. It does
not establish that anything renders it.

**Half B — the flow.** Python source is scanned for a value loaded from configuration
reaching a rendering or evaluating sink **within the same function**. A match is stronger:
something in this repository does render configuration. Interprocedural and cross-file
flows are out of scope and are not claimed — Semgrep CE is intra-procedural too, so nothing
in Phase 1 claims wider.

## The false-positive that would have made this check useless

Hugging Face `chat_template` fields legitimately contain Jinja2, and they are everywhere.
Flagging their presence would bury every real finding. Verified from the `transformers`
source (`utils/chat_template_utils.py`): chat templates are compiled with
`ImmutableSandboxedEnvironment` from `jinja2.sandbox`. So conventional Jinja syntax in a
known template field is expected and is suppressed — while sandbox-**escape gadgets** in
that same field still fire, because gadget chains exist precisely to defeat that sandbox.

Suppressions are counted and reported in the finding rather than dropped silently.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from ...evidence import make_evidence, make_finding, make_scope
from ..config_parse import ParsedConfig, ScalarValue, iter_config_files, parse_config

RULE_ID = "template-injection-config"
RULE_VERSION = "0.1.0"

#: Config keys conventionally holding a template that the ecosystem renders on purpose.
#: Presence of template syntax here is not a finding; an escalated construct still is.
KNOWN_TEMPLATE_FIELDS = frozenset({"chat_template"})


@dataclass(frozen=True)
class Detector:
    rule_id: str
    pattern: re.Pattern[str]
    escalated: bool
    matches: str
    benign_lookalike: str
    suppressible_in_template_field: bool


DETECTORS: tuple[Detector, ...] = (
    Detector(
        rule_id="ssti-gadget",
        pattern=re.compile(
            r"__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__"
            r"|__init__\s*\.\s*__globals__|_TemplateReference__context"
            r"|\blipsum\b|\bcycler\b|\bjoiner\b|\bself\s*\.\s*_"
        ),
        escalated=True,
        matches=(
            "Python introspection gadgets used to escape a Jinja sandbox by walking from an "
            "ordinary object to __builtins__"
        ),
        benign_lookalike=(
            "Documentation or a test fixture quoting a gadget chain. The construct itself "
            "has no legitimate use inside a configuration value."
        ),
        suppressible_in_template_field=False,
    ),
    Detector(
        rule_id="resolver-eval",
        pattern=re.compile(r"\$\{\s*(eval|python|exec|call)\s*:", re.IGNORECASE),
        escalated=True,
        matches=(
            "An OmegaConf/Hydra-style resolver that evaluates an arbitrary expression at "
            "config-resolution time"
        ),
        benign_lookalike=(
            "A project may register a custom resolver named 'call' for benign purposes; the "
            "expression it evaluates is still attacker-controlled if the config is."
        ),
        suppressible_in_template_field=False,
    ),
    Detector(
        rule_id="yaml-python-tag",
        # Applied to tag sightings rather than to scalar text.
        pattern=re.compile(r"python/(object|name|module)"),
        escalated=True,
        matches="A YAML tag that constructs an arbitrary Python object on unsafe load",
        benign_lookalike=(
            "None in a distributed artifact. Some internal tooling serialises objects this "
            "way, which is itself the hazard."
        ),
        suppressible_in_template_field=False,
    ),
    Detector(
        rule_id="jinja-block",
        pattern=re.compile(r"\{%-?.+?-?%\}", re.DOTALL),
        escalated=False,
        matches="A Jinja2 statement block",
        benign_lookalike=(
            "Chat templates, prompt templates and documentation examples. Extremely common "
            "and usually benign."
        ),
        suppressible_in_template_field=True,
    ),
    Detector(
        rule_id="jinja-expression",
        pattern=re.compile(r"\{\{.+?\}\}", re.DOTALL),
        escalated=False,
        matches="A Jinja2 expression",
        benign_lookalike="Same as jinja-block; also common in README-style config comments.",
        suppressible_in_template_field=True,
    ),
    Detector(
        rule_id="resolver-env",
        pattern=re.compile(r"\$\{\s*(oc\.env|env)\s*:", re.IGNORECASE),
        escalated=False,
        matches="A resolver that reads a process environment variable during config resolution",
        benign_lookalike=(
            "Legitimate and idiomatic in Hydra configs. Reported because it moves environment "
            "values into config-rendered strings, not because it is itself unsafe."
        ),
        suppressible_in_template_field=False,
    ),
    Detector(
        rule_id="shell-substitution",
        # `$(...)` only. Backtick substitution was in the first version and was removed
        # after the false-positive control caught it matching "`--verbose`" in a prose
        # description field: inline code in prose is far more common in ML config than
        # backtick shell substitution, so the pattern cost more soundness than it bought
        # completeness. A backtick-substitution payload is a known miss, recorded below.
        pattern=re.compile(r"\$\([^)]{1,200}\)"),
        escalated=False,
        matches="Shell command substitution syntax `$(...)` in a configuration value",
        benign_lookalike=(
            "Make-style variable syntax in a build-ish config field. Less common than the "
            "backtick prose case that this detector no longer matches."
        ),
        suppressible_in_template_field=False,
    ),
)

#: Detectors keyed by rule id, for the YAML-tag path which does not scan scalar text.
_BY_ID = {d.rule_id: d for d in DETECTORS}


@dataclass
class Match:
    detector: Detector
    path: str
    pointer: str
    line: int | None
    excerpt: str


@dataclass
class Suppression:
    path: str
    pointer: str
    rule_id: str
    reason: str


# --------------------------------------------------------------------------- Half A

def _is_known_template_field(pointer: str) -> bool:
    return any(seg in KNOWN_TEMPLATE_FIELDS for seg in pointer.split("/"))


def scan_value(cfg_path: str, scalar: ScalarValue) -> tuple[list[Match], list[Suppression]]:
    matches: list[Match] = []
    suppressions: list[Suppression] = []
    in_template_field = _is_known_template_field(scalar.pointer)

    for det in DETECTORS:
        if det.rule_id == "yaml-python-tag":
            continue  # handled from tag sightings, not from scalar text
        found = det.pattern.search(scalar.value)
        if not found:
            continue
        if in_template_field and det.suppressible_in_template_field:
            suppressions.append(
                Suppression(
                    path=cfg_path,
                    pointer=scalar.pointer,
                    rule_id=det.rule_id,
                    reason=(
                        "conventional template syntax inside a known template field; "
                        "transformers renders chat templates in an ImmutableSandboxedEnvironment"
                    ),
                )
            )
            continue
        # Show the match inside a window of its surrounding value, so a reader can judge
        # it without opening the file. A bare match like 'cycler' is not reviewable.
        lo = max(0, found.start() - 40)
        hi = min(len(scalar.value), found.end() + 40)
        excerpt = ("…" if lo else "") + scalar.value[lo:hi] + ("…" if hi < len(scalar.value) else "")
        matches.append(
            Match(
                detector=det,
                path=cfg_path,
                pointer=scalar.pointer,
                line=scalar.line,
                excerpt=excerpt[:200],
            )
        )
    return matches, suppressions


def scan_config(parsed: ParsedConfig) -> tuple[list[Match], list[Suppression]]:
    matches: list[Match] = []
    suppressions: list[Suppression] = []
    for scalar in parsed.scalars:
        m, s = scan_value(parsed.path, scalar)
        matches += m
        suppressions += s
    for tag in parsed.dangerous_tags:
        matches.append(
            Match(
                detector=_BY_ID["yaml-python-tag"],
                path=parsed.path,
                pointer=tag.pointer,
                line=tag.line,
                excerpt=tag.tag[:200],
            )
        )
    return matches, suppressions


# --------------------------------------------------------------------------- Half B

CONFIG_LOADERS = frozenset(
    {
        "yaml.load",
        "yaml.safe_load",
        "yaml.full_load",
        "yaml.unsafe_load",
        "json.load",
        "json.loads",
        "tomllib.load",
        "tomllib.loads",
        "toml.load",
        "OmegaConf.load",
        "OmegaConf.create",
        "AutoConfig.from_pretrained",
        "AutoTokenizer.from_pretrained",
    }
)

RENDER_SINKS = frozenset(
    {"Template", "jinja2.Template", "from_string", "render_template_string", "render"}
)

EVAL_SINKS = frozenset({"eval", "exec", "compile"})


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _root_name(node: ast.AST) -> str:
    """The base identifier of an expression, so cfg['a'].b resolves to cfg."""
    while True:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            node = node.value
            continue
        if isinstance(node, ast.Call):
            node = node.func
            continue
        return ""


@dataclass
class Flow:
    path: str
    line: int
    sink: str
    source_name: str
    kind: str = field(default="render")


def find_config_to_sink_flows(source: str, rel_path: str) -> list[Flow]:
    """Intra-function flows from a configuration load to a render or eval sink.

    Deliberately narrow. A name bound from a config loader that later appears in a sink
    call *in the same function scope* is a flow. Anything wider is not claimed, and callers
    must not upgrade a co-occurrence into a flow.
    """
    tree = ast.parse(source)
    flows: list[Flow] = []

    scopes: list[ast.AST] = [tree]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append(node)

    for scope in scopes:
        tainted: set[str] = set()
        body = scope.body if hasattr(scope, "body") else []

        # Pass 1 — names bound from a configuration loader in this scope.
        for stmt in body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Call):
                    if _dotted(sub.value.func) in CONFIG_LOADERS:
                        for target in sub.targets:
                            name = _root_name(target)
                            if name:
                                tainted.add(name)
        if not tainted:
            continue

        # Pass 2 — sink calls in this scope consuming a tainted name.
        for stmt in body:
            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue
                callee = _dotted(sub.func)
                short = callee.rsplit(".", 1)[-1]
                if short in RENDER_SINKS:
                    kind = "render"
                elif short in EVAL_SINKS or callee in EVAL_SINKS:
                    kind = "eval"
                else:
                    continue
                for arg in list(sub.args) + [kw.value for kw in sub.keywords]:
                    if _root_name(arg) in tainted:
                        flows.append(
                            Flow(
                                path=rel_path,
                                line=sub.lineno,
                                sink=callee or short,
                                source_name=_root_name(arg),
                                kind=kind,
                            )
                        )
                        break

    # Module scope and function scope both see statements inside functions, so the same
    # flow can be recorded twice. Deduplicate on the identity of the flow itself.
    seen: set[tuple] = set()
    unique: list[Flow] = []
    for f in flows:
        key = (f.path, f.line, f.sink, f.source_name, f.kind)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# --------------------------------------------------------------------------- emission

@dataclass
class CheckResult:
    findings: list[dict]
    scope: dict
    matches: list[Match]
    suppressions: list[Suppression]
    flows: list[Flow]


def _evidence_for(m: Match) -> dict:
    return make_evidence(
        kind="config_key",
        path=m.path,
        line=m.line,
        pointer=m.pointer,
        excerpt=m.excerpt,
        detail=f"detector={m.detector.rule_id}",
    )


def run(
    root: Path,
    *,
    excluded_dirs: set[str] | None = None,
    component: str = "scanner",
) -> CheckResult:
    """Run the template-injection check over a repository root."""
    excluded_dirs = excluded_dirs or {"vendor", ".git", "node_modules"}

    parsed: list[ParsedConfig] = []
    for path in iter_config_files(root, excluded=excluded_dirs):
        parsed.append(parse_config(path, str(path.relative_to(root))))

    analysed = [p.path for p in parsed if p.ok]
    failed = [p.failed_item for p in parsed if not p.ok]
    excluded = [
        {
            "path": f"{d}/",
            "reason": "default policy exclusion for vendored or metadata directories",
            "kind": "policy_exclusion",
        }
        for d in sorted(excluded_dirs)
        if (root / d).exists()
    ]

    matches: list[Match] = []
    suppressions: list[Suppression] = []
    for p in parsed:
        if not p.ok:
            continue
        m, s = scan_config(p)
        matches += m
        suppressions += s

    # Half B over Python files. Parse failures here are recorded against the same scope.
    flows: list[Flow] = []
    py_analysed: list[str] = []
    for py in sorted(root.rglob("*.py")):
        if any(part in excluded_dirs for part in py.parts):
            continue
        rel = str(py.relative_to(root))
        try:
            src = py.read_text(encoding="utf-8-sig")
        except (UnicodeDecodeError, OSError) as exc:
            failed.append(
                {"path": rel, "reason": f"{type(exc).__name__}: {exc}", "kind": "decode_error"}
            )
            continue
        try:
            flows += find_config_to_sink_flows(src, rel)
        except SyntaxError as exc:
            failed.append(
                {
                    "path": rel,
                    "reason": f"SyntaxError: {exc.msg} (line {exc.lineno})",
                    "kind": "parse_error",
                }
            )
            continue
        py_analysed.append(rel)

    analysed_all = sorted(analysed + py_analysed)
    scope = make_scope(
        analysed=analysed_all,
        languages=["yaml", "json", "toml", "python"],
        excluded=excluded,
        failed=failed,
    )

    # Detector inventories per capability, so a clean result can state what was evaluated
    # rather than only which files were read. A capability reporting clean with no stated
    # detector count is indistinguishable from one that has no detectors at all.
    surface_detectors = [
        d for d in DETECTORS if not d.escalated and d.rule_id != "yaml-python-tag"
    ]
    eval_detectors = [d for d in DETECTORS if d.escalated and d.rule_id != "yaml-python-tag"]
    tag_detectors = [d for d in DETECTORS if d.rule_id == "yaml-python-tag"]

    surface = [m for m in matches if not m.detector.escalated]
    escalated = [m for m in matches if m.detector.escalated and m.detector.rule_id != "yaml-python-tag"]
    yaml_tags = [m for m in matches if m.detector.rule_id == "yaml-python-tag"]

    findings: list[dict] = []
    suppressed_note = (
        f" {len(suppressions)} conventional-template match(es) were suppressed inside known "
        f"template fields and are not counted here."
        if suppressions
        else ""
    )

    def _status(hits: list) -> str:
        if hits:
            return "FOUND"
        return "PARTIAL" if failed else "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

    common_limits = [
        "A surface match establishes that an expression-bearing value exists; it does not "
        "establish that anything renders or evaluates it.",
        "Detection is syntactic. An expression assembled at runtime from fragments would "
        "not be matched.",
        "Only YAML, JSON and TOML configuration is analysed. Other configuration formats "
        "are out of scope for this check.",
    ]

    # --- template.injection_surface
    findings.append(
        make_finding(
            capability="template.injection_surface",
            status=_status(surface),
            detection_method="static_ast",
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            source_component=component,
            scope=scope,
            evidence=[_evidence_for(m) for m in surface],
            confidence_basis=(
                f"{len(surface)} configuration value(s) matched conventional template or "
                f"interpolation syntax across {len(analysed)} parsed configuration file(s)."
                + suppressed_note
            )
            if surface
            else (
                f"None of the {len(surface_detectors)} surface detector(s) matched in "
                f"{len(analysed)} parsed configuration file(s)." + suppressed_note
            ),
            limitations=common_limits
            + [
                "Conventional template syntax is common and usually benign; this finding is "
                "a surface inventory, not an indication of compromise.",
            ],
        )
    )

    # --- template.expression_evaluation
    eval_evidence = [_evidence_for(m) for m in escalated]
    for f in flows:
        eval_evidence.append(
            make_evidence(
                kind="file_line",
                path=f.path,
                line=f.line,
                excerpt=f"{f.sink}(... {f.source_name} ...)",
                detail=f"config-loaded value reaches a {f.kind} sink in the same function",
            )
        )
    eval_hits = escalated + flows
    findings.append(
        make_finding(
            capability="template.expression_evaluation",
            status=_status(eval_hits),
            detection_method="static_ast_dataflow" if flows else "static_ast",
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            source_component=component,
            scope=scope,
            evidence=eval_evidence,
            confidence_basis=(
                f"{len(escalated)} configuration value(s) contained a construct with no "
                f"benign use in configuration (sandbox-escape gadget or expression-evaluating "
                f"resolver), and {len(flows)} intra-function flow(s) from a configuration "
                f"load to a render or eval sink were found."
            )
            if eval_hits
            else (
                f"None of the {len(eval_detectors)} expression-evaluating detector(s) matched, "
                f"and no intra-function configuration-to-sink flow was found, across "
                f"{len(analysed_all)} analysed file(s)."
            ),
            limitations=common_limits
            + [
                "Flow analysis is intra-function only. A configuration value passed between "
                "functions or modules before reaching a sink is not detected.",
                "A detected flow does not establish that the sink is reached at runtime.",
            ],
        )
    )

    # --- execution.deserialization via YAML object tags
    findings.append(
        make_finding(
            capability="execution.deserialization",
            status=_status(yaml_tags),
            detection_method="static_ast",
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            source_component=component,
            scope=scope,
            evidence=[_evidence_for(m) for m in yaml_tags],
            confidence_basis=(
                f"{len(yaml_tags)} YAML tag(s) constructing arbitrary Python objects were "
                "found. TrustLens recorded these tags without constructing them."
            )
            if yaml_tags
            else (
                f"The {len(tag_detectors)} YAML object-tag detector(s) found no "
                f"arbitrary-object tags in {len(analysed)} parsed configuration file(s)."
            ),
            limitations=common_limits
            + [
                "Establishes that the tag is present, not that the document is ever loaded "
                "with an unsafe loader. Under yaml.safe_load the tag raises instead.",
            ],
        )
    )

    return CheckResult(
        findings=findings,
        scope=scope,
        matches=matches,
        suppressions=suppressions,
        flows=flows,
    )
