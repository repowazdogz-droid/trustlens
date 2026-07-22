"""Rule-driven static checks over Python source.

One tree walk, many independent rules. Each rule states its own invariant and its own
blind spot, and findings are never collapsed into a score — the brief requires each check
to remain separately visible, and a reader must be able to see which rule fired and why.

Rules resolve through the file's import alias map, so `import subprocess as sp` followed by
`sp.Popen(..., shell=True)` matches. Renaming an import would otherwise be a one-line
bypass of every rule in this file, and the planted-case controls exercise exactly that.

Families implemented here, from the Phase 1 scope:

* 2 — dynamic execution
* 3 — process and shell invocation
* 6 — dangerous deserialization

Remaining families are added as further rule sets against the same engine.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ...evidence import make_evidence, make_finding, make_scope
from ..pysource import (
    PythonFile,
    call_names,
    dotted_name,
    is_literal_false,
    is_literal_true,
    keyword_of,
    load_python_files,
    resolve,
)

RULE_VERSION = "0.1.0"

Predicate = Callable[[ast.Call, dict], bool]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    family: str
    capability: str
    targets: frozenset[str]
    what: str
    blind_spot: str
    escalated: bool = False
    predicate: Predicate | None = None
    #: When set, the rule only fires if the predicate is TRUE; otherwise a call to a
    #: matching target with the predicate false is explicitly not a finding.
    predicate_note: str = ""


# --------------------------------------------------------------------------- predicates

def _shell_true(call: ast.Call, aliases: dict) -> bool:
    return is_literal_true(keyword_of(call, "shell"))


def _unsafe_yaml_loader(call: ast.Call, aliases: dict) -> bool:
    """yaml.load is unsafe unless an explicitly safe Loader is supplied."""
    loader = keyword_of(call, "Loader")
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    if loader is None:
        return True  # no Loader at all: the historically unsafe default
    name = resolve(dotted_name(loader), aliases).rsplit(".", 1)[-1]
    return name not in {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


def _weights_only_false(call: ast.Call, aliases: dict) -> bool:
    """Only an explicit weights_only=False is flagged.

    PyTorch changed the default to True, so an omitted argument is the safe modern case and
    flagging it would produce noise on every ordinary torch.load in the ecosystem. An
    artifact pinned to an old torch is a version question this check cannot see, and that
    is recorded as a gap in CLAIMS.md rather than guessed at.
    """
    return is_literal_false(keyword_of(call, "weights_only"))


def _allow_pickle_true(call: ast.Call, aliases: dict) -> bool:
    return is_literal_true(keyword_of(call, "allow_pickle"))


def _safe_mode_false(call: ast.Call, aliases: dict) -> bool:
    return is_literal_false(keyword_of(call, "safe_mode"))


# ------------------------------------------------------------------------------- rules

RULES: tuple[Rule, ...] = (
    # ---------------------------------------------------------------- family 2
    Rule(
        rule_id="exec-eval-builtin",
        family="dynamic_execution",
        capability="execution.dynamic_eval",
        targets=frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}),
        escalated=True,
        what="A builtin that executes or compiles code supplied at runtime",
        blind_spot=(
            "A call reached indirectly, e.g. through getattr(builtins, 'ev'+'al'), is not "
            "matched. Only a syntactically visible callee is."
        ),
    ),
    Rule(
        rule_id="dynamic-import",
        family="dynamic_execution",
        capability="execution.dynamic_import",
        targets=frozenset(
            {"__import__", "builtins.__import__", "importlib.import_module",
             "importlib.__import__", "importlib.util.spec_from_file_location"}
        ),
        what="A module imported by a name computed at runtime",
        blind_spot=(
            "The imported module name is not resolved. A constant import here is "
            "indistinguishable from an attacker-controlled one without dataflow."
        ),
    ),
    Rule(
        rule_id="code-object-construction",
        family="dynamic_execution",
        capability="execution.dynamic_eval",
        targets=frozenset({"types.FunctionType", "types.CodeType"}),
        escalated=True,
        what="Direct construction of a function or code object",
        blind_spot="Legitimate in metaprogramming libraries; rare in dataset or model code.",
    ),
    # ---------------------------------------------------------------- family 3
    Rule(
        rule_id="subprocess-invocation",
        family="process_shell",
        capability="process.subprocess",
        targets=frozenset(
            {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
             "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"}
        ),
        what="A child process is created",
        blind_spot=(
            "Does not establish that the command is attacker-controlled, nor that the call "
            "is reached at runtime."
        ),
    ),
    Rule(
        rule_id="subprocess-shell-true",
        family="process_shell",
        capability="process.shell",
        targets=frozenset(
            {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
             "subprocess.check_output"}
        ),
        escalated=True,
        predicate=_shell_true,
        predicate_note="only when shell=True is written literally",
        what="A child process is created through a shell, so the argument is a command line",
        blind_spot=(
            "shell=True passed via a variable or **kwargs is not matched; only a literal "
            "True is. A shell-less call that invokes /bin/sh explicitly is caught by the "
            "shell-binary rule instead."
        ),
    ),
    Rule(
        rule_id="os-shell-exec",
        family="process_shell",
        capability="process.shell",
        targets=frozenset({"os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
                           "os.spawnv", "os.spawnve", "pty.spawn"}),
        escalated=True,
        what="A shell or process is executed through the os module",
        blind_spot="Does not resolve the command string.",
    ),
    # ---------------------------------------------------------------- family 6
    Rule(
        rule_id="pickle-load",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset(
            {"pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
             "_pickle.load", "_pickle.loads", "dill.load", "dill.loads",
             "cloudpickle.load", "cloudpickle.loads", "joblib.load",
             "pandas.read_pickle", "pd.read_pickle", "shelve.open"}
        ),
        escalated=True,
        what="Deserialization that can construct arbitrary objects and execute code on load",
        blind_spot=(
            "Establishes the call site, not the trustworthiness of the data it reads. A "
            "pickle load of a file the repository itself ships is still arbitrary code."
        ),
    ),
    Rule(
        rule_id="marshal-load",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"marshal.load", "marshal.loads"}),
        escalated=True,
        what="marshal deserialization, which accepts code objects",
        blind_spot="Rare outside interpreter internals; presence is itself unusual.",
    ),
    Rule(
        rule_id="yaml-unsafe-load",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"yaml.load"}),
        escalated=True,
        predicate=_unsafe_yaml_loader,
        predicate_note="only when no Loader, or a non-safe Loader, is supplied",
        what="yaml.load without a safe Loader, which can construct arbitrary Python objects",
        blind_spot=(
            "A Loader passed through a variable is treated as unsafe, which may over-report. "
            "yaml.safe_load is never flagged."
        ),
    ),
    Rule(
        rule_id="yaml-unsafe-api",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"yaml.unsafe_load", "yaml.full_load", "yaml.unsafe_load_all", "yaml.full_load_all"}),
        escalated=True,
        what="A PyYAML entry point that permits arbitrary object construction",
        blind_spot="full_load is narrower than unsafe_load but still constructs Python objects.",
    ),
    Rule(
        rule_id="torch-load-weights-only-false",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"torch.load", "torch.serialization.load"}),
        escalated=True,
        predicate=_weights_only_false,
        predicate_note="only when weights_only=False is written literally",
        what="torch.load with the pickle guard explicitly disabled",
        blind_spot=(
            "An omitted weights_only is NOT flagged, because current PyTorch defaults it to "
            "True. An artifact pinned to an older torch would be unsafe and is not detected."
        ),
    ),
    Rule(
        rule_id="torch-safe-globals-widening",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"torch.serialization.add_safe_globals", "torch.load.add_safe_globals",
                           "add_safe_globals"}),
        what="The torch.load allowlist is widened, re-admitting types the guard excluded",
        blind_spot="Widening may be entirely legitimate; it is reported as surface, not fault.",
    ),
    Rule(
        rule_id="numpy-allow-pickle",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"numpy.load", "np.load"}),
        escalated=True,
        predicate=_allow_pickle_true,
        predicate_note="only when allow_pickle=True is written literally",
        what="numpy.load with pickle enabled, which deserializes arbitrary objects",
        blind_spot="allow_pickle defaults to False and an omitted argument is not flagged.",
    ),
    Rule(
        rule_id="keras-safe-mode-false",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"keras.models.load_model", "keras.saving.load_model",
                           "tensorflow.keras.models.load_model", "load_model"}),
        escalated=True,
        predicate=_safe_mode_false,
        predicate_note="only when safe_mode=False is written literally",
        what="Keras model loading with unsafe lambda deserialization enabled",
        blind_spot=(
            "safe_mode defaults to True in Keras v3 and an omitted argument is not flagged. "
            "Lambda layers inside a .keras archive are a separate, unimplemented check."
        ),
    ),
)

FAMILIES = tuple(dict.fromkeys(r.family for r in RULES))


# ------------------------------------------------------------------------------- engine

@dataclass
class Hit:
    rule: Rule
    path: str
    line: int
    matched_name: str
    excerpt: str


def scan_file(pf: PythonFile, rules: tuple[Rule, ...] = RULES) -> list[Hit]:
    """Match every rule against one parsed file. Never executes the file."""
    if not pf.ok or pf.tree is None:
        return []
    hits: list[Hit] = []
    source_lines = (pf.source or "").splitlines()

    for node in ast.walk(pf.tree):
        if not isinstance(node, ast.Call):
            continue
        names = call_names(node, pf.aliases)
        if not names:
            continue
        for rule in rules:
            if not (names & rule.targets):
                continue
            if rule.predicate is not None and not rule.predicate(node, pf.aliases):
                continue
            line = getattr(node, "lineno", 0)
            raw = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else ""
            resolved = resolve(dotted_name(node.func), pf.aliases)
            hits.append(
                Hit(
                    rule=rule,
                    path=pf.path,
                    line=line,
                    matched_name=resolved or dotted_name(node.func),
                    excerpt=raw[:200],
                )
            )
    return hits


@dataclass
class SurfaceResult:
    findings: list[dict]
    scope: dict
    hits: list[Hit]
    files: list[PythonFile]


def run(
    root: Path,
    *,
    excluded_dirs: set[str] | None = None,
    families: tuple[str, ...] | None = None,
    component: str = "scanner",
) -> SurfaceResult:
    """Run the Python-surface checks over a repository root."""
    excluded_dirs = excluded_dirs or {"vendor", ".git", "node_modules", "__pycache__"}
    rules = RULES if families is None else tuple(r for r in RULES if r.family in families)

    files = load_python_files(root, excluded_dirs)
    analysed = [f.path for f in files if f.ok]
    failed = [f.failed_item for f in files if not f.ok]
    excluded = [
        {
            "path": f"{d}/",
            "reason": "default policy exclusion for vendored, metadata or cache directories",
            "kind": "policy_exclusion",
        }
        for d in sorted(excluded_dirs)
        if (root / d).exists()
    ]

    hits: list[Hit] = []
    for pf in files:
        hits += scan_file(pf, rules)

    scope = make_scope(
        analysed=analysed,
        languages=["python"],
        excluded=excluded,
        failed=failed,
    )

    by_capability: dict[str, list[Hit]] = defaultdict(list)
    for h in hits:
        by_capability[h.rule.capability].append(h)

    capabilities = sorted({r.capability for r in rules})
    findings = []
    for capability in capabilities:
        cap_hits = by_capability.get(capability, [])
        if cap_hits:
            status = "FOUND"
        elif failed:
            status = "PARTIAL"
        else:
            status = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

        cap_rules = [r for r in rules if r.capability == capability]
        limitations = [
            "Establishes that the construct appears in parsed source; does not establish "
            "that it executes at runtime.",
            "Analysis is per-file and syntactic. A call assembled dynamically or reached "
            "through an indirection is not matched.",
        ] + sorted({r.blind_spot for r in cap_rules})

        rules_fired = sorted({h.rule.rule_id for h in cap_hits})
        basis = (
            f"{len(cap_hits)} call site(s) matched {len(rules_fired)} rule(s) "
            f"({', '.join(rules_fired)}) across {len(analysed)} parsed Python file(s). "
            "Import aliases were resolved before matching."
            if cap_hits
            else (
                f"No call site matched any of the {len(cap_rules)} rule(s) for this "
                f"capability across {len(analysed)} parsed Python file(s)."
            )
        )
        conditional = [r for r in cap_rules if r.predicate is not None]
        if conditional:
            basis += " Conditional rules fired only under their stated condition: " + "; ".join(
                f"{r.rule_id} ({r.predicate_note})" for r in conditional
            ) + "."

        findings.append(
            make_finding(
                capability=capability,
                status=status,
                detection_method="static_ast",
                rule_id=f"python-surface:{capability}",
                rule_version=RULE_VERSION,
                source_component=component,
                scope=scope,
                evidence=[
                    make_evidence(
                        kind="file_line",
                        path=h.path,
                        line=h.line,
                        excerpt=h.excerpt,
                        detail=f"rule={h.rule.rule_id} resolved={h.matched_name}",
                    )
                    for h in cap_hits
                ],
                confidence_basis=basis,
                limitations=limitations,
            )
        )

    return SurfaceResult(findings=findings, scope=scope, hits=hits, files=files)
