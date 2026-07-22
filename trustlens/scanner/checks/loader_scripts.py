"""Repository-shape checks: custom loader scripts and remote-code entry points.

This is check family 1, and Phase 0 grounding changed its shape. The brief scoped it as
"Hugging Face `datasets` custom loader scripts", but that vector is **version-gated**:
verified at the tags, `datasets` 3.6.0 honours loading scripts while 4.0.0 and later raise
`RuntimeError("Dataset scripts are no longer supported")` and ignore `trust_remote_code`.
The live equivalent moved to `transformers`, where `auto_map` in `config.json` points at
repository Python that `get_class_from_dynamic_module` executes — its own docstring says
"Calling this function will execute the code in the module file found locally or downloaded
from the Hub".

So the check is split:

* `execution.loader_script` — a dataset loading script is present. Reported with the
  version condition attached, because the same file is dangerous under a pinned old
  `datasets` and inert under a current one. TrustLens cannot see the consuming version from
  the artifact, and says so rather than guessing.
* `execution.dynamic_import` — an `auto_map` entry in `config.json` naming repository code.
  This is the live vector and is not version-gated.

Entry-point file criteria are taken from arXiv 2601.14163 §5.2, which grounds them in the
PyTorch Hub and `transformers` documentation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ...evidence import make_evidence, make_finding, make_scope
from ..config_parse import parse_json

RULE_ID = "loader-scripts"
RULE_VERSION = "0.1.0"

#: Files whose presence marks a repository as requiring custom code during loading.
#: From arXiv 2601.14163 §5.2.
ENTRY_POINT_FILES = frozenset({"tokenizer.py", "hubconf.py", "__init__.py"})
ENTRY_POINT_PREFIXES = ("modeling_", "tokenization_", "configuration_")

#: The version at which `datasets` removed loading-script support. Verified at the tags.
DATASETS_SCRIPTS_REMOVED_IN = "4.0.0"


@dataclass
class ShapeHit:
    rule_id: str
    capability: str
    path: str
    line: int | None
    detail: str
    excerpt: str


def _is_entry_point(name: str) -> bool:
    return name in ENTRY_POINT_FILES or name.startswith(ENTRY_POINT_PREFIXES)


def find_dataset_loader_scripts(root: Path, py_files: list[str]) -> list[ShapeHit]:
    """A dataset loading script is conventionally named after its repository directory."""
    hits: list[ShapeHit] = []
    repo_name = root.name
    for rel in py_files:
        p = Path(rel)
        if p.parent != Path(".") or p.suffix != ".py":
            continue
        if p.stem == repo_name:
            hits.append(
                ShapeHit(
                    rule_id="dataset-loader-script-by-name",
                    capability="execution.loader_script",
                    path=rel,
                    line=None,
                    detail=(
                        f"a top-level Python file named after the repository directory "
                        f"({repo_name}.py) is the dataset loading-script convention"
                    ),
                    excerpt=rel,
                )
            )
    return hits


def find_builder_classes(root: Path, py_files: list[str]) -> list[ShapeHit]:
    """A `datasets.GeneratorBasedBuilder` subclass is a loading script regardless of name."""
    import ast

    hits: list[ShapeHit] = []
    for rel in py_files:
        path = root / rel
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            continue  # scope failures are recorded by the caller, not double-counted here
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                name = ""
                if isinstance(base, ast.Attribute):
                    name = base.attr
                elif isinstance(base, ast.Name):
                    name = base.id
                if name in {"GeneratorBasedBuilder", "ArrowBasedBuilder", "DatasetBuilder",
                            "BeamBasedBuilder"}:
                    hits.append(
                        ShapeHit(
                            rule_id="dataset-builder-class",
                            capability="execution.loader_script",
                            path=rel,
                            line=node.lineno,
                            detail=f"class {node.name} subclasses {name}",
                            excerpt=f"class {node.name}({name})",
                        )
                    )
    return hits


def find_entry_points(py_files: list[str]) -> list[ShapeHit]:
    hits = []
    for rel in py_files:
        name = Path(rel).name
        if _is_entry_point(name):
            hits.append(
                ShapeHit(
                    rule_id="custom-code-entry-point",
                    capability="execution.loader_script",
                    path=rel,
                    line=None,
                    detail=(
                        "file name matches a documented custom-code entry point "
                        "(arXiv 2601.14163 §5.2)"
                    ),
                    excerpt=name,
                )
            )
    return hits


def find_auto_map(root: Path, config_files: list[str]) -> list[ShapeHit]:
    """`auto_map` in a model config points at repository code that transformers executes."""
    hits: list[ShapeHit] = []
    for rel in config_files:
        if Path(rel).name not in {"config.json", "tokenizer_config.json",
                                  "preprocessor_config.json", "processor_config.json"}:
            continue
        parsed = parse_json(root / rel, rel)
        if not parsed.ok:
            continue
        for scalar in parsed.scalars:
            if not scalar.pointer.startswith("/auto_map"):
                continue
            # Values look like "modeling_x.MyModel" or "repo--modeling_x.MyModel".
            module = scalar.value.split("--")[-1].split(".")[0]
            hits.append(
                ShapeHit(
                    rule_id="auto-map-remote-code",
                    capability="execution.dynamic_import",
                    path=rel,
                    line=scalar.line,
                    detail=(
                        f"auto_map entry {scalar.pointer} names repository module "
                        f"'{module}', which transformers executes when trust_remote_code "
                        "is enabled"
                    ),
                    excerpt=scalar.value[:200],
                )
            )
    return hits


def find_build_hooks(root: Path) -> list[ShapeHit]:
    hits = []
    for name in ("setup.py", "conftest.py"):
        if (root / name).is_file():
            hits.append(
                ShapeHit(
                    rule_id="build-time-executed-file",
                    capability="execution.build_hook",
                    path=name,
                    line=None,
                    detail=(
                        "setup.py executes during installation; conftest.py executes on "
                        "test collection. Both run before any explicit invocation."
                    ),
                    excerpt=name,
                )
            )
    return hits


@dataclass
class ShapeResult:
    findings: list[dict]
    scope: dict
    hits: list[ShapeHit]


def run(
    root: Path,
    *,
    excluded_dirs: set[str] | None = None,
    component: str = "scanner",
) -> ShapeResult:
    excluded_dirs = excluded_dirs or {"vendor", ".git", "node_modules", "__pycache__"}

    py_files, config_files, failed = [], [], []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in excluded_dirs for part in rel_parts):
            continue
        rel = str(p.relative_to(root))
        if p.suffix == ".py":
            try:
                p.read_text(encoding="utf-8")
                py_files.append(rel)
            except (UnicodeDecodeError, OSError) as exc:
                failed.append(
                    {"path": rel, "reason": f"{type(exc).__name__}: {exc}", "kind": "decode_error"}
                )
        elif p.suffix == ".json":
            config_files.append(rel)

    hits = (
        find_dataset_loader_scripts(root, py_files)
        + find_builder_classes(root, py_files)
        + find_entry_points(py_files)
        + find_auto_map(root, config_files)
        + find_build_hooks(root)
    )

    scope = make_scope(
        analysed=sorted(py_files + config_files),
        languages=["python", "json"],
        excluded=[
            {
                "path": f"{d}/",
                "reason": "default policy exclusion",
                "kind": "policy_exclusion",
            }
            for d in sorted(excluded_dirs)
            if (root / d).exists()
        ],
        failed=failed,
    )

    by_cap: dict[str, list[ShapeHit]] = {}
    for h in hits:
        by_cap.setdefault(h.capability, []).append(h)

    capabilities = ["execution.loader_script", "execution.dynamic_import", "execution.build_hook"]
    findings = []
    for capability in capabilities:
        cap_hits = by_cap.get(capability, [])
        status = "FOUND" if cap_hits else ("PARTIAL" if failed else "NOT_FOUND_WITHIN_ANALYSED_SCOPE")

        limitations = [
            "Establishes the presence and shape of a file, not that it is executed.",
            "Repository conventions change; a loading script under an unconventional name "
            "and with no builder subclass is not matched.",
        ]
        if capability == "execution.loader_script":
            limitations.append(
                f"Whether a loading script is live depends on the consuming `datasets` "
                f"version, which is NOT visible in the artifact. Scripts are honoured "
                f"before {DATASETS_SCRIPTS_REMOVED_IN} and raise RuntimeError from "
                f"{DATASETS_SCRIPTS_REMOVED_IN} onward. This finding does not assert which "
                "applies."
            )
        if capability == "execution.dynamic_import":
            limitations.append(
                "auto_map is executed by transformers only when the consumer passes "
                "trust_remote_code=True; the finding records reachability, not activation."
            )

        basis = (
            f"{len(cap_hits)} repository-shape indicator(s) matched: "
            + "; ".join(sorted({h.rule_id for h in cap_hits}))
            + "."
            if cap_hits
            else (
                f"No repository-shape indicator for this capability across "
                f"{len(py_files)} Python and {len(config_files)} JSON file(s)."
            )
        )
        if capability == "execution.loader_script" and cap_hits:
            basis += (
                f" A loading script is honoured by `datasets` before "
                f"{DATASETS_SCRIPTS_REMOVED_IN} and rejected from that version onward; the "
                "consuming version is unknown to this check."
            )

        findings.append(
            make_finding(
                capability=capability,
                status=status,
                detection_method="static_ast",
                rule_id=f"{RULE_ID}:{capability}",
                rule_version=RULE_VERSION,
                source_component=component,
                scope=scope,
                evidence=[
                    make_evidence(
                        kind="file_line" if h.line else "declaration_text",
                        path=h.path,
                        line=h.line,
                        excerpt=h.excerpt,
                        detail=f"rule={h.rule_id} {h.detail}",
                    )
                    for h in cap_hits
                ],
                confidence_basis=basis,
                limitations=limitations,
            )
        )

    return ShapeResult(findings=findings, scope=scope, hits=hits)
