"""Python source loading, parsing and name resolution for the static checks.

TrustLens parses Python itself rather than inferring parse success from an external tool.
That is not a preference: the entry-condition probe showed Semgrep reporting three
unparseable files as successfully scanned, with `errors: []` and exit 0
(`docs/PHASE1_ENTRY_CONDITIONS.md`). A scanner that inherits another tool's optimism
inherits its false-clean results.

Three properties this module guarantees:

* **Parsing never executes.** `ast.parse` builds a tree; it does not import, run, or
  evaluate the module. Nothing here calls `import`, `exec`, `eval` or `compile` on scanned
  content.
* **A file that cannot be parsed becomes a `scope.failed` entry**, which forces `PARTIAL`
  downstream. There is no path by which a parse failure becomes a clean result.
* **Parsing is fenced.** The Python documentation states `ast.parse` can crash the
  interpreter on sufficiently large or deeply nested input. Input here is untrusted and
  attacker-chosen, so size is capped and recursion depth is bounded, with either limit
  producing a recorded failure rather than a crash.
"""

from __future__ import annotations

import ast
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

#: Files larger than this are excluded rather than parsed. Recorded as an exclusion (a
#: choice) rather than a failure, since nothing was attempted.
MAX_SOURCE_BYTES = 5 * 1024 * 1024

#: Recursion ceiling while parsing untrusted input. Deeply nested literals are a documented
#: interpreter-crash vector; hitting this produces a recorded failure instead.
PARSE_RECURSION_LIMIT = 3000


@contextmanager
def _recursion_fence(limit: int = PARSE_RECURSION_LIMIT):
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(limit)
    try:
        yield
    finally:
        sys.setrecursionlimit(previous)


@dataclass
class PythonFile:
    path: str
    source: str | None = None
    tree: ast.Module | None = None
    failed_item: dict | None = None
    #: Maps a local binding to the canonical dotted module path it refers to.
    aliases: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.failed_item is None


def _fail(path: str, kind: str, reason: str) -> PythonFile:
    return PythonFile(path=path, failed_item={"path": path, "reason": reason, "kind": kind})


def build_alias_map(tree: ast.Module) -> dict[str, str]:
    """Resolve import aliases so `import subprocess as sp` makes `sp.Popen` matchable.

    Without this, renaming an import is a one-line bypass of every call rule. The
    planted-case controls exercise exactly that.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level:
                continue  # relative import; the target is outside this file's knowledge
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def parse_source(source: str, rel: str) -> PythonFile:
    try:
        with _recursion_fence():
            tree = ast.parse(source)
    except SyntaxError as exc:
        return _fail(rel, "parse_error", f"SyntaxError: {exc.msg} (line {exc.lineno})")
    except ValueError as exc:
        # e.g. source containing a null byte
        return _fail(rel, "parse_error", f"ValueError: {exc}")
    except RecursionError:
        return _fail(
            rel,
            "resource_limit",
            f"RecursionError: nesting exceeded the {PARSE_RECURSION_LIMIT}-frame parse fence",
        )
    except MemoryError:
        return _fail(rel, "resource_limit", "MemoryError while parsing")
    return PythonFile(path=rel, source=source, tree=tree, aliases=build_alias_map(tree))


def load_python_file(path: Path, rel: str) -> PythonFile:
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return _fail(
                rel,
                "resource_limit",
                f"file exceeds the {MAX_SOURCE_BYTES}-byte parse limit and was not parsed",
            )
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return _fail(rel, "decode_error", f"UnicodeDecodeError: {exc}")
    except (OSError, PermissionError) as exc:
        return _fail(rel, "io_error", f"{type(exc).__name__}: {exc}")
    return parse_source(source, rel)


def iter_python_files(root: Path, excluded_dirs: set[str]) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*.py")):
        if not p.is_file():
            continue
        if any(part in excluded_dirs for part in p.relative_to(root).parts):
            continue
        # A symlink escaping the scan root is an exclusion decision, not a parse.
        try:
            p.resolve().relative_to(root.resolve())
        except (ValueError, OSError):
            continue
        out.append(p)
    return out


def load_python_files(root: Path, excluded_dirs: set[str]) -> list[PythonFile]:
    return [
        load_python_file(p, str(p.relative_to(root))) for p in iter_python_files(root, excluded_dirs)
    ]


# ------------------------------------------------------------------ name resolution

def dotted_name(node: ast.AST) -> str:
    """Render an attribute/name chain as a dotted string, or '' if it is not one."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def resolve(name: str, aliases: dict[str, str]) -> str:
    """Expand a dotted name through the file's import aliases.

    `sp.Popen` with `import subprocess as sp` resolves to `subprocess.Popen`.
    `run(...)` with `from subprocess import run` resolves to `subprocess.run`.
    """
    if not name:
        return ""
    head, _, tail = name.partition(".")
    target = aliases.get(head)
    if target is None:
        return name
    return f"{target}.{tail}" if tail else target


def call_names(node: ast.Call, aliases: dict[str, str]) -> set[str]:
    """Every name a call could reasonably be known by, for matching against rules."""
    raw = dotted_name(node.func)
    if not raw:
        return set()
    resolved = resolve(raw, aliases)
    names = {raw, resolved}
    # Also expose the bare attribute so `x.extractall()` matches a suffix rule.
    if "." in resolved:
        names.add(resolved.rsplit(".", 1)[-1])
    return {n for n in names if n}


def keyword_of(node: ast.Call, name: str) -> ast.expr | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_literal_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_literal_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def string_constants(tree: ast.Module) -> list[tuple[str, int]]:
    """Every string literal with its line, for endpoint and path rules."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append((node.value, getattr(node, "lineno", 0)))
    return out
