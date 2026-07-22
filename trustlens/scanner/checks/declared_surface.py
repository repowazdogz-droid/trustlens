"""Extract what an artifact SAYS about itself.

This is the "declared" half of declared-versus-reachable. It reads README files, dataset
and model cards, metadata frontmatter, and package manifests, and records claims verbatim
with their location. It never infers a claim the artifact did not make.

Three rules shape every decision here:

**Absence of a declaration is `UNKNOWN`, never a safe default.** An artifact that says
nothing about network access has not declared that it makes none. The brief is explicit on
this and it is the easiest place to accidentally invent reassurance.

**Polarity is read, not guessed.** "requires custom code" and "requires no custom code"
differ by one word and mean opposite things. Patterns carry explicit polarity, and when
both polarities match for the same capability the result is `ambiguous` plus a recorded
contradiction — not a coin flip.

**A malformed card is a scope failure, not an empty card.** Unterminated or invalid YAML
frontmatter is recorded and forces `PARTIAL` downstream, because "we could not read the
declarations" and "there were no declarations" are different claims.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ...evidence import make_evidence, make_scope

RULE_ID = "declared-surface"
RULE_VERSION = "0.1.0"

#: Files that conventionally carry a dataset or model card, in preference order. Several
#: are non-standard locations that real repositories nonetheless use.
CARD_FILENAMES = (
    "README.md",
    "README.MD",
    "readme.md",
    "README.rst",
    "README.txt",
    "MODEL_CARD.md",
    "DATASET_CARD.md",
    "CARD.md",
    "docs/README.md",
    "docs/CARD.md",
    "docs/MODEL_CARD.md",
)

MANIFEST_FILENAMES = ("requirements.txt", "pyproject.toml", "setup.py", "environment.yml")


@dataclass(frozen=True)
class ProsePattern:
    pattern: re.Pattern[str]
    capability: str
    declaration: str
    note: str


#: Order matters only for readability; every pattern is evaluated. Negative patterns are
#: written to require the negation adjacent to the subject so that "no custom code is
#: required" matches and "custom code is required, no exceptions" does not.
PROSE_PATTERNS: tuple[ProsePattern, ...] = (
    # ---- custom code / execution
    ProsePattern(
        re.compile(
            r"\b(no|without|does not (?:require|need)|do not (?:require|need)|requires no)\b"
            r"[^.\n]{0,40}\b(custom code|code execution|executable code|loading script|"
            r"loader script|remote code)\b",
            re.IGNORECASE,
        ),
        "execution.loader_script",
        "explicitly_absent",
        "the card states custom code is not required",
    ),
    ProsePattern(
        re.compile(
            r"\b(requires?|needs?|must run|you must execute)\b"
            # The gap must not contain a negation, or "requires no custom code" would
            # match this POSITIVE pattern as well as the negative one and manufacture a
            # contradiction on a perfectly consistent card.
            r"(?:(?!\b(?:no|not|never|without|nor)\b)[^.\n]){0,40}"
            r"\b(custom code|loading script|loader script|remote code|trust_remote_code)\b",
            re.IGNORECASE,
        ),
        "execution.loader_script",
        "required",
        "the card states custom code is required",
    ),
    ProsePattern(
        re.compile(r"trust_remote_code\s*=\s*True", re.IGNORECASE),
        "execution.dynamic_import",
        "required",
        "the card instructs the reader to enable remote code execution",
    ),
    # ---- network
    ProsePattern(
        re.compile(
            r"\b(no|without|does not (?:require|need)|requires no)\b[^.\n]{0,40}"
            r"\b(network|internet|download|remote (?:access|fetch))\b",
            re.IGNORECASE,
        ),
        "network.outbound",
        "explicitly_absent",
        "the card states no network access is required",
    ),
    ProsePattern(
        re.compile(
            r"\b(requires?|needs?|will)\b"
            r"(?:(?!\b(?:no|not|never|without|nor)\b)[^.\n]){0,30}"
            r"\b(internet|network access|download(?:s|ed|ing)? (?:the|from|data))\b",
            re.IGNORECASE,
        ),
        "network.outbound",
        "required",
        "the card states network access is required",
    ),
    # ---- installation
    ProsePattern(
        re.compile(r"(?:^|\s)(?:pip|pip3|conda|uv pip)\s+install\s+\S", re.IGNORECASE),
        "package.install_at_runtime",
        "required",
        "the card gives a package-installation instruction",
    ),
    # ---- credentials / environment
    ProsePattern(
        re.compile(
            r"\b(set|export|provide|supply)\b[^.\n]{0,30}"
            r"\b([A-Z][A-Z0-9_]{3,}_(?:TOKEN|KEY|SECRET|PASSWORD))\b"
        ),
        "env.credential_pattern_read",
        "required",
        "the card instructs the reader to supply a credential in the environment",
    ),
    ProsePattern(
        re.compile(
            r"\b(requires?|needs?)\b"
            r"(?:(?!\b(?:no|not|never|without|nor)\b)[^.\n]){0,30}"
            r"\b(credentials?|api key|access token|authentication)\b",
            re.IGNORECASE,
        ),
        "env.credential_pattern_read",
        "required",
        "the card states credentials are required",
    ),
    # ---- passive-data claim
    ProsePattern(
        re.compile(
            r"\b(passive|static|plain|raw)\b[^.\n]{0,20}\b(data|dataset|files?|records?)\b",
            re.IGNORECASE,
        ),
        "execution.loader_script",
        "not_required",
        "the card describes the artifact as passive data",
    ),
)


@dataclass
class Declaration:
    capability: str
    declaration: str
    declared_by: str
    path: str
    line: int | None
    verbatim: str
    note: str


@dataclass
class DeclaredResult:
    declarations: list[dict] = field(default_factory=list)
    contradictions: list[dict] = field(default_factory=list)
    unknowns: list[dict] = field(default_factory=list)
    scope: dict = field(default_factory=dict)
    sources_examined: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------- frontmatter

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)


def extract_frontmatter(text: str) -> tuple[dict | None, str | None]:
    """Return (parsed_frontmatter, failure_reason).

    A document with no frontmatter returns (None, None) — that is an absence, not a
    failure. A document whose frontmatter is present but unreadable returns a reason, which
    becomes a scope failure. Those two must not be conflated.
    """
    if not text.startswith("---"):
        return None, None
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return None, (
            "frontmatter opening delimiter '---' present but no closing delimiter found; "
            "declarations in this block could not be read"
        )
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        return None, f"frontmatter is not valid YAML: {type(exc).__name__}: {str(exc)[:200]}"
    if data is None:
        return {}, None
    if not isinstance(data, dict):
        return None, (
            f"frontmatter parsed as {type(data).__name__}, not a mapping; "
            "declarations could not be read"
        )
    return data, None


def _line_of(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    return None if idx < 0 else text.count("\n", 0, idx) + 1


# ------------------------------------------------------------------------ card reading

def extract_from_card(text: str, rel: str) -> tuple[list[Declaration], list[dict]]:
    declarations: list[Declaration] = []
    failures: list[dict] = []

    frontmatter, failure = extract_frontmatter(text)
    if failure:
        failures.append({"path": rel, "reason": failure, "kind": "parse_error"})

    if frontmatter:
        tags = frontmatter.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        if isinstance(tags, list) and any(str(t) == "custom_code" for t in tags):
            declarations.append(
                Declaration(
                    capability="execution.loader_script",
                    declaration="required",
                    declared_by="metadata_yaml",
                    path=rel,
                    line=_line_of(text, "custom_code"),
                    verbatim="tags: custom_code",
                    note="the card's metadata carries the custom_code tag",
                )
            )
        if frontmatter.get("configs") or frontmatter.get("dataset_info"):
            declarations.append(
                Declaration(
                    capability="execution.loader_script",
                    declaration="not_required",
                    declared_by="metadata_yaml",
                    path=rel,
                    line=_line_of(text, "configs") or _line_of(text, "dataset_info"),
                    verbatim="configs/dataset_info present in metadata",
                    note=(
                        "declarative data configuration is present, which is the "
                        "no-loading-script convention"
                    ),
                )
            )

    body = _FRONTMATTER_RE.sub("", text) if frontmatter is not None else text
    for pattern in PROSE_PATTERNS:
        match = pattern.pattern.search(body)
        if not match:
            continue
        snippet = match.group(0).strip()
        declarations.append(
            Declaration(
                capability=pattern.capability,
                declaration=pattern.declaration,
                declared_by="dataset_card",
                path=rel,
                line=_line_of(text, snippet),
                verbatim=snippet[:400],
                note=pattern.note,
            )
        )
    return declarations, failures


def extract_from_manifest(path: Path, rel: str) -> list[Declaration]:
    """A dependency manifest is a declaration that installation is expected."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    if not text.strip():
        return []
    return [
        Declaration(
            capability="package.install_at_runtime",
            declaration="required",
            declared_by="package_manifest",
            path=rel,
            line=1,
            verbatim=text.strip().splitlines()[0][:200],
            note="a dependency manifest is present, so installation is expected",
        )
    ]


# ------------------------------------------------------------------------------- run

def _to_record(d: Declaration) -> dict:
    return {
        "capability": d.capability,
        "declaration": d.declaration,
        "declared_by": d.declared_by,
        "source": make_evidence(
            kind="declaration_text", path=d.path, line=d.line, excerpt=d.verbatim[:512]
        ),
        "verbatim": d.verbatim[:1024],
        "extraction_rule_id": RULE_ID,
        "extraction_rule_version": RULE_VERSION,
    }


#: Declaration values that assert the capability is NOT used, versus that it IS.
_NEGATIVE = {"explicitly_absent", "not_required"}
_POSITIVE = {"required", "optional"}


def run(
    root: Path,
    *,
    excluded_dirs: set[str] | None = None,
    component: str = "scanner",
) -> DeclaredResult:
    excluded_dirs = excluded_dirs or {"vendor", ".git", "node_modules", "__pycache__"}
    root = Path(root)

    declarations: list[Declaration] = []
    failures: list[dict] = []
    analysed: list[str] = []
    sources_examined: list[str] = []

    seen_real_paths: set = set()
    for name in CARD_FILENAMES:
        path = root / name
        sources_examined.append(name)
        if not path.is_file():
            continue
        # On a case-insensitive filesystem README.md, README.MD and readme.md resolve to
        # one file. Without this, every declaration and every failure is recorded once per
        # spelling, inflating counts and manufacturing duplicate contradictions.
        # Path.resolve() preserves the spelling it was given, so it does NOT collapse
        # README.md and README.MD on a case-insensitive filesystem. Filesystem identity
        # (device, inode) does, and is the truth rather than a string guess.
        try:
            st = path.stat()
            identity = (st.st_dev, st.st_ino)
        except OSError:
            identity = (0, str(path).casefold())
        if identity in seen_real_paths:
            continue
        seen_real_paths.add(identity)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            failures.append(
                {"path": name, "reason": f"UnicodeDecodeError: {exc}", "kind": "decode_error"}
            )
            continue
        except OSError as exc:
            failures.append(
                {"path": name, "reason": f"{type(exc).__name__}: {exc}", "kind": "io_error"}
            )
            continue
        found, fails = extract_from_card(text, name)
        declarations += found
        failures += fails
        analysed.append(name)

    for name in MANIFEST_FILENAMES:
        path = root / name
        sources_examined.append(name)
        if path.is_file():
            declarations += extract_from_manifest(path, name)
            analysed.append(name)

    # ---- contradictions between declarations themselves
    contradictions: list[dict] = []
    by_capability: dict[str, list[Declaration]] = {}
    for d in declarations:
        by_capability.setdefault(d.capability, []).append(d)

    records = [_to_record(d) for d in declarations]
    for capability, group in sorted(by_capability.items()):
        polarities = {
            "negative" if g.declaration in _NEGATIVE else
            "positive" if g.declaration in _POSITIVE else "other"
            for g in group
        }
        if "negative" in polarities and "positive" in polarities:
            indices = [str(records.index(_to_record(g))) for g in group]
            contradictions.append(
                {
                    "contradiction_id": f"D-{capability}",
                    "summary": (
                        f"The artifact declares both that {capability} is required and that "
                        "it is not, in the same repository."
                    ),
                    "between": [
                        {
                            "evidence_kind": "declared",
                            "ref": indices[i],
                            "assertion": f"{group[i].declaration}: {group[i].verbatim[:120]}",
                        }
                        for i in range(min(2, len(group)))
                    ],
                    "reconciled": False,
                    "capability": capability,
                }
            )

    unknowns: list[dict] = []
    if not declarations:
        unknowns.append(
            {
                "subject": "Declared capabilities of the artifact",
                "reason": (
                    "No card, metadata or manifest declaration was found among the "
                    f"{len(sources_examined)} conventional locations examined. The artifact "
                    "has not declared what it requires; this is not a declaration that it "
                    "requires nothing."
                ),
                "would_be_resolved_by": (
                    "A dataset or model card stating the artifact's execution, network and "
                    "credential requirements."
                ),
            }
        )
    if failures:
        unknowns.append(
            {
                "subject": "Completeness of the declared surface",
                "reason": (
                    f"{len(failures)} declaration source(s) could not be read, so the set of "
                    "declarations is incomplete."
                ),
                "would_be_resolved_by": "A readable, well-formed card.",
            }
        )

    scope = make_scope(
        analysed=sorted(analysed),
        languages=["markdown", "yaml", "toml", "text"],
        excluded=[],
        failed=failures,
    )

    return DeclaredResult(
        declarations=records,
        contradictions=contradictions,
        unknowns=unknowns,
        scope=scope,
        sources_examined=sources_examined,
    )
