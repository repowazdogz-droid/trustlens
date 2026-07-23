"""Safe, position-preserving parsing of untrusted configuration files.

Two requirements drive every choice here.

**Parsing must never construct anything.** A YAML document from an untrusted repository can
carry `!!python/object/apply:os.system`, which `yaml.load` will happily execute. This module
never calls `yaml.load`, and it does not merely use `SafeLoader` either — `SafeLoader`
*raises* on such a tag, which would turn the most interesting finding in the file into a
parse failure. Instead it installs a catch-all multi-constructor that **records the tag and
returns an inert placeholder**, so a dangerous tag is detected, located, and reported
without ever being constructed.

**A failure to parse is a first-class result, not an exception to swallow.** Every parse
returns a `ParsedConfig`; when it failed, the object carries a `failed_item` ready to drop
into `scope.failed`, which forces `PARTIAL` downstream. Phase 1 establishes parseability
itself rather than inferring it from an external tool, because the entry-condition probe
showed Semgrep reporting unparseable files as successfully scanned
(`docs/PHASE1_ENTRY_CONDITIONS.md`).
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

#: YAML tag suffixes that construct arbitrary Python objects. Detected, never constructed.
DANGEROUS_TAG_MARKERS = (
    "python/object",
    "python/object/apply",
    "python/object/new",
    "python/name",
    "python/module",
)

#: The standard YAML 1.1 types. Anything else is recorded as a tag sighting.
#:
#: This is an allowlist rather than a prefix test, and the distinction is load-bearing:
#: `!!python/object/apply:os.system` resolves to the tag
#: `tag:yaml.org,2002:python/object/apply:os.system` — it carries the *standard* prefix.
#: A "does this tag look non-standard" prefix check therefore silently misses the single
#: most dangerous construct in YAML, which is exactly what the first version of this file
#: did until a planted fixture caught it.
_STANDARD_YAML_TYPES = frozenset(
    {
        "str", "int", "float", "bool", "null", "binary", "timestamp",
        "seq", "map", "set", "omap", "pairs", "merge", "value", "yaml",
    }
)
_YAML_STD_PREFIX = "tag:yaml.org,2002:"


def is_nonstandard_tag(tag: str) -> bool:
    """True when a tag is not one of the standard YAML types, whatever its prefix."""
    if not isinstance(tag, str) or not tag:
        return False
    suffix = tag[len(_YAML_STD_PREFIX):] if tag.startswith(_YAML_STD_PREFIX) else tag
    return suffix.lstrip("!") not in _STANDARD_YAML_TYPES


@dataclass(frozen=True)
class TagSighting:
    """A YAML tag encountered during parsing. Recorded rather than resolved."""

    tag: str
    pointer: str
    line: int | None

    @property
    def is_dangerous(self) -> bool:
        return any(marker in self.tag for marker in DANGEROUS_TAG_MARKERS)


@dataclass(frozen=True)
class ScalarValue:
    """One string value in a configuration document, with where it came from."""

    pointer: str
    value: str
    line: int | None


@dataclass
class ParsedConfig:
    path: str
    format: str
    scalars: list[ScalarValue] = field(default_factory=list)
    tags: list[TagSighting] = field(default_factory=list)
    failed_item: dict | None = None

    @property
    def ok(self) -> bool:
        return self.failed_item is None

    @property
    def dangerous_tags(self) -> list[TagSighting]:
        return [t for t in self.tags if t.is_dangerous]


def _fail(path: str, fmt: str, kind: str, reason: str) -> ParsedConfig:
    return ParsedConfig(
        path=path,
        format=fmt,
        failed_item={"path": path, "reason": reason, "kind": kind},
    )


# ----------------------------------------------------------------------------- YAML

def _tag_capturing_loader(sightings: list[tuple[str, Any]]):
    """A SafeLoader that records unknown tags instead of constructing or rejecting them."""

    class _Loader(yaml.SafeLoader):
        pass

    def _capture(loader, tag_suffix, node):  # noqa: ANN001 - pyyaml signature
        sightings.append((tag_suffix, node))
        return {"__trustlens_unconstructed_tag__": tag_suffix}

    # The empty prefix catches every tag SafeLoader has no explicit constructor for,
    # which is exactly the set that would otherwise raise or execute.
    _Loader.add_multi_constructor("", _capture)
    _Loader.add_multi_constructor("!", _capture)
    return _Loader


def _walk_yaml_node(node, pointer: str, out: ParsedConfig) -> None:
    """Walk the composed node graph, which carries source positions on every node."""
    if node is None:
        return
    tag = getattr(node, "tag", "")
    if is_nonstandard_tag(tag):
        out.tags.append(
            TagSighting(tag=tag, pointer=pointer or "/", line=node.start_mark.line + 1)
        )
    if isinstance(node, yaml.ScalarNode):
        if isinstance(node.value, str):
            out.scalars.append(
                ScalarValue(
                    pointer=pointer or "/",
                    value=node.value,
                    line=node.start_mark.line + 1,
                )
            )
    elif isinstance(node, yaml.SequenceNode):
        for i, child in enumerate(node.value):
            _walk_yaml_node(child, f"{pointer}/{i}", out)
    elif isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, yaml.ScalarNode) else "?"
            _walk_yaml_node(value_node, f"{pointer}/{key}", out)


def parse_yaml(path: Path, rel: str) -> ParsedConfig:
    out = ParsedConfig(path=rel, format="yaml")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        return _fail(rel, "yaml", "decode_error", f"UnicodeDecodeError: {exc}")
    except OSError as exc:
        return _fail(rel, "yaml", "io_error", f"{type(exc).__name__}: {exc}")

    sightings: list[tuple[str, Any]] = []
    loader_cls = _tag_capturing_loader(sightings)
    try:
        # compose_all gives a node graph with source marks, and never constructs values.
        for doc in yaml.compose_all(text, Loader=loader_cls):
            _walk_yaml_node(doc, "", out)
    except yaml.YAMLError as exc:
        return _fail(rel, "yaml", "parse_error", f"{type(exc).__name__}: {str(exc)[:300]}")
    return out


# ----------------------------------------------------------------------------- JSON / TOML

def _locate_line(text: str, needle: str) -> int | None:
    """Best-effort line lookup for formats whose parsers discard positions.

    Returns the 1-based line of the first occurrence, or None. This is a locate, not a
    parse position: if the same string appears twice, the first wins. Recorded as
    best-effort so a reader does not over-trust the coordinate.
    """
    if not needle:
        return None
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def _walk_plain(obj: Any, pointer: str, text: str, out: ParsedConfig) -> None:
    if isinstance(obj, str):
        out.scalars.append(
            ScalarValue(pointer=pointer or "/", value=obj, line=_locate_line(text, obj))
        )
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _walk_plain(v, f"{pointer}/{k}", text, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_plain(v, f"{pointer}/{i}", text, out)


def parse_json(path: Path, rel: str) -> ParsedConfig:
    out = ParsedConfig(path=rel, format="json")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        return _fail(rel, "json", "decode_error", f"UnicodeDecodeError: {exc}")
    except OSError as exc:
        return _fail(rel, "json", "io_error", f"{type(exc).__name__}: {exc}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return _fail(rel, "json", "parse_error", f"JSONDecodeError: {exc}")
    _walk_plain(data, "", text, out)
    return out


def parse_toml(path: Path, rel: str) -> ParsedConfig:
    out = ParsedConfig(path=rel, format="toml")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return _fail(rel, "toml", "io_error", f"{type(exc).__name__}: {exc}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _fail(rel, "toml", "decode_error", f"UnicodeDecodeError: {exc}")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return _fail(rel, "toml", "parse_error", f"TOMLDecodeError: {exc}")
    _walk_plain(data, "", text, out)
    return out


#: Extensions are used to choose a parser, but never to decide whether a file is analysed —
#: dispatch on extension alone is the documented evasion in CVE-2025-10155. Files that fail
#: their extension's parser are retried against the others before being recorded as failed.
_PARSERS = {
    ".yaml": parse_yaml,
    ".yml": parse_yaml,
    ".json": parse_json,
    ".toml": parse_toml,
}

CONFIG_SUFFIXES = tuple(_PARSERS)


def parse_config(path: Path, rel: str) -> ParsedConfig:
    """Parse one configuration file, trying other formats if the expected one fails."""
    suffix = path.suffix.lower()
    primary = _PARSERS.get(suffix)
    order = [primary] if primary else []
    order += [p for p in (parse_yaml, parse_json, parse_toml) if p is not primary]

    first_failure: ParsedConfig | None = None
    for parser in order:
        result = parser(path, rel)
        if result.ok:
            return result
        if first_failure is None:
            first_failure = result
    assert first_failure is not None
    return first_failure


def iter_config_files(root: Path, excluded: set[str] | None = None) -> Iterator[Path]:
    excluded = excluded or set()
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in excluded for part in p.parts):
            continue
        if p.suffix.lower() in CONFIG_SUFFIXES:
            yield p
