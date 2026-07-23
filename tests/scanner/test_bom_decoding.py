"""Regression control for the UTF-8 BOM parse failure found in the first external study.

Study reference: `study/results/PHASE1_VERIFICATIONS.md` V2, `study/results/DIVERGENCE_CATALOGUE.md`.
`k9cli/video-vec2wav2-tokenizer` shipped Python files beginning with a UTF-8 BOM (`ef bb bf`).
The scanner read them with `encoding="utf-8"`, which leaves the BOM as a `U+FEFF` character, so
`ast.parse` rejected it and 30 of 33 capabilities came back `PARTIAL` — the repo was effectively
unanalysed. Bandit parsed the identical files without error.

The fix reads source with `encoding="utf-8-sig"` (strips a leading BOM, no-op otherwise) at
every scanner read site. This control asserts three things the fix must satisfy at once:

1. a BOM-carrying file now parses and is analysed (no `PARTIAL` from the BOM);
2. behaviour is unchanged on a byte-identical non-BOM twin;
3. a genuinely unparseable input STILL fails closed to `PARTIAL` — the fix reads the BOM, it
   does not weaken the failing-closed guarantee for input the scanner truly cannot parse.

The fixtures under `tests/fixtures/bom/` are real files: `bom_module.py` begins with the actual
`ef bb bf` bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustlens.scanner.pysource import load_python_file
from trustlens.scanner.assemble import scan

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "bom"


def test_the_fixture_actually_carries_a_bom():
    """Guard the guard: if the fixture lost its BOM, this control would pass vacuously."""
    assert (FIX / "bom_module.py").read_bytes()[:3] == b"\xef\xbb\xbf"
    assert (FIX / "nobom_module.py").read_bytes()[:3] != b"\xef\xbb\xbf"


def test_bom_file_parses_instead_of_failing():
    """The k9cli condition: a BOM-prefixed file must now parse, not become a scope failure."""
    pf = load_python_file(FIX / "bom_module.py", "bom_module.py")
    assert pf.ok, f"BOM file should parse now; failed with {pf.failed_item}"
    assert pf.tree is not None


def test_bom_and_nonbom_twins_produce_identical_analysis():
    """Behaviour must be unchanged by the presence of a BOM — same capability found."""
    bom = load_python_file(FIX / "bom_module.py", "m.py")
    nobom = load_python_file(FIX / "nobom_module.py", "m.py")
    assert bom.ok and nobom.ok
    # Both decode to the same source (BOM stripped) and the same import aliases.
    assert bom.source == nobom.source
    assert bom.aliases == nobom.aliases


def test_bom_repo_scan_has_no_partial_from_the_bom(tmp_path):
    """End to end: scanning a repo of BOM files completes rather than PARTIALing, and the
    detectable capability (subprocess/shell) is FOUND."""
    (tmp_path / "loader.py").write_bytes(
        b"\xef\xbb\xbf" + b"import subprocess\nsubprocess.run(['x'], shell=True)\n"
    )
    result = scan(tmp_path)
    assert result.record["scope"]["failed"] == [], (
        f"BOM file must not appear in scope.failed: {result.record['scope']['failed']}"
    )
    caps = {f["capability"]: f["status"] for f in result.record["findings"]}
    assert caps.get("process.shell") == "FOUND"


def test_genuinely_unparseable_input_still_fails_closed(tmp_path):
    """The failing-closed guarantee must survive the fix. A real syntax error, and a real
    non-UTF-8 file, must both still produce a scope failure (PARTIAL), not a clean parse."""
    # (a) invalid syntax
    bad_syntax = load_python_file(_write(tmp_path / "a.py", b"def (:\n  pass\n"), "a.py")
    assert not bad_syntax.ok and bad_syntax.failed_item["kind"] == "parse_error"

    # (b) genuinely invalid bytes (not a BOM) — utf-8-sig must still raise
    bad_bytes = load_python_file(_write(tmp_path / "b.py", b"\xff\xfe\x00bad"), "b.py")
    assert not bad_bytes.ok and bad_bytes.failed_item["kind"] == "decode_error"

    # (c) at the record level, that failure is PARTIAL, never clean
    (tmp_path / "c.py").write_bytes(b"\xff\xfe not utf8 at all")
    result = scan(tmp_path)
    assert result.record["scope"]["failed"], "an undecodable file must land in scope.failed"


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path
