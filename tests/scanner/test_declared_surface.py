"""Controls for declared-surface extraction.

The adversarial fixtures were written before the parser was trusted, and they found four
real defects: triplicated declarations on a case-insensitive filesystem, a negation that
matched the positive pattern as well as the negative one, false contradictions manufactured
on perfectly consistent cards, and duplicated scope failures. Each has a regression test
below.

The property that matters most: **absence of a declaration is never a declaration of
absence.** A card that says nothing about network access has not promised there is none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustlens.scanner.checks import declared_surface as ds

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "declared_surface"


def _run(name: str) -> ds.DeclaredResult:
    return ds.run(FIXTURES / name)


def _decls(result: ds.DeclaredResult) -> set[tuple[str, str]]:
    return {(d["capability"], d["declaration"]) for d in result.declarations}


# --------------------------------------------------------- absence is not a declaration

@pytest.mark.parametrize("name", ["no_declarations", "empty_repo"])
def test_absent_declarations_are_unknown_not_safe(name):
    result = _run(name)
    assert result.declarations == []
    assert result.unknowns, "an artifact that declares nothing must produce an UNKNOWN"
    reason = result.unknowns[0]["reason"]
    assert "not a declaration that it requires nothing" in reason, (
        "the record must state that silence is not a safe declaration"
    )


def test_sources_examined_is_recorded_even_when_nothing_is_found():
    """A clean result must say where it looked, or it is indistinguishable from not looking."""
    result = _run("empty_repo")
    assert len(result.sources_examined) >= 10
    assert "README.md" in result.sources_examined


# ------------------------------------------------------------------ happy-path reading

def test_honest_passive_card_is_read_correctly():
    result = _run("honest_passive")
    decls = _decls(result)
    assert ("execution.loader_script", "explicitly_absent") in decls
    assert ("network.outbound", "explicitly_absent") in decls


def test_honest_custom_code_card_is_read_correctly():
    result = _run("honest_custom_code")
    decls = _decls(result)
    assert ("execution.loader_script", "required") in decls
    assert ("execution.dynamic_import", "required") in decls
    assert ("network.outbound", "required") in decls
    assert ("package.install_at_runtime", "required") in decls


def test_declaration_in_an_unexpected_location_is_found():
    """A card at docs/CARD.md rather than README.md is still a card."""
    result = _run("unexpected_location")
    assert ("execution.loader_script", "required") in _decls(result)
    assert result.declarations[0]["source"]["path"] == "docs/CARD.md"


# -------------------------------------------------------------- regression: polarity

def test_requires_no_custom_code_does_not_also_read_as_required():
    """Regression: the positive pattern matched across the negation.

    "requires no custom code" produced BOTH explicitly_absent and required, which
    manufactured a contradiction on a perfectly consistent card.
    """
    result = _run("honest_passive")
    decls = _decls(result)
    assert ("execution.loader_script", "required") not in decls
    assert ("network.outbound", "required") not in decls
    assert result.contradictions == [], "an internally consistent card must not contradict itself"


def test_negation_after_the_subject_still_reads_as_required():
    """"requires custom code, and there is no way around it" is a positive declaration."""
    result = _run("negation_traps")
    assert ("execution.loader_script", "required") in _decls(result)
    assert ("execution.loader_script", "explicitly_absent") not in _decls(result)


# ------------------------------------------------------ regression: filesystem identity

def test_declarations_are_not_duplicated_by_filename_case():
    """Regression: README.md, README.MD and readme.md are one file on macOS.

    Path.resolve() preserves the spelling it was given, so it does not collapse them;
    filesystem identity does. Without this every declaration was recorded three times.
    """
    result = _run("honest_custom_code")
    verbatims = [d["verbatim"] for d in result.declarations]
    assert len(verbatims) == len(set(verbatims)), f"duplicated declarations: {verbatims}"


def test_scope_failures_are_not_duplicated_by_filename_case():
    result = _run("malformed_frontmatter")
    paths = [f["path"] for f in result.scope["failed"]]
    assert len(paths) == 1, f"the same unreadable file was recorded {len(paths)} times: {paths}"


# ---------------------------------------------------------------- genuine contradiction

def test_genuinely_contradictory_card_is_reported():
    """Frontmatter says custom_code; prose says none required. Both are recorded."""
    result = _run("contradictory")
    decls = _decls(result)
    assert ("execution.loader_script", "required") in decls
    assert ("execution.loader_script", "explicitly_absent") in decls
    assert len(result.contradictions) == 1
    assert result.contradictions[0]["capability"] == "execution.loader_script"
    assert result.contradictions[0]["reconciled"] is False


# ------------------------------------------------------------- malformed declarations

@pytest.mark.parametrize(
    "name,expected_fragment",
    [
        ("malformed_frontmatter", "not valid YAML"),
        ("unterminated_frontmatter", "no closing delimiter"),
        ("non_mapping_frontmatter", "not a mapping"),
        ("non_utf8_card", "UnicodeDecodeError"),
    ],
)
def test_malformed_card_is_a_recorded_failure_not_an_empty_card(name, expected_fragment):
    result = _run(name)
    assert result.scope["failed"], f"{name} produced no scope failure"
    assert expected_fragment in result.scope["failed"][0]["reason"]
    assert any("Completeness of the declared surface" in u["subject"] for u in result.unknowns)


def test_unterminated_frontmatter_still_reads_the_prose_below_it():
    """A broken metadata block must not discard the rest of the document silently."""
    result = _run("unterminated_frontmatter")
    assert ("execution.loader_script", "required") in _decls(result)
    assert result.scope["failed"], "the broken frontmatter must still be recorded"


def test_no_frontmatter_is_not_a_failure():
    """Absence of a metadata block is an absence, not an error."""
    result = _run("no_declarations")
    assert result.scope["failed"] == []


def test_frontmatter_parser_unit():
    assert ds.extract_frontmatter("# no frontmatter\n") == (None, None)
    data, failure = ds.extract_frontmatter("---\na: 1\n---\nbody\n")
    assert data == {"a": 1} and failure is None
    data, failure = ds.extract_frontmatter("---\na: [1,\n---\nbody\n")
    assert data is None and "not valid YAML" in failure


# ------------------------------------------------------- declared versus observed

def test_declared_versus_observed_contradiction_is_produced_end_to_end():
    """The product's headline output: card says passive, scanner finds execution."""
    from trustlens.scanner.assemble import scan

    result = scan(Path("examples/repos/unsafe_dataset_loader"))
    dvr = [c for c in result.contradictions if c["contradiction_id"].startswith("DVR-")]
    assert dvr, "a card declaring passive data over an executing repository must contradict"
    assert any(c["capability"] == "execution.loader_script" for c in dvr)
    for c in dvr:
        assert c["reconciled"] is False
        kinds = {side["evidence_kind"] for side in c["between"]}
        assert kinds == {"declared", "static"}


def test_honest_repositories_produce_no_declared_versus_observed_contradiction():
    from trustlens.scanner.assemble import scan

    for name in ("clean_tabular", "clean_jsonl", "clean_imagefolder"):
        result = scan(Path("examples/repos") / name)
        dvr = [c for c in result.contradictions if c["contradiction_id"].startswith("DVR-")]
        assert dvr == [], f"{name} produced a false discrepancy: {dvr}"
