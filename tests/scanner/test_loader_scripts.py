"""Controls for the repository-shape check: loader scripts and the auto_map remote-code vector."""

from __future__ import annotations

from pathlib import Path

import pytest

from trustlens.scanner.checks import loader_scripts as ls

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "loader_scripts"
CLEAN = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

EXPECTED = {
    "clean_repo": {},
    "legacy_dataset_script": {"execution.loader_script": "FOUND"},
    "auto_map_repo": {
        "execution.dynamic_import": "FOUND",
        "execution.loader_script": "FOUND",
    },
    "build_hook_repo": {"execution.build_hook": "FOUND"},
}


def _statuses(name: str) -> dict[str, str]:
    return {f["capability"]: f["status"] for f in ls.run(FIXTURES / name).findings}


@pytest.mark.parametrize("fixture", sorted(EXPECTED))
def test_fixture_statuses(fixture):
    statuses = _statuses(fixture)
    for capability, want in EXPECTED[fixture].items():
        assert statuses[capability] == want, f"{fixture}/{capability}"
    for capability, got in statuses.items():
        if capability not in EXPECTED[fixture]:
            assert got == CLEAN, f"{fixture}/{capability} unexpectedly {got}"


def test_every_fixture_is_covered():
    on_disk = {d.name for d in FIXTURES.iterdir() if d.is_dir()}
    assert on_disk == set(EXPECTED)


def test_auto_map_names_the_module_it_would_execute():
    """The live vector must identify which repository module transformers would run."""
    result = ls.run(FIXTURES / "auto_map_repo")
    auto = [h for h in result.hits if h.rule_id == "auto-map-remote-code"]
    assert len(auto) == 2, "both auto_map entries should be reported"
    modules = {h.detail.split("'")[1] for h in auto}
    assert modules == {"configuration_custom", "modeling_custom"}


def test_loader_script_finding_states_the_version_condition():
    """The same file is live or inert depending on a version this check cannot see."""
    result = ls.run(FIXTURES / "legacy_dataset_script")
    finding = next(
        f for f in result.findings if f["capability"] == "execution.loader_script"
    )
    assert finding["status"] == "FOUND"
    text = finding["confidence_basis"] + " ".join(finding["limitations"])
    assert ls.DATASETS_SCRIPTS_REMOVED_IN in text, (
        "the finding must state the datasets version at which loading scripts stop being honoured"
    )
    assert "not visible" in text.lower() or "unknown" in text.lower(), (
        "the finding must state that the consuming version is unknown, rather than assume one"
    )


def test_loader_script_does_not_assert_which_version_applies():
    """Honest bound: presence is reported, activation is not asserted."""
    result = ls.run(FIXTURES / "legacy_dataset_script")
    finding = next(
        f for f in result.findings if f["capability"] == "execution.loader_script"
    )
    assert any("does not assert" in lim.lower() for lim in finding["limitations"])


def test_builder_subclass_is_detected_regardless_of_filename(tmp_path):
    """A loading script under an unconventional name is still a builder subclass."""
    repo = tmp_path / "oddly_named"
    repo.mkdir()
    (repo / "totally_unrelated.py").write_text(
        "import datasets\n"
        "class D(datasets.GeneratorBasedBuilder):\n"
        "    pass\n",
        encoding="utf-8",
    )
    result = ls.run(repo)
    assert any(h.rule_id == "dataset-builder-class" for h in result.hits)


def test_clean_repo_yields_no_shape_findings():
    result = ls.run(FIXTURES / "clean_repo")
    assert result.hits == []
    assert all(f["status"] == CLEAN for f in result.findings)


def test_auto_map_is_read_without_importing_the_module(tmp_path, monkeypatch):
    """Reading auto_map must not import the module it names."""
    import sys

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.json").write_text(
        '{"auto_map": {"AutoModel": "modeling_canary.Model"}}', encoding="utf-8"
    )
    (repo / "modeling_canary.py").write_text(
        "# TrustLens SYNTHETIC FIXTURE - fires on import\n"
        "import pathlib\n"
        f"pathlib.Path({str(tmp_path / 'CANARY')!r}).write_text('fired')\n",
        encoding="utf-8",
    )
    before = set(sys.modules)

    ls.run(repo)

    assert not (tmp_path / "CANARY").exists(), "reading auto_map imported the named module"
    assert "modeling_canary" not in set(sys.modules) - before
