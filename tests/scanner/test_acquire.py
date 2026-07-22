"""Controls for remote acquisition.

The test that matters is `test_moving_target_still_yields_the_pinned_commit`. Confirming
that the flow *completes* proves nothing about the immutable-reference guarantee; the
guarantee is only tested by moving the source between the dry-run and the fetch and
checking that what arrives is what was pinned, not what HEAD points at now.

All fixtures are local git repositories created in a temp directory. Nothing here touches
a network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from trustlens.scanner import acquire
from trustlens.scanner.acquire import (
    AcquisitionError,
    AuthorizationRequired,
    ImmutableReferenceLost,
)

ACK = "warren; local test fixture that I created in this temp directory"


def _git(args, cwd):
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True,
        env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
             "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "HOME": str(cwd)},
    )


@pytest.fixture
def origin(tmp_path):
    """A local git repository standing in for a remote."""
    repo = tmp_path / "origin"
    repo.mkdir()
    _git(["init", "--quiet", "-b", "main"], repo)
    (repo / "README.md").write_text("# v1\nOriginal content.\n", encoding="utf-8")
    (repo / "loader.py").write_text("X = 1\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "--quiet", "-m", "v1"], repo)
    return repo


def _head(repo: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(repo), capture_output=True, text=True, check=True
    ).stdout.strip()


# --------------------------------------------------------------------------- dry run

def test_plan_writes_nothing_and_pins_a_commit(origin, tmp_path):
    before = {p for p in tmp_path.rglob("*")}
    p = acquire.plan(str(origin))
    after = {p_ for p_ in tmp_path.rglob("*")}

    assert before == after, "the dry run must not write anything"
    assert p.commit == _head(origin)
    assert len(p.commit) == 40
    assert "DRY RUN — nothing has been fetched." in p.describe()
    assert p.commit in p.describe(), "the dry run must show the commit it pinned"


def test_plan_lists_what_would_be_fetched(origin):
    p = acquire.plan(str(origin))
    assert p.refs_seen, "the dry run must show the refs advertised by the source"
    assert any(name.endswith("main") for name in p.refs_seen)


def test_plan_refuses_an_unsupported_source():
    with pytest.raises(AcquisitionError, match="only https"):
        acquire.plan("ftp://example.invalid/repo.git")


def test_plan_refuses_a_missing_ref(origin):
    with pytest.raises(AcquisitionError, match="not found"):
        acquire.plan(str(origin), ref="no-such-branch")


# ------------------------------------------------------------------- authorization

def test_fetch_without_acknowledgement_is_refused(origin, tmp_path):
    p = acquire.plan(str(origin))
    with pytest.raises(AuthorizationRequired, match="explicit authorization"):
        acquire.acquire(p, tmp_path / "dest", authorization_acknowledgement=ACK)
    assert not (tmp_path / "dest").exists() or not any((tmp_path / "dest").iterdir())


def test_empty_acknowledgement_is_refused(origin, tmp_path):
    p = acquire.plan(str(origin))
    with pytest.raises(AuthorizationRequired, match="not an acknowledgement"):
        acquire.acquire(
            p,
            tmp_path / "dest",
            authorization_acknowledgement="   ",
            i_am_authorised_to_fetch_this=True,
        )


def test_fetch_refuses_a_non_empty_destination(origin, tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "existing.txt").write_text("do not clobber me\n", encoding="utf-8")
    p = acquire.plan(str(origin))
    with pytest.raises(AcquisitionError, match="non-empty destination"):
        acquire.acquire(
            p, dest, authorization_acknowledgement=ACK, i_am_authorised_to_fetch_this=True
        )
    assert (dest / "existing.txt").read_text() == "do not clobber me\n"


# ------------------------------------------------------------------- the happy path

def test_acquire_records_the_immutable_reference_and_hash(origin, tmp_path):
    p = acquire.plan(str(origin))
    rec = acquire.acquire(
        p, tmp_path / "dest", authorization_acknowledgement=ACK,
        i_am_authorised_to_fetch_this=True,
    )
    assert rec.commit == p.commit
    assert len(rec.content_hash) == 64
    assert rec.file_count == 2
    assert rec.moved_since_plan is False
    assert rec.authorization_acknowledgement == ACK

    block = acquire.to_artifact_block(rec)
    assert block["immutable_reference"] == p.commit
    assert block["acquisition_authorised_by"] == ACK
    assert block["acquisition_method"] == "git_clone"


# ---------------------------------------------- THE test: a source that moves

def test_moving_target_still_yields_the_pinned_commit(origin, tmp_path):
    """Change the source between dry-run and fetch. The pinned content must arrive.

    Confirming the flow completes proves nothing. This is the only test that exercises
    the guarantee the dry-run exists to provide.
    """
    p = acquire.plan(str(origin))
    pinned = p.commit

    # The source moves after the plan was made.
    (origin / "README.md").write_text("# v2\nCONTENT CHANGED AFTER THE DRY RUN.\n", encoding="utf-8")
    (origin / "evil.py").write_text("import os\nos.system('echo pwned')\n", encoding="utf-8")
    _git(["add", "-A"], origin)
    _git(["commit", "--quiet", "-m", "v2"], origin)
    moved_head = _head(origin)
    assert moved_head != pinned, "precondition: the source must actually have moved"

    dest = tmp_path / "dest"
    rec = acquire.acquire(
        p, dest, authorization_acknowledgement=ACK, i_am_authorised_to_fetch_this=True
    )

    assert rec.commit == pinned, "the pinned commit must be what was acquired"
    assert (dest / "README.md").read_text() == "# v1\nOriginal content.\n", (
        "the acquired content is from the moved HEAD, not the pinned commit"
    )
    assert not (dest / "evil.py").exists(), (
        "a file added after the dry run appeared in the acquisition"
    )
    assert rec.moved_since_plan is True, "a source that moved must be recorded as having moved"
    assert rec.head_at_fetch == moved_head


def test_moving_target_is_visible_in_the_record(origin, tmp_path):
    """A moved source is not merely handled; it is reported."""
    p = acquire.plan(str(origin))
    (origin / "new.txt").write_text("added\n", encoding="utf-8")
    _git(["add", "-A"], origin)
    _git(["commit", "--quiet", "-m", "v2"], origin)

    rec = acquire.acquire(
        p, tmp_path / "dest", authorization_acknowledgement=ACK,
        i_am_authorised_to_fetch_this=True,
    )
    assert rec.moved_since_plan is True
    assert rec.head_at_fetch != rec.commit


def test_vanished_pinned_commit_fails_loudly(origin, tmp_path):
    """A force-push that destroys the pinned commit must not silently yield HEAD."""
    p = acquire.plan(str(origin))

    # Rewrite history so the pinned commit no longer exists in the source.
    (origin / "README.md").write_text("# rewritten\n", encoding="utf-8")
    _git(["add", "-A"], origin)
    _git(["commit", "--quiet", "--amend", "-m", "rewritten"], origin)
    _git(["reflog", "expire", "--expire=now", "--all"], origin)
    _git(["gc", "--prune=now", "--quiet"], origin)

    with pytest.raises(ImmutableReferenceLost, match="pinned at dry-run time"):
        acquire.acquire(
            p, tmp_path / "dest", authorization_acknowledgement=ACK,
            i_am_authorised_to_fetch_this=True,
        )


def test_acquiring_the_same_commit_twice_yields_the_same_hash(origin, tmp_path):
    p = acquire.plan(str(origin))
    a = acquire.acquire(
        p, tmp_path / "a", authorization_acknowledgement=ACK,
        i_am_authorised_to_fetch_this=True,
    )
    b = acquire.acquire(
        p, tmp_path / "b", authorization_acknowledgement=ACK,
        i_am_authorised_to_fetch_this=True,
    )
    assert a.content_hash == b.content_hash


# ------------------------------------------- acquisition stays out of the scan path

def test_scanning_never_acquires(monkeypatch, tmp_path):
    """The scanner's no-subprocess guarantee must not be weakened by acquisition."""
    called: list[str] = []

    def _boom(*a, **k):
        called.append("acquire")
        raise AssertionError("scan() must never acquire")

    monkeypatch.setattr(acquire, "plan", _boom)
    monkeypatch.setattr(acquire, "acquire", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)

    from trustlens.scanner.assemble import scan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("X = 1\n", encoding="utf-8")
    scan(repo)
    assert called == []


def test_assemble_module_does_not_import_acquire():
    import trustlens.scanner.assemble as assemble_mod
    import inspect

    source = inspect.getsource(assemble_mod)
    # Match the module reference, not the substring: "acquired_at" is a legitimate schema
    # field name and matching it made this test fire on correct code.
    assert "from .acquire" not in source and "import acquire" not in source, (
        "the assembler must not import acquisition; fetching is a separate, "
        "explicitly-initiated step"
    )
    assert "acquire." not in source
