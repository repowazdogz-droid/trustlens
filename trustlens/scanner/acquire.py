"""Remote acquisition, with a dry-run that pins an immutable reference.

**This module is deliberately outside the scan path.** The scanner spawns no processes at
all, and the inertness harness proves it by making `subprocess.run` raise. Acquisition
*does* spawn `git`, on purpose, and it is a separate, explicitly-initiated step. Nothing in
`assemble.scan()` calls anything here, and a test asserts that. The no-subprocess guarantee
belongs to scanning and is not weakened to accommodate fetching.

The flow, in order, none of it optional:

1. **Explicit initiation.** There is no implicit fetch. `plan()` does not write anything.
2. **Dry-run first.** `plan()` reports what would be fetched and resolves the source to an
   immutable reference before a single byte is written.
3. **Authorization acknowledgement.** `acquire()` refuses without it.
4. **Immutable reference.** The commit resolved at plan time is what gets checked out — not
   whatever HEAD points at when the fetch happens. This is the guarantee that matters and
   it is tested against a repository that moves between the two steps.
5. **Hash after acquisition**, over the acquired tree.

If the pinned commit no longer exists at fetch time — a force-push, a deleted branch — the
acquisition **fails loudly** rather than silently substituting current HEAD.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GIT_TIMEOUT_SECONDS = 120

#: Sources TrustLens will resolve. Anything else is refused rather than guessed at.
_GIT_URL = re.compile(r"^(https://|git@|ssh://|file://|/|\./|\.\./)")


class AcquisitionError(RuntimeError):
    """Raised when acquisition cannot proceed safely. Never downgraded to a warning."""


class AuthorizationRequired(AcquisitionError):
    """Raised when a fetch is attempted without an explicit acknowledgement."""


class ImmutableReferenceLost(AcquisitionError):
    """Raised when the pinned commit is not present at fetch time."""


@dataclass
class AcquisitionPlan:
    """What a fetch WOULD do. Produced without writing anything."""

    source: str
    resolved_ref: str
    requested_ref: str
    commit: str
    planned_at: str
    refs_seen: dict[str, str] = field(default_factory=dict)

    def describe(self) -> str:
        lines = [
            "DRY RUN — nothing has been fetched.",
            f"  source           : {self.source}",
            f"  requested ref    : {self.requested_ref}",
            f"  resolved ref     : {self.resolved_ref}",
            f"  immutable commit : {self.commit}",
            f"  planned at       : {self.planned_at}",
            "",
            "  A fetch will check out the immutable commit above, not whatever the",
            "  branch points at when the fetch runs. If that commit has disappeared by",
            "  then, acquisition fails rather than substituting current HEAD.",
        ]
        if self.refs_seen:
            lines.append("")
            lines.append(f"  refs advertised by the source ({len(self.refs_seen)}):")
            for name, sha in sorted(self.refs_seen.items())[:10]:
                lines.append(f"    {sha[:12]}  {name}")
            if len(self.refs_seen) > 10:
                lines.append(f"    … {len(self.refs_seen) - 10} more")
        return "\n".join(lines)


@dataclass
class AcquisitionRecord:
    source: str
    commit: str
    requested_ref: str
    destination: str
    acquired_at: str
    content_hash: str
    content_hash_method: str
    file_count: int
    total_bytes: int
    authorization_acknowledgement: str
    plan_planned_at: str
    moved_since_plan: bool
    head_at_fetch: str | None


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AcquisitionError("git is not available on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"git timed out after {GIT_TIMEOUT_SECONDS}s") from exc


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ------------------------------------------------------------------------- dry run

def plan(source: str, *, ref: str = "HEAD") -> AcquisitionPlan:
    """Resolve a source to an immutable commit. Writes nothing, fetches no content.

    `git ls-remote` reads the ref advertisement only; it does not transfer objects.
    """
    if not _GIT_URL.match(source):
        raise AcquisitionError(
            f"refusing to resolve {source!r}: only https, ssh, git@, file:// and local "
            "paths are supported. TrustLens does not guess at a source format."
        )

    result = _git(["ls-remote", source])
    if result.returncode != 0:
        raise AcquisitionError(
            f"could not read refs from {source!r} (git exit {result.returncode}): "
            f"{result.stderr.strip()[:300]}"
        )

    refs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            refs[parts[1]] = parts[0]

    # An explicitly requested ref NEVER falls back to HEAD. Silently substituting the
    # default branch for a branch that does not exist is precisely the class of quiet
    # substitution this module exists to prevent, and the first version did exactly that.
    if ref == "HEAD":
        candidates = ["HEAD"]
    elif ref.startswith("refs/"):
        candidates = [ref]
    else:
        candidates = [f"refs/heads/{ref}", f"refs/tags/{ref}"]
    commit = None
    resolved = ref
    for candidate in candidates:
        if candidate in refs:
            commit = refs[candidate]
            resolved = candidate
            break
    if commit is None and re.fullmatch(r"[0-9a-f]{40}", ref):
        commit, resolved = ref, ref  # already an immutable reference
    if commit is None:
        raise AcquisitionError(
            f"ref {ref!r} not found at {source!r}. Available: {sorted(refs)[:10]}"
        )

    return AcquisitionPlan(
        source=source,
        resolved_ref=resolved,
        requested_ref=ref,
        commit=commit,
        planned_at=_now(),
        refs_seen=refs,
    )


# ------------------------------------------------------------------------- fetch

def directory_manifest_v1(root: Path, excluded_dirs: set[str]) -> tuple[str, int, int]:
    lines, count, total = [], 0, 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in excluded_dirs for part in rel.parts):
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        lines.append(f"{rel}\0{hashlib.sha256(data).hexdigest()}")
        count += 1
        total += len(data)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest(), count, total


def acquire(
    plan_obj: AcquisitionPlan,
    destination: Path,
    *,
    authorization_acknowledgement: str,
    i_am_authorised_to_fetch_this: bool = False,
) -> AcquisitionRecord:
    """Fetch the planned commit. Refuses without an explicit acknowledgement."""
    if not i_am_authorised_to_fetch_this:
        raise AuthorizationRequired(
            "remote acquisition requires an explicit authorization acknowledgement. "
            "Pass i_am_authorised_to_fetch_this=True only if you own the source or have "
            "permission to retrieve it."
        )
    if not authorization_acknowledgement or not authorization_acknowledgement.strip():
        raise AuthorizationRequired(
            "authorization_acknowledgement must record WHO authorised this fetch and on "
            "what basis; an empty acknowledgement is not an acknowledgement."
        )

    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise AcquisitionError(
            f"refusing to fetch into non-empty destination {destination}; acquisition "
            "never overwrites existing content."
        )
    destination.mkdir(parents=True, exist_ok=True)

    clone = _git(["clone", "--quiet", "--no-checkout", plan_obj.source, str(destination)])
    if clone.returncode != 0:
        raise AcquisitionError(
            f"clone failed (git exit {clone.returncode}): {clone.stderr.strip()[:300]}"
        )

    # What does the branch point at NOW? Recorded so a moving target is visible rather
    # than silently absorbed.
    head_now = _git(["rev-parse", "HEAD"], cwd=destination)
    head_at_fetch = head_now.stdout.strip() if head_now.returncode == 0 else None

    checkout = _git(["checkout", "--quiet", plan_obj.commit], cwd=destination)
    if checkout.returncode != 0:
        raise ImmutableReferenceLost(
            f"the commit pinned at dry-run time ({plan_obj.commit}) could not be checked "
            f"out from {plan_obj.source!r}: {checkout.stderr.strip()[:300]}. The source has "
            "changed since the plan was made; acquisition fails rather than substituting "
            "whatever HEAD points at now."
        )

    actual = _git(["rev-parse", "HEAD"], cwd=destination)
    actual_commit = actual.stdout.strip()
    if actual_commit != plan_obj.commit:
        raise ImmutableReferenceLost(
            f"checked-out commit {actual_commit} does not match the pinned commit "
            f"{plan_obj.commit}"
        )

    digest, file_count, total_bytes = directory_manifest_v1(destination, {".git"})

    return AcquisitionRecord(
        source=plan_obj.source,
        commit=plan_obj.commit,
        requested_ref=plan_obj.requested_ref,
        destination=str(destination),
        acquired_at=_now(),
        content_hash=digest,
        content_hash_method="directory_manifest_v1",
        file_count=file_count,
        total_bytes=total_bytes,
        authorization_acknowledgement=authorization_acknowledgement.strip(),
        plan_planned_at=plan_obj.planned_at,
        moved_since_plan=bool(head_at_fetch and head_at_fetch != plan_obj.commit),
        head_at_fetch=head_at_fetch,
    )


def to_artifact_block(record: AcquisitionRecord, artifact_type: str = "git_repository") -> dict:
    """Shape an acquisition record into the evidence schema's artifact block."""
    return {
        "artifact_id": Path(record.destination).name,
        "artifact_type": artifact_type,
        "declared_kind": None,
        "source": record.source,
        "immutable_reference": record.commit,
        "acquisition_method": "git_clone",
        "acquisition_authorised_by": record.authorization_acknowledgement,
        "acquired_at": record.acquired_at,
        "content_hash": record.content_hash,
        "content_hash_method": record.content_hash_method,
        "file_count": record.file_count,
        "total_bytes": record.total_bytes,
    }
