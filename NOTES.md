# Project notes

## Publication state (2026-07-23)

**Public.** https://github.com/repowazdogz-droid/trustlens

| Field | Value |
|---|---|
| Visibility | PUBLIC |
| Default branch | `master` — set deliberately; the repo history and CI are on `master`, and `ci.yml` triggers on both `master` and `main`. **No rename to `main`.** |
| Published at commit | `1e348d2` (all four phases built; docs un-frozen; LICENSE, CI in place) |
| CI | **Green** — both jobs (`verify`, `clean-clone`) pass. Action versions bumped past the Node 20 deprecation (`checkout@v5`, `setup-python@v6`). |
| Verified from the public URL | README "Try it" run verbatim from `https://github.com/repowazdogz-droid/trustlens.git` in a fresh clone: 656 passed, 0 failed, example records byte-identical. |
| Secret scanning | 0 alerts; push not blocked. The synthetic unsafe fixtures (path-shaped strings, pattern definitions) trip nothing; the explanatory notes in README + SECURITY.md were sufficient. |
| License | Apache-2.0 (`LICENSE`, matching `pyproject.toml`). |

### Not done, deliberately — release and DOI are separate, still-open decisions

**No release tagged. No DOI minted.** This is a held decision, not an oversight:

- The **Phase 3 sandbox is `EXPERIMENTAL` and code-locked.** `status.promote()` refuses to
  leave `EXPERIMENTAL` on a gVisor-only configuration, unconditionally. It was signed off
  (SO-1, SO-2 in `docs/SIGN_OFF.md`) for hostile-**userspace** artifacts only — **not** for
  kernel-exploitation artifacts, the class the July 2026 incident represented. Promotion out
  of `EXPERIMENTAL` is a separate sign-off that has not been given and, per SO-1, will not be
  given while the mechanism is gVisor.
- **Publication ≠ release ≠ DOI.** The code is public and verified; tagging a versioned
  release and minting a DOI are distinct acts with their own review, and the human decision
  on them is still open.

### Defect found at publication (recorded so it isn't repeated)

The first public clone came up **empty**: `gh repo create --source` pushed `master` while
GitHub had initialised the default branch as `main`, leaving HEAD pointing at a nonexistent
ref. Invisible to every source-side and local-clone check; visible only from the public URL.
Fixed by setting the default branch to `master`. This is the third instance of the
"verify the artifact people receive" class — see `CONTRIBUTING.md`, that section.

### Outstanding (not blocking publication)

- Promotion of the sandbox out of `EXPERIMENTAL` — separate sign-off, not available on
  gVisor-only (see above).
- Release tag + DOI — separate human decisions, open.
- Deferred items D1–D4 (`docs/DEFERRED.md`) — unscheduled (post-v1), each with a reason and
  what stands in its place.
