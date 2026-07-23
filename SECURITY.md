# Security policy and safe-operation rules

TrustLens analyses artifacts that are assumed hostile. That makes the tool itself part of
the attack surface, and it makes careless defaults dangerous in a way an ordinary linter's
are not.

## Non-negotiable defaults

| Default | Behavior |
|---|---|
| Destructiveness | Non-destructive. Nothing is modified in the analysed artifact. |
| Locality | Local. No telemetry, no upload of findings, no remote schema fetch. |
| Network | Offline where possible. Acquisition is the only networked step and it is explicit. |
| Filesystem | Read-only against the artifact. |
| Failure | Fail closed. An error is never rendered as a pass. |
| Credentials | No production credentials, ever. Phase 2 works from offline descriptions. |
| Exploitation | None. No payload generation, no evasion, no weaponised probes. |
| Acquisition | Never silent. Explicit initiation plus a dry-run first. |
| Execution | Nothing is executed by default. Phase 3 execution is opt-in and gated. |

## Handling untrusted artifacts

An artifact under analysis is untrusted input to TrustLens itself, so:

- **Static analysis never imports, executes, unpickles, or deserialises the artifact.**
  Structural inspection only. A scanner that must load a file to analyse it has already
  lost.
- **Parsers are dispatched on content, not on file extension.** Published vulnerabilities
  in existing ML artifact scanners show extension-based dispatch producing a clean verdict
  on a malicious file whose loader dispatches on content instead (see `GROUNDING.md`).
- **A parse failure is `PARTIAL`, never clean.** The same published class includes a
  scanner halting on a corrupt archive entry and reporting no findings. In TrustLens a
  failure to complete is structurally incapable of being expressed as a completed clean
  scan.
- **The parser itself is a DoS surface and is fenced.** The Python documentation states
  that `ast.parse` can crash the interpreter: "It is possible to crash the Python
  interpreter with a sufficiently large/complex string due to stack depth limitations in
  Python's AST compiler." Since the input is untrusted and attacker-chosen, parsing runs
  behind a resource fence (recursion limit and subprocess or equivalent), and a crash is
  recorded as a `scope.failed` entry producing `PARTIAL` — never as a completed scan of
  that file.
- **Archive extraction is bounded** — path traversal, symlink escape, entry count,
  expansion ratio and total size are limits, not warnings.
- **Credential-shaped values are never stored.** TrustLens records the *names* of
  environment variables and the *paths* of secret mounts. Where a value would appear in an
  excerpt it is replaced and the evidence location is flagged `redacted`.
- **Excerpts are bounded** so records cannot become copies of the artifact.

## Remote acquisition

Any operation that fetches from a remote repository requires all of:

1. Explicit user initiation. There is no implicit fetch.
2. A dry-run showing exactly what would be fetched, before anything is fetched.
3. An ownership or authorization acknowledgement where the target is not obviously public.
4. An immutable reference — commit or revision — recorded where the source can supply one.
5. A cryptographic hash computed after acquisition.

Acquired artifacts are never committed to this repository.

## The sandbox is EXPERIMENTAL and that is enforced, not documented

Phase 3 is built. Its status is `EXPERIMENTAL` in a machine-readable state, and it refuses
any request that treats it as approved for hostile input, trusted for suspected zero-day
artifacts, a certified containment boundary, or production-safe for arbitrary untrusted
execution. There is no flag that trivially bypasses this.

**It is gVisor-scoped.** SO-1 and SO-2 ([`docs/SIGN_OFF.md`](docs/SIGN_OFF.md)) signed it off
for artifacts whose threat model is hostile *userspace* code — **not** for kernel-level
exploitation, the class the July 2026 incident represented. `status.promote()` refuses to
leave `EXPERIMENTAL` on a gVisor-only configuration, unconditionally; that promotion is a
separate sign-off which has not been given and, per SO-1, will not be given while the
mechanism is gVisor. See [`SANDBOX_THREAT_MODEL.md`](SANDBOX_THREAT_MODEL.md).

Leaving `EXPERIMENTAL` requires a signed or cryptographically hashed review record naming
the isolation mechanism and version, host configuration, completed conformance probes,
unresolved failures, threat-model version, reviewer identity, review date, and explicitly
approved and prohibited use profiles. The runtime validates that record before permitting
an approved profile. **Editing documentation does not change execution permissions.**

In every CLI output, API response, report and evidence record while `EXPERIMENTAL`:

> EXPERIMENTAL — DO NOT USE FOR SUSPECTED ZERO-DAY OR HOSTILE ARTIFACTS

A sandbox that leaks while presenting itself as protective is worse than no sandbox,
because it converts caution into false confidence.

## What TrustLens will not do

Not unimplemented features. Boundaries.

- Internet scanning or target discovery.
- Credential stuffing, brute force, or any use of live credentials.
- Exploit or payload generation.
- Persistence, evasion, or anti-detection.
- Automated exploitation chaining.
- Probing infrastructure the operator has not initiated analysis of.

## The synthetic "unsafe" fixtures shipped in this repository

TrustLens ships deliberately dangerous-*looking* code under `examples/repos/unsafe_*` and
`tests/fixtures/`: `subprocess(..., shell=True)`, `pickle.loads`, unsafe YAML tags,
credential-shaped paths. They are the scanner's positive controls — a control set that never
fires on a real trigger is not evidence the scanner works, so the triggers must be present.

Every one of these files is safe as shipped:

- Each dangerous call sits inside a **never-invoked method**; nothing runs on import.
- Each points at **nothing real** — configuration that resolves nowhere, canary paths.
- **No live credentials**, and **no external network contact**.
- Each is labelled in-source as a TrustLens fixture.

The inertness harness proves it: it detonates armed copies in a temp directory to show the
payloads are live, then scans a fresh copy with `subprocess`, `os.system` and `socket`
replaced by objects that raise, and confirms nothing fired
(`tests/scanner/test_inertness.py`).

**Expect automated scanners to flag them.** GitHub's scanning, an AV engine, or a corporate
proxy may pattern-match the malware-shaped constructs. That is the fixtures' purpose, not a
compromise — none of it is executable as an exploit. This is stated here so the flags are
anticipated rather than alarming.

## Reporting a vulnerability in TrustLens

Report privately to the maintainer rather than opening a public issue. A false-clean result
— any input for which TrustLens reports a completed clean scan while the capability is
present and in scope — is the highest-severity class of bug in this project and is treated
as a security report, not a correctness bug.
