# Sandbox — claims and bounds

**Status: `EXPERIMENTAL` and gVisor-scoped. SO-1 (isolation choice) and SO-2 (probe suite)
signed off** — see [`docs/SIGN_OFF.md`](../../docs/SIGN_OFF.md) and
[`../../SANDBOX_THREAT_MODEL.md`](../../SANDBOX_THREAT_MODEL.md). Promotion out of
`EXPERIMENTAL` is **not** granted, and per SO-1 will not be granted for a gVisor-only
configuration.

## The boundary, first

The sandbox was signed off for artifacts whose threat model is **hostile userspace code**. It
was **not** signed off as containment against **kernel-level exploitation** — the class the
July 2026 incident represented. That distinction is load-bearing and is enforced in code, not
prose: `status.promote()` refuses to leave `EXPERIMENTAL` on gVisor unconditionally, so no
document edit and no review record can widen the boundary while the mechanism is gVisor.

## What it establishes

- For **one execution, under one operator-supplied profile, inside gVisor with
  `--network=none`**, it records what the artifact did: imports executed, files touched,
  network attempted, subprocesses spawned — each as a `DIRECT_OBSERVATION` or a
  `dynamic_blocked_observation`.
- Via the **conformance suite**, whether the configured boundary held against twelve
  prohibited-operation probes (host filesystem read/write, host PID visibility, signalling
  host processes, privilege confinement, blocked outbound, cloud metadata, device access,
  resource limits, DNS policy, mount isolation, environment sanitisation).
- **The runsc version, its sha256, and the observed sandbox kernel** are recorded in every
  sandbox record. A containment claim about an unpinned binary is not a claim about anything.
- **No artifact-derived value reaches the sandbox launch configuration** (mounts, limits,
  runtime flags, network, environment, image) — the constraint that gVisor's own policy makes
  a precondition of containment and that three of Kata's four host-compromise advisories
  violated. Enforced statically (import guard) and at runtime (the launch-config contamination
  check), each with a positive control.

## What it does not establish

- **That the artifact is safe.** An all-conform run is `NOT_FOUND_WITHIN_ANALYSED_SCOPE` —
  the weakest of the five states. Nothing hostile was observed *at userspace level in this one
  execution under this profile with this input*. That bounds the run, not the artifact.
- **Containment against a kernel-level attacker.** Not signed off for that class. Firecracker
  on real KVM hardware is the stated requirement before that class is in scope, and it is not
  built.
- **That observed behaviour matches behaviour elsewhere.** A network-isolated observation is a
  lower bound on behaviour; an artifact that detects the sandbox and stays quiet produces
  `NOT_FOUND_WITHIN_ANALYSED_SCOPE`, which is not evidence of safety.
- **Absence of dormant, delayed, or conditionally-triggered behaviour.** No finite set of
  executions establishes it.
- **Protection against hardware side channels.** gVisor disclaims them, and so does this.

## Known gaps, stated rather than discovered later

- **Host hardening for gVisor systrap is not established** on this host; it must be before any
  `EXPERIMENTAL` status is lifted (`SANDBOX_THREAT_MODEL.md` §5).
- **The §4 import guard catches import-mediated flow, not every channel.** It is a strong
  structural barrier, not a proof of non-interference; a dynamic taint analysis would be
  strictly stronger and is deliberately not built (§8).
- **The sandbox-launch path is verified only in a Linux container, by hand, not in CI.** There
  is no CI and no local KVM, so everything downstream of "launch a real gVisor sandbox" is
  hand-verified and recorded, not continuously tested (`docs/COVERAGE_GAPS.md` CG-2).

## Controls

- **EXPERIMENTAL lock** (`test_sandbox_experimental_lock.py`) — `promote()` refused on gVisor
  even with a valid review record and profiles; a positive control shows the lock can pass for
  a hypothetical signed-off mechanism, so the refusal is specific, not universal.
- **Config-injection guard** (`test_sandbox_config_isolation.py`) — detonate-then-defuse: a
  planted analysis-package import into a sandbox module makes the guard fire; restored, it
  passes.
- **Non-weaponization audit** (`test_probes_non_weaponized.py`) — forbids the dangerous shapes
  a probe must never contain; a supporting control, not a substitute for the human SO-2 review.
- **Probe negative control** — run uncontained, 8 of 12 probes deviate; run inside gVisor,
  12 of 12 conform. The tool passes a known-good sandbox without a false alarm and fails a
  known-bad one — the ground-truth validation recorded in `docs/PROBE_SUITE_REVIEW.md`.
