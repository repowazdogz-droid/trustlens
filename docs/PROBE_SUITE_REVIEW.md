# Conformance probe suite — presented for review

**Status: AWAITING WARREN'S REVIEW. Not self-certified. This gate is separate from SO-1.**

SO-1 (2026-07-22) approved the *isolation choice*. It did not approve this probe suite. Per
the standing rule and the Phase 3 spec, human review of the probe suite is a **separate,
non-delegable gate**, and the implementing session may not discharge it on the strength of the
tests passing. This document exists so that review has something concrete and complete to act
on. Nothing here treats the suite as approved.

The suite runs today and its results are shown below, but "it runs and passes" is precisely
the claim a human must not accept on trust for a suite whose whole job is to execute
operations that must be safe as written. Read the code; this document is a map to it.

## What to review, and the two constraints it must meet

The payload is `trustlens/sandbox/probes.py` (runs inside the sandbox) and the harness is
`trustlens/sandbox/conformance.py` (runs outside, grades). The two binding constraints:

1. **Non-weaponized and non-destructive *as written*, not merely as intended.** Every probe
   attempts an operation expected to be *refused*, in its most benign form. There is no
   sandbox-escape exploit, no CVE proof-of-concept, no code whose success would compromise a
   host. `tests/sandbox/test_probes_non_weaponized.py` is a structural audit that forbids the
   dangerous shapes (no `subprocess`/`ctypes`/`mmap`/`fcntl`, no `exec`/`eval`, no
   sysrq-trigger or kernel-sysctl writes, the signal probe restricted to signal 0, the device
   probe read-only and never reading contents). **That audit is not a substitute for your
   read** — it forbids known-bad patterns; it cannot certify the intent of new code.

2. **This review gate is yours.** The recommended action at the end of this document is a
   checklist for a human, not a test result.

## The twelve probes (the full Phase 3 list)

Each attempts a prohibited operation and reports `CONFORMS` (boundary held), `DEVIATES`
(boundary failed — a containment finding), or `INCONCLUSIVE` (could not determine; never
treated as a pass). The most benign form of each, stated so you can check it against the code:

| # | Probe | What it does | Why it is safe as written |
|---|---|---|---|
| 1 | host filesystem read | opens a HOST-planted sentinel path | one read-only open of one byte; no exfiltration |
| 2 | host filesystem write | `O_CREAT` on the read-only rootfs and the ro artifact mount | targets only the sandbox's own read-only paths; never a host control file |
| 3 | host PID visibility | lists `/proc`, reads `comm` | read-only; looks for host-process markers |
| 4 | signal host process | `os.kill(pid, 0)` for host-range PIDs | signal **0** is the null signal — it delivers nothing |
| 5 | privilege confinement | `mknod` of a char device in `/tmp`, then unlink | creates a harmless node (1,3 = `/dev/null`'s numbers); denied in a confined sandbox |
| 6 | blocked outbound | TCP connect to 1.1.1.1:443, 8.8.8.8:53 | a connect attempt with no payload sent |
| 7 | cloud metadata | TCP connect to 169.254.169.254:80 | a connect attempt with no payload sent |
| 8 | device access | read-only `open` of `/dev/kvm`, `/dev/mem`, `/dev/sda`, `/dev/kmsg` | opened only; **contents never read**; fd closed immediately |
| 9 | resource limits | `getrlimit(RLIMIT_NOFILE)` | reads the limit; never exhausts it |
| 10 | DNS policy | `getaddrinfo("example.com")` | a name lookup; no connection follows |
| 11 | mount isolation | reads `/proc/self/mountinfo` | read-only; flags mounts outside the harness set |
| 12 | environment sanitisation | reads `os.environ` | read-only; flags host env vars outside the allowlist |

## Evidence — ground-truth validation against real gVisor (2026-07-23)

Run on `runsc release-20260721.0`, aarch64, no KVM, inside a privileged container. Raw output:
`scratchpad/.../conformance_evidence_2026-07-23.txt`. Two runs, because a verifier must be
shown to catch a real problem, not just to pass:

**Negative control — probes run UNCONTAINED (no sandbox):** 8 of 12 probes report `DEVIATES`.
This is the load-bearing evidence that the probes can actually detect the *absence* of
containment; a suite that only ever reports `CONFORMS` proves nothing. (The 4 that conform
uncontained do so because of the container's own environment — few PIDs, no metadata endpoint,
a runtime-set `RLIMIT_NOFILE` — not because the probe is blind. The suite as a whole fires
loudly.)

**Inside the gVisor sandbox:** 12 of 12 `CONFORMS` → `NOT_FOUND_WITHIN_ANALYSED_SCOPE`. A
correctly-contained sandbox produces **no false alarm**. This is the ground-truth pass that
separates "the tool runs" from "the tool works": the known-good case is not flagged, and the
known-bad case is.

Note the state the all-green run maps to: `NOT_FOUND_WITHIN_ANALYSED_SCOPE`, the **weakest** of
the five states, not a clean bill of health. It bounds the probed classes in this environment
and says nothing about gVisor's strength against a kernel exploit (`SANDBOX_THREAT_MODEL.md`
§2.1, §7). An all-green conformance run does **not** lift `EXPERIMENTAL`, and `status.promote()`
refuses gVisor regardless of any conformance result.

## Three soundness findings from the gVisor run — please review these specifically

The first inside-sandbox run reported **3 false `DEVIATES` on a correctly-contained sandbox**.
A false alarm on a good sandbox is the cardinal failure for this kind of tool, so each was
fixed and the fix is recorded here for your scrutiny — because these are exactly the judgement
calls a human should check, not the agent.

- **PR-1 — host filesystem read.** The probe also tried `/etc/shadow` and `/proc/1/environ`.
  Inside the sandbox's own mount and PID namespaces those read the *sandbox's* shadow file
  (from the operator base image) and the *sandbox init's* environ — neither is a host file.
  **Fix:** rely solely on a host-planted sentinel that does not exist in our rootfs, so a read
  can succeed only if the mount boundary leaked. True positive by construction.

- **PR-2 — privilege confinement.** The probe judged confinement from `/proc/self/uid_map`, a
  namespaces concept. gVisor does not confine by uid mapping — the Sentry is the boundary — so
  in-sandbox uid 0 is not a deviation, and a uid_map of "0 0" false-flagged a good sandbox.
  **Fix:** replaced with a benign capability test — `mknod` of a char device, which needs
  `CAP_MKNOD` and is denied in a confined sandbox. Mechanism-independent, and a success is a
  real capability leak rather than an inference.

- **PR-3 — environment sanitisation.** The runtime injects a locale variable (`LC_CTYPE`),
  which is not host-derived and not a secret; flagging it made a sanitised sandbox report a
  deviation. **Fix:** treat `LC_*` as runtime defaults. A real host secret
  (`AWS_SECRET_ACCESS_KEY`, a token) is still caught unchanged.

All three are the same lesson: the probes were first written with a namespaces/runc mental
model, and gVisor's model differs. They are documented in `docs/COVERAGE_GAPS.md` context and
guarded by regression tests (`test_privilege_probe_conforms_when_the_privileged_syscall_is_refused`
is the explicit "do not cry wolf on a good sandbox" guard).

## For your review — a checklist a human runs, not a test

1. Read `probes.py` end to end. For each probe, satisfy yourself the operation is benign *as
   written* — that its worst case, if the sandbox failed entirely, is a harmless local action
   (a connect with no payload, a node created and removed, a read of one byte), never a
   host-affecting one.
2. Confirm the non-weaponization audit (`test_probes_non_weaponized.py`) forbids what you would
   forbid, and add any pattern it misses.
3. Confirm you agree with the three soundness calls (PR-1..3) — especially that treating
   `LC_*` as allowed (PR-3) does not hide a leak you care about.
4. Confirm the grading asymmetry is what you want: any single `DEVIATES` fails the suite
   (`FOUND`); all-green is the weakest state, not a safety claim.

## What approving this would and would not do

Approving the probe suite would record that these probes are safe to run and sound in what
they check. It would **not** lift `EXPERIMENTAL`, would **not** approve running hostile
artifacts, and would **not** grant gVisor-only promotion (withheld by SO-1 and refused in code
by `status.promote()`). Those remain separate and, for a gVisor-only configuration, closed.

**When you have reviewed:** record the outcome as SO-2 in `docs/SIGN_OFF.md`. Until then this
suite is presented, not approved.
