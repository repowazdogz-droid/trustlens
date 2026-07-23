# Coverage gaps — where the existing machinery does not catch errors

A defect that was caught is reassuring. A defect that the project's *own guards* did not
catch — that was found by eye, by a reviewer, or by luck — is the more useful signal, because
it marks the edge of what current coverage sees. Those belong in a list of their own rather
than absorbed into a general "N defects fixed" count, where they would read as evidence the
process is working when in fact they are evidence of where it isn't.

One entry per gap. Each records: what slipped, why the existing machinery missed it, and what
now covers it (if anything).

---

## CG-1 — Lossy `command` serialisation in the sandbox evidence record

**Found:** 2026-07-22, by eye, reading the first end-to-end gVisor run's output. Not by any
test.

**The defect.** `runsc.sandbox_block()` serialised the sandbox command with `" ".join(argv)`.
A profile command of `("/bin/sh", "-c", "uname -r; id -u")` became the record string
`"/bin/sh -c uname -r; id -u"`, which reads as two shell statements when it was a single `-c`
argument. The evidence record could not round-trip to the argv that actually ran.

**Why the machinery did not catch it.** Every test that touched `sandbox_block()` asserted on
the *structured* fields (`sandbox_status`, `banner`, `review_record_hash`) — the fields the
schema and the honesty invariants care about. Nothing asserted that the human-readable
`command` string was a *faithful* rendering of the argv, because faithfulness of a
free-text-shaped field had never been posed as a property. The schema types `command` as a
string and is satisfied by any string. So the value was wrong in a way that was invisible to
both the schema and the tests, and visible only to a person reading the output and noticing
the semicolon looked load-bearing.

**What this says about coverage.** The project's guards are strong on *structural* honesty
(five-state taxonomy, status comparison, contamination) and weak on *representational
fidelity* — whether a field that summarises something for a human actually reconstructs the
thing it summarises. That class was simply not on the map. It is plausible other summary
fields have the same latent gap (`network_rules`, `mounted_paths` rendering, any future
"human-readable" projection of structured state).

**What now covers CG-1 specifically.** `shlex.join` in `sandbox_block()`, and
`test_the_recorded_command_round_trips_to_the_argv_that_ran`, which asserts
`shlex.split(recorded) == profile.command`. That closes the instance. It does **not** close
the class: there is no general "every human-readable projection must round-trip" check, and
writing one is not yet scoped.

**Status:** instance closed; class open and now visible.

---

## CG-2 — `assemble_rootfs` could not run a dynamically linked interpreter

**Found:** 2026-07-23, by running the conformance suite in real gVisor. Not by any test — the
local suite cannot run gVisor, so it never exercised the interpreter-launch path at all.

**The defect.** The first `assemble_rootfs` built a rootfs by copying a single `python3`
binary into an otherwise bare directory. A dynamically linked interpreter needs its shared
libraries (`libpython`, `libc`, the dynamic loader); a lone binary in an empty rootfs cannot
execute. Inside the sandbox the command produced no output, so the probe payload never ran.

**Why the machinery did not catch it — and why this one is different from CG-1.** CG-1 was
invisible to tests that *did run*. CG-2 was invisible because the relevant test **cannot run
in this environment at all**: gVisor requires Linux, the local suite is on macOS, and the
whole sandbox-execution path is only exercisable in a Linux container that the unit tests do
not spin up. The unit tests validated the *grading* and the *probe logic* thoroughly, and the
`prepare_rootfs`/launch path not at all. This is the honest shape of the coverage boundary the
platform constraint (docs/PHASE3_PLATFORM_CONSTRAINT.md) imposes: everything downstream of
"launch a real sandbox" is verified by hand in a container and recorded, not by CI, **because
there is no CI and no local Linux/KVM** — exactly the gap the isolation review flagged.

**The redeeming detail.** The failure was *loud*, not silent. `parse_results` raised
"the probe payload did not run to completion … This is a failure to observe, not a clean
result" rather than returning an empty, all-conforming result. The never-silent design caught
a defect its own test coverage could not reach. That is the intended safety net doing its job.

**What now covers CG-2.** `prepare_rootfs` replaced `assemble_rootfs`: it overlays the probe
payload onto a **prepared working base rootfs** the operator supplies, and raises
`FileNotFoundError` if the base lacks the named interpreter, rather than silently producing an
unrunnable rootfs. The manual gVisor run (recorded in `docs/PROBE_SUITE_REVIEW.md`) is the
verification, since no local test can be.

**Status:** instance closed; the coverage boundary it revealed (sandbox-launch path is
container-only, hand-verified, no CI) is inherent to the platform and now stated plainly.
