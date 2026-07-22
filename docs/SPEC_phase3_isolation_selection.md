# Phase 3 isolation-selection review

**Status: DRAFT — AWAITING SIGN-OFF. Not approved. No sandbox execution code exists.**
Prepared 2026-07-22 for Warren's review. Every mechanism claim below is quoted from the
project's own documentation or an authoritative advisory record, with the retrieval date
recorded. Nothing here is self-certified.

## What signing this off would mean, and what it would not

Signing off means agreeing that the mechanism named in §6 is the right one to build against,
on the evidence presented, with the constraints in §5 binding. It does **not** approve
running hostile artifacts: the sandbox begins and remains `EXPERIMENTAL` in a
machine-readable state, and leaving that state needs a separate, later review of conformance
probes that do not yet exist.

Two gates remain after this one:

1. The threat model (`SANDBOX_THREAT_MODEL.md`, drafted alongside this).
2. Your sign-off on the **conformance-probe suite**, confirming every probe is genuinely
   non-destructive and non-weaponized *as written*, not merely as intended.

## 1. The platform constraint, measured

Full detail in `docs/PHASE3_PLATFORM_CONSTRAINT.md`. In brief, on this machine (Apple M4
Max, macOS 15.7.3):

- **`/dev/kvm` is absent** inside the local Linux VM, even privileged. Nested virtualization
  is not exposed. **Firecracker and Kata cannot run here at all.**
- **gVisor's systrap platform works**, verified by running `runsc release-20260714.0` on
  aarch64 with no KVM. The sandboxed process reported kernel `4.19.0-gvisor` rather than the
  host's `6.19.14` — direct evidence the workload reaches the Sentry, not the host kernel.

This is an **input** to the decision, not the decision. If the threat model concludes a
microVM boundary is necessary, the correct response is to procure Linux/KVM hardware, not to
pick the mechanism that happens to run on this laptop.

## 2. A caveat that must survive into any future revision of this document

**Do not rank these mechanisms by CVE or escape count.** The counts are not comparable, and
an earlier draft of this analysis did rank them, wrongly. The denominators differ in ways
that swamp the numbers:

- **gVisor publishes zero GitHub repository advisories** — disclosure runs through a mailing
  list — and its CVE criteria exclude anything where "the attacker… control[s] the sandbox
  configuration". A low count reflects disclosure route and criteria as much as defect rate.
- **runc's own advisory list omits CVE-2019-5736**, its best-known escape. Every
  advisory-derived count here is a **lower bound**, not a total.
- **Kata's advisories cluster in ten months**, which may indicate scrutiny rather than
  defect density; one credits AI-assisted analysis for the finding.
- Deployment scale, project age and attacker attention differ by orders of magnitude.

Per-mechanism findings below are therefore stated individually, at the strength the evidence
supports, and are **not** presented as a league table.

## 3. What each project says its boundary is

**Firecracker** — assumes hostility from the first instruction, and pushes gradation into
host configuration. `docs/design.md`:

> "From a security perspective, all vCPU threads are considered to be running malicious code
> as soon as they have been started."

README, scoping the claim:

> "The overall security of Firecracker microVMs, including the ability to meet the criteria
> for safe multi-tenant computing, depends on a well configured Linux host operating system."

**gVisor** — a graded attacker model with an explicit protection line. `SECURITY.md`:

> "gVisor's purpose is to prevent these [container escapes]."

and, decisively for our use case:

> "The issue occurs in a context where the attacker does not initially control the sandbox
> configuration."

**Kata** — the broadest stated asset scope, in a document scoped only to the added VM layer.
`docs/threat-model/threat-model.md`:

> "Kata seeks to prevent an untrusted container workload or user of that container workload
> to gain control of, obtain information from, or tamper with the host infrastructure."

**Rootless podman/runc** — no threat model exists. runc's `SECURITY.md` is a disclosure
policy only. Podman's README claims a *privilege ceiling*, which is not a containment claim:

> "rootless containers will never have more privileges than the user that launched them."

Read exactly, that bounds privilege, not reach. A kernel LPE from inside the container
defeats it, and nothing in the sentence says otherwise.

## 4. Per-mechanism findings

### Firecracker

Strongest advisory record of the four: **no confirmed guest-to-host escape** in the public
record. Two memory-safety issues with conditional escape potential — CVE-2026-5747, whose
advisory states host-memory access "require[s] a higher level of control over the guest
environment, such as the use of a custom guest kernel", and CVE-2026-1386, which is a
*host-local* symlink attack, not a guest escape.

Requires KVM, a jailer started as root, and a hardened host (SMT off, KSM off, current
microcode). Recommends one Firecracker process per tenant — for us, one microVM per artifact.
Does no network filtering: "All egress traffic from a guest is therefore considered
untrusted, and should be filtered at the host-level."

**Cannot run on this machine.** Firecracker's own tested-platform table lists only AWS
`.metal` instances.

### gVisor

One confirmed sandbox-crossing issue, CVE-2018-16359, in 2018. Recent CVEs are DoS,
fingerprinting, or host-side LPE in `runsc` (CVE-2025-2713) rather than guest escapes. Note
the count caveat in §2 before reading anything into that.

Implements the syscall surface itself: "gVisor never passes through any system call to the
host." Two-layer design — "escaping the sandbox usually requires chaining multiple exploits".
Documents a fully rootless mode at the cost of networking: `runsc --rootless --network=none`.

**Its protection line is the thing to understand.** gVisor covers an attacker who controls
the workload *and the container image*. It explicitly does **not** cover one who controls the
OCI spec or runtime flags — its own example says exposing host files via configured mounts
"is intended behavior", not a vulnerability. §5 exists because of this.

**Runs on this machine today**, demonstrated.

### Kata Containers

Four host-compromise advisories in the twelve months to 2026-07-22, **three of them
configuration-injection**: `GHSA-7fhf-v3p3-rp56` (untrusted pod annotation bind-mounts any
host path, bypassing the operator allowlist), `CVE-2026-50540` (CVSS 9.1, arbitrary TOML
config → host RCE), and `CVE-2026-44210` (VM escape via virtiofsd argument injection through
a **default-enabled** annotation, serving "the entire host root filesystem into the guest").

That pattern is the reason §5 is a structural constraint rather than a note. It is also
mechanism-independent: the same design error would defeat any of these four.

Kata 4.0.0 (2026-07-20) is the fix release for three of those advisories and is two days old
at the time of writing, with essentially no field exposure. Default QEMU networking uses
`vhost-net`, an in-host-kernel backend that Kata's own risk gradient calls higher-risk, and
which it says "is being reevaluated".

**Cannot run on this machine.**

### Rootless podman / runc

Repeated confirmed escapes across 2019–2025, three landing on a single day (2025-11-05).
Verified directly in NVD: CVE-2019-5736 (CVSS 8.6) "allows attackers to overwrite the host
runc binary (and consequently obtain host root access)"; CVE-2024-21626 (8.6);
CVE-2025-31133 (7.8).

The structural argument matters more than the count: a shared host kernel means, in gVisor's
phrasing of this class, "the workload is only one system call away from host compromise".
Podman's own `rootless.md` is titled "Shortcomings of Rootless Podman" and notes "No support
for setting resource limits on systems using cgroups v1" — a resource-exhaustion DoS from a
hostile artifact would be unmitigated on such a host.

Runs on this machine via a Linux VM. **Not suitable as the primary boundary for hostile
artifacts.** Retained only as a possible degraded fallback, clearly labelled as such.

## 5. Binding design constraint — no artifact-derived data in sandbox configuration

**This is a requirement on TrustLens, not on the mechanism, and it holds whichever mechanism
is chosen.**

No value derived from a scanned artifact — declared metadata, filenames, configuration file
contents, any string read during static analysis, or any finding computed from them — may
reach the code that constructs the sandbox's launch configuration: mounts, resource limits,
runtime flags, network configuration, environment allowlist, or image identifier. The
artifact is delivered as opaque bytes at a fixed, pre-declared path. Launch configuration
comes only from operator-supplied profile values.

**Evidence.** gVisor `SECURITY.md` makes non-control of the configuration a *precondition*
for an issue being a gVisor vulnerability at all, and states that exposing host files via
configured mounts "is intended behavior". Kata's `CVE-2026-50540` and `CVE-2026-44210`
demonstrate the consequence when that line is crossed — the latter through a default-enabled
annotation.

**Enforcement.** `tests/test_sandbox_config_isolation.py`, written before any sandbox code.
It fires on any import from an analysis package into a sandbox module, and it carries a
positive control proving the checker detects a real violation rather than passing vacuously.

## 6. Recommendation

**Recommended: gVisor, systrap platform, `--network=none`, rootless where possible.**

The reasoning, in order of weight:

1. **Its threat model matches our attacker exactly.** An untrusted ML artifact is gVisor's
   `SandboxImage` rung — inside the protected range — provided §5 holds. No other project
   states its protection line this precisely, which makes the claim auditable rather than
   aspirational.
2. **It reimplements the syscall surface rather than filtering it.** For an artifact whose
   whole risk is what it asks the kernel to do, that is the property that matters most.
3. **It can be developed and conformance-tested where the reviewer is.** The probes needing
   your sign-off would run on the machine where everything else in this project is verified,
   not on remote ephemeral infrastructure.
4. **A rootless, no-network mode exists and is documented.** That is the configuration a
   first `EXPERIMENTAL` profile should use.

**What would change this recommendation:**

- If the threat model concludes a hardware-virtualization boundary is required — for example
  because the artifacts may carry kernel exploits rather than merely hostile userspace code —
  then **Firecracker** is the better mechanism on its advisory record, and the answer is to
  procure Linux/KVM hardware. That is a cost decision, not a technical blocker.
- If the artifact must have network access to be meaningfully observed, gVisor's rootless
  mode is unavailable and the privilege model changes; that should be re-reviewed rather
  than assumed through.

**Not recommended: Kata**, on the configuration-injection record combined with a fix release
two days old. **Not recommended as primary: rootless containers**, on the shared-kernel
argument.

## 7. CI status — corrected

**There is no CI configured in this repository.** No `.github/workflows`, no git remote.
"CI-only iteration" is a real option but a **yet-to-be-built** one, not a currently available
fallback, and it should be costed as new infrastructure.

GitHub-hosted runners do expose `/dev/kvm`, but per GitHub's own changelog of 2023-02-23 only
on **larger** Linux runners — a paid tier. **[?] Whether standard `ubuntu-latest` runners now
expose it was not verified**, and is not extrapolated here.

## 8. What this review does not establish

- That any mechanism is safe for hostile artifacts. None of the four claims that, and
  choosing one does not confer it.
- That the CVE records are complete. They are lower bounds; gVisor's is a lower bound by
  policy.
- That gVisor's systrap platform is as strong as its KVM platform, or that either is as
  strong as a microVM. That comparison was not made and would need its own evidence.
- Anything about the conformance probes, which do not exist.
- That side channels are addressed. Every project disclaims them; gVisor states plainly:
  "gVisor does not provide protection against hardware side channels."
