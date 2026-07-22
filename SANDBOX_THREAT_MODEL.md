# Sandbox threat model

## Status: DRAFT — AWAITING SIGN-OFF

**Drafted 2026-07-22. Not approved. No isolation mechanism has been *selected* — one is
*recommended*, and selecting it is Warren's call, not this document's.**

**No sandbox execution code exists, and none will be written before sign-off.**

This is the third of three explicit states this file may hold, declared on the line above so
it can be checked mechanically rather than inferred from prose:

| State | Meaning |
|---|---|
| `NOT WRITTEN` | Placeholder. No review performed. (Held until 2026-07-22.) |
| `DRAFT — AWAITING SIGN-OFF` | Written, evidenced, not approved. **Current.** |
| `SIGNED OFF` | Warren has reviewed and approved this document. |

`SIGNED OFF` is a claim about a human action and may only be set by that human. Nothing in
this repository sets it, and no test infers it.

Two further things remain true regardless of this document's state, and are unchanged:

**The runtime status is code-enforced, not documentary.** The sandbox begins `EXPERIMENTAL`
in a machine-readable state. The schema already refuses to serialise an `EXPERIMENTAL`
sandbox listing approved profiles, and refuses a `REVIEWED` status with no review-record
hash. Editing this file changes nothing about what the runtime permits.

**Sign-off on the conformance-probe suite is a separate, later gate.** Approving this
document does not approve those probes. They do not exist yet. When they do, they require
explicit confirmation that each is non-destructive and non-weaponized *as written*, not
merely as intended — and the implementing session cannot discharge that on its own behalf.

---

## 1. What the sandbox is for, and what it is not for

TrustLens' first three components analyse artifacts **statically**. The sandbox exists to
observe what an artifact *does* when loaded — imports executed, files touched, network
attempted, subprocesses spawned — because static analysis of Python cannot decide this in
general and does not claim to.

**In scope:** an untrusted ML dataset, model artifact, or repository, obtained from a public
registry, which may be deliberately hostile and may be constructed specifically to defeat
this tool.

**Explicitly not in scope:**

- Malware analysis or detonation as a service. This is not a detonation chamber for
  arbitrary binaries.
- Any claim that executing an artifact here makes it safe to execute elsewhere.
- Any claim of containing an attacker with a kernel 0-day, a hypervisor escape, or hardware
  side-channel capability.
- Multi-tenant isolation. One artifact, one sandbox instance, torn down after.

## 2. Attacker model

The attacker **controls the artifact completely**: file contents, filenames, declared
metadata, archive structure, pickle opcodes, model card text, and any embedded code. They
know TrustLens is analysing them and have read this document.

The attacker **does not control**: the host, the operator's profile configuration, the
sandbox launch parameters, the isolation binary, or the kernel. §4 exists to keep it that
way, because the boundary between these two lists is the entire security argument.

Assumed capabilities: hostile userspace code, resource exhaustion attempts, attempts to read
host state, attempts to exfiltrate over network, attempts to persist. Assumed **not**
available: a working kernel 0-day. That assumption is load-bearing and is stated as an
assumption, not a fact — it is the largest single item in this model's trusted base.

## 3. Recommended mechanism and boundary

**Recommended (pending sign-off): gVisor, systrap platform, `--network=none`, rootless where
the host permits.** Full comparison and reasoning:
`docs/SPEC_phase3_isolation_selection.md`.

The boundary is gVisor's Sentry — a userspace kernel implementing the syscall surface. Per
gVisor's own documentation, "gVisor never passes through any system call to the host". The
claimed containment is *of hostile userspace code that attempts syscalls*, which is precisely
the observed risk class for a malicious ML artifact.

Verified on this machine rather than assumed: `runsc release-20260714.0` on aarch64 without
KVM produced a sandboxed process reporting kernel `4.19.0-gvisor` against a host kernel of
`6.19.14`. The workload reaches the Sentry, not the host kernel.

**Version pinning is required before any code.** The mechanism version, its checksum, and its
acquisition path must be recorded in the evidence record for every run, because a containment
claim about an unpinned binary is not a claim about anything.

## 4. Binding design constraint — artifact data may never reach launch configuration

**This is the single most important constraint in this document, it applies whichever
mechanism is selected, and it is a constraint on TrustLens rather than on the mechanism.**

No value derived from a scanned artifact may reach the code that constructs the sandbox's
launch configuration. "Derived from a scanned artifact" includes, without limit: declared
metadata, dataset or model card contents, filenames and paths inside the artifact,
configuration file contents, any string read during static analysis, and any finding,
evidence excerpt, or record field computed from those. "Launch configuration" means mount
specifications, resource limits, runtime flags, network configuration, environment
allowlists, and the image or VM identifier.

The artifact enters the sandbox as **opaque bytes at a fixed, pre-declared path**. Launch
configuration is built **only** from operator-supplied profile values.

### Why — the evidence

gVisor's `SECURITY.md` (retrieved 2026-07-22) makes non-control of the configuration a
*precondition* for an issue counting as a gVisor vulnerability at all. A CVE is assigned only
when:

> "The issue occurs in a context where the attacker does not initially control the sandbox
> configuration."

and its worked example is explicit that the other side of that line is working as intended:

> "An attacker can configure a sandbox to mount an arbitrary directory on the host, then read
> its files from inside the sandbox. Classification: SandboxSpec / HostLeak. CVE: No.
> Exposing host files to the sandbox via configured mounts and the sandbox being able to read
> them is intended behavior."

A deployment where untrusted input influences mounts, limits, or flags is therefore outside
gVisor's protected range **by the project's own definition**, and no amount of correct gVisor
operation compensates for it.

Kata Containers supplies the empirical demonstration that this is not theoretical. Three of
its four host-compromise advisories in the twelve months to 2026-07-22 are
configuration-injection paths:

| Advisory | Effect |
|---|---|
| `GHSA-7fhf-v3p3-rp56` | Untrusted pod annotation bind-mounts any host path into the guest, bypassing the operator allowlist (≤ 3.32.0) |
| `CVE-2026-50540` (CVSS 9.1) | Pod user specifies an arbitrary TOML configuration file on the host → host-level RCE (≤ 3.32.0) |
| `CVE-2026-44210` | VM escape via virtiofsd argument injection through a **default-enabled** annotation, serving "the entire host root filesystem into the guest VM" |

The last is the sharpest: the dangerous path was on **by default**. The failure mode is not
exotic. It is what happens whenever workload-supplied data reaches sandbox configuration.

### How it is enforced

`tests/test_sandbox_config_isolation.py`, written **before** any sandbox code so the code is
built against the constraint rather than audited for it afterwards. It fails on any import
from an analysis package into a sandbox module, and carries a positive control
(`test_the_guard_can_actually_fire`) that runs the checker against a synthetic violating
module — because a guard that has never fired proves nothing.

## 5. Host assumptions

- The host kernel is current and patched. The sandbox does not defend a vulnerable kernel.
- The host is single-tenant and operator-controlled. No untrusted party supplies profiles.
- **[?] Host hardening (SMT off, KSM off, current microcode) is Firecracker's documented
  requirement; the equivalent requirement set for gVisor systrap on this host has not been
  established** and must be before any `EXPERIMENTAL` status is lifted.
- The `runsc` binary is acquired over TLS from the official release channel, checksum
  verified, and pinned. Not rebuilt from source, not fetched at run time.

## 6. Guest model, as it will be built

Stated as design requirements for code that does not exist yet, so the code can be checked
against them rather than described afterwards:

- **Filesystem** — the artifact at a fixed path, read-only where the analysis permits. No
  host path is mounted by a name derived from the artifact (§4). No writable host mount.
- **Network** — `--network=none`. Attempted network activity is *observed as a finding*, not
  serviced. If a future profile needs network to observe behaviour meaningfully, that is a
  **re-review trigger**, not a configuration change: it removes rootless mode and changes the
  privilege model.
- **Privilege** — rootless where the host permits, per gVisor's documented
  `runsc --rootless --network=none`.
- **Resources** — CPU, memory, wall-clock and process-count limits from the operator profile
  only. Timeout is fail-closed: expiry yields `PARTIAL` with the timeout recorded in
  `scope.failed`, never a clean result.
- **Devices** — no device passthrough. No `/dev/kvm`, no GPU. (A future GPU profile would be
  a new threat model, not an extension of this one.)
- **Lifecycle** — one instance per artifact, destroyed after. No reuse, no snapshot restore.

## 7. Classes of escape and bypass NOT covered

Stated plainly, because a threat model that lists only what it stops is marketing.

1. **Kernel 0-day.** The Sentry reduces but does not eliminate host kernel surface. A
   sufficient kernel exploit defeats this boundary.
2. **Hardware side channels.** gVisor states directly: "gVisor does not provide protection
   against hardware side channels." Neither does anything else considered here.
3. **A gVisor Sentry escape.** One confirmed sandbox-crossing issue exists in the record
   (CVE-2018-16359, 2018). A second is possible and unmitigated.
4. **Operator-supplied misconfiguration.** §4 stops *artifact* data reaching launch config.
   It does not stop an operator writing a bad profile. That is deliberate — an operator
   configuring their own sandbox is outside gVisor's model and outside this one.
5. **Anything the artifact does when run *elsewhere*.** Observed behaviour in a
   network-isolated sandbox is a lower bound on behaviour, never a characterisation of it. An
   artifact that detects the sandbox and stays quiet produces
   `NOT_FOUND_WITHIN_ANALYSED_SCOPE`, which is **not** evidence of safety and must never be
   rendered as such.
6. **Resource exhaustion of the host** beyond what the configured limits cap.
7. **Supply-chain compromise of `runsc` itself.** Mitigated only by checksum pinning.

## 8. Trusted base

Named, per `honest-claims`, because a containment claim is only as good as what it rests on:
the host kernel; the gVisor Sentry and Gofer implementation; the `runsc` binary and its
acquisition path; the operator's profile; the assumption in §2 that no kernel 0-day is in
play; and the correctness of the §4 guard, which is a static import check and therefore
catches *import-mediated* data flow rather than every conceivable channel.

That last item is a real limitation and is stated as one: an import guard is a strong
structural barrier, not a proof of non-interference. A dynamic taint analysis would be
strictly stronger and is not being built.

## 9. Update policy for the isolation component

- The pinned `runsc` version and checksum are recorded in every evidence record.
- gVisor security disclosures run through a mailing list, not GitHub advisories — so
  monitoring must subscribe to that list. Watching the repository advisory feed would produce
  silence, and silence would be mistaken for absence of issues. This is the isolation
  review's count caveat in operational form.
- A version bump is a review event: the pin changes, and the recorded mechanism version in
  prior records must remain accurate for those runs.

## 10. What this document does not establish

- That gVisor is safe for hostile artifacts. gVisor does not claim that, and this document
  does not confer it.
- That the recommendation in §3 is correct. It is a recommendation with stated reasoning and
  stated conditions that would change it.
- That systrap is as strong as gVisor's KVM platform, or that either is as strong as a
  microVM. Not established, not asserted.
- Anything about the conformance probes, which do not exist and are a separate gate.
- That the CVE record is complete for any mechanism. All counts here are lower bounds; per
  §9, gVisor's is a lower bound by disclosure policy.
