# Phase 3 platform constraint — resolved 2026-07-22

Resolved **before** drafting the isolation-selection review, because the answer changes
which mechanisms are worth comparing. Settled empirically on the actual development machine,
not from documentation alone.

## Correction to an earlier statement

I previously flagged that "Firecracker, gVisor and Kata are all Linux/KVM-dependent". **That
was partly wrong.** All three are Linux-only, but only Firecracker and Kata are
*KVM*-dependent. gVisor's default platform needs no virtualization at all, and that
distinction turns out to be the deciding one.

## The machine

Apple **M4 Max**, macOS 15.7.3, arm64. `kern.hv_support: 1`.

## What each mechanism requires — from the projects themselves

| Mechanism | Requirement | Source |
|---|---|---|
| **Firecracker** | "Firecracker requires read/write access to `/dev/kvm` exposed by the KVM module"; "supports x86_64 and aarch64 **Linux**" | `docs/getting-started.md` |
| **gVisor** | "Today, gVisor requires Linux"; "supports x86_64/AMD64 and ARM64". The **systrap** platform "relies on `seccomp`'s `SECCOMP_RET_TRAP`… **does not require virtualization support from the host** and is therefore well-suited to run *inside* a virtual machine". Default since mid-2023. | `g3doc/architecture_guide/platforms.md`, FAQ |
| **Kata** | "Kata Containers requires **nested virtualization or bare metal**" | `docs/install/README.md` |
| **rootless podman/runc** | runc: "`runc` only supports Linux." podman runs on Mac "using a **Podman-managed virtual machine**" | both READMEs |

## What is actually true on this machine — measured, not inferred

A Linux VM is available (OrbStack, kernel `6.19.14`, aarch64).

**`/dev/kvm` is ABSENT inside it.** `grep -c kvm /proc/modules` returns 0, even with
`--privileged`. Nested virtualization is not exposed to the guest.

→ **Firecracker and Kata cannot run on this machine at all**, not even inside the Linux VM.

**gVisor systrap works.** Downloaded `runsc` for `aarch64` (`release-20260714.0`) inside the
Linux VM and ran a sandbox with no KVM:

```
$ runsc --platform=systrap --network=none --rootless --ignore-cgroups \
        do sh -c 'echo GVISOR-SANDBOX-OK; uname -r; id -u'
GVISOR-SANDBOX-OK
4.19.0-gvisor
0
```

The sandboxed process reports kernel **`4.19.0-gvisor`** — the Sentry's own emulated kernel,
not the host's `6.19.14`. That is direct evidence the workload is talking to gVisor rather
than to the host kernel, which is the property the whole mechanism exists to provide.

(`--ignore-cgroups` was needed only because this ran container-in-container; it is an
artefact of the test harness, not of gVisor on this platform.)

## The constraint, stated plainly

| Mechanism | Runs natively on macOS | Runs in a Linux VM here | Locally developable & testable |
|---|---|---|---|
| **gVisor (systrap)** | No | **Yes — demonstrated** | **Yes** |
| gVisor (KVM platform) | No | No — needs `/dev/kvm` | No |
| **Firecracker** | No | **No** — needs `/dev/kvm` | No |
| **Kata** | No | **No** — needs nested virt or bare metal | No |
| rootless podman/runc | No (VM only) | Yes | Yes |

## The practical path forward

This is a constraint to plan around, not a blocker.

**For gVisor — no obstacle.** It can be developed, run and conformance-tested locally today
inside the existing Linux VM. Nothing needs procuring. This is the only VM-class-adjacent
mechanism with that property, and it arises directly from systrap not needing virtualization.

**For Firecracker or Kata — three options, in order of cost:**

1. **Cloud bare-metal or nested-virt-enabled instance.** Firecracker's own tested-platform
   table lists only AWS `.metal` instances, and its docs state "EC2 only supports KVM on
   `.metal` instance types" — so for Firecracker specifically this is the *documented*
   supported path, not a workaround. Cost is real and recurring.
2. **CI-only iteration** on Linux runners with nested virtualization. Slow feedback, and the
   conformance probes — the part requiring human sign-off — would only ever run remotely,
   which weakens the review rather than the code.
3. **A separate Linux/KVM machine.** Fastest iteration, highest fixed cost.

**What this does not change.** The mechanism decision is not settled by convenience. If the
threat model concludes a microVM boundary is required for hostile ML artifacts, the correct
answer is to procure Linux/KVM infrastructure, not to choose gVisor because it is the one
that runs on this laptop. The platform constraint is an input to the review, not its
conclusion.

**What it does change.** Any option requiring KVM carries an infrastructure cost that must be
weighed explicitly in the review, and its conformance probes could not be run on the machine
where the rest of this project is verified — which matters because the human sign-off gate
covers exactly those probes.

---

# Addendum, 2026-07-22: CI viability, and a correction on escape counts

## CI as a path for Firecracker/Kata — real, but narrower than implied, and not currently existing

**There is no CI configured in this repository.** No `.github/workflows`, no git remote.
"CI-only iteration" is therefore infrastructure that would have to be created, not an option
already available — a distinction worth making before it is weighed against buying a Linux
box.

**GitHub-hosted runners do expose `/dev/kvm`, but only on the larger tier.** From GitHub's
own changelog, 23 February 2023, "Hardware accelerated Android virtualization on Actions
Linux larger hosted runners":

> "Starting on February 23, 2023, Actions users of GitHub-hosted **larger** Linux runners
> will be able to make use of hardware acceleration for Android testing… To make use of this
> on Linux, Actions users will need to add the runner user to the KVM user group"

with the setup being a udev rule on `KERNEL=="kvm"`. The presence of a `/dev/kvm` node is
what Firecracker requires.

So the CI path is **real but paid and tier-specific**: larger runners, not the standard free
ones. **[?] Whether the standard `ubuntu-latest` runners now also expose `/dev/kvm` was not
verified** — the primary evidence found says "larger", and I am not extrapolating from it.

Weighing it honestly: CI would let Firecracker or Kata be exercised, but the conformance
probes are precisely the artefact requiring human sign-off, and running them only on remote
ephemeral infrastructure makes that review harder to perform and harder to trust than running
them where the reviewer can see them.

## Correction: the "highest escape count" line was stated with more confidence than the evidence carries

I wrote that rootless podman/runc has "the highest escape count". The underlying CVEs are
real and I verified three of them directly against NVD rather than relying on a summary:

| CVE | NVD CVSS | Verbatim |
|---|---|---|
| CVE-2019-5736 | 8.6 | "allows attackers to overwrite the host runc binary (and consequently obtain host root access)" |
| CVE-2024-21626 | 8.6 | "due to an internal file descriptor leak, an attacker could cause…" |
| CVE-2025-31133 | 7.8 | affects "1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2" |

**But a cross-project count is not a like-for-like measurement, and ranking by it is
unsound.** The denominators differ in ways that swamp the counts:

* **gVisor publishes zero GitHub repository advisories** — disclosure runs through a mailing
  list — and its CVE criteria explicitly exclude anything where "the attacker… control[s] the
  sandbox configuration". Its low count reflects its disclosure route and restrictive
  criteria as much as its defect rate.
* **runc's own advisory list omits CVE-2019-5736**, its most famous escape. Every GHSA-derived
  count in this review is therefore a **lower bound**, not a total.
* **Kata's advisories cluster in the last ten months**, which could indicate more defects or
  simply more scrutiny — one of them credits AI-assisted analysis for the finding.
* Deployment scale, age and attacker attention differ by orders of magnitude across the four.

**What survives as decision-relevant, stated at the strength the evidence supports:**

* Firecracker: **no confirmed guest-to-host escape** in the public record; two memory-safety
  defects with conditional escape potential.
* gVisor: **one** confirmed sandbox-crossing issue, in 2018.
* Kata: **four** host-compromise advisories in twelve months, **three of them
  configuration-injection**.
* runc/podman: **repeated** confirmed escapes across 2019–2025, three landing on one day
  (2025-11-05), against a mechanism whose own projects publish no threat model.

That last row is enough to treat plain rootless containers as a weak fallback for hostile ML
artifacts — supported by the shared-kernel argument and podman's own claim being a *privilege
ceiling* rather than a containment claim, not by a count comparison. **The count comparison
itself should not appear in the review as a ranking.**
