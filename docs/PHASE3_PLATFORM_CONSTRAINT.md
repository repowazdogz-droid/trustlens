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
