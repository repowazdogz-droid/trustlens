# Sandbox threat model

## Status: NOT WRITTEN — the sandbox does not exist

**No isolation mechanism has been selected. No execution code has been written. No
security review has been performed.**

This file exists as a placeholder so that its absence is not mistaken for an oversight, and
so that nothing in this repository can be read as implying a containment boundary exists.
It will be written in Phase 3, which is gated on independently verified Phases 1 and 2.

Any document, report, or record in this repository that appears to describe a sandbox
configuration before Phase 3 is illustrative of the *evidence schema* and describes no real
isolation. `examples/records/sandbox_record.json` is such a record: its
`isolation_mechanism` field reads `PLACEHOLDER — selected in Phase 3, not in Phase 0`.

## What this file must contain before Phase 3 can be considered complete

Written from primary documentation and security advisories, with versions pinned and
recorded:

- The isolation-selection review: Firecracker microVMs, gVisor, Kata Containers, and
  rootless containers with hardened namespaces, seccomp, capabilities and cgroups
  evaluated against their own security models, with the reason for the selection stated.
- Chosen mechanism and version.
- The security boundary: what it is claimed to contain, and from what.
- Host assumptions, guest assumptions, and kernel dependence.
- Privilege model, filesystem model, network model, device exposure, resource controls.
- Update policy for the isolation component.
- Known limitations documented by the mechanism's own maintainers.
- Classes of escape or bypass explicitly **not** covered.

A naive subprocess is not an isolation boundary and will not be used as one.

## Two constraints already fixed

**The status is code-enforced, not documentary.** The sandbox begins `EXPERIMENTAL` in a
machine-readable state. Leaving that state requires a validated review record; the schema
already refuses to serialise an `EXPERIMENTAL` sandbox that lists approved profiles, and
refuses a `REVIEWED` status with no review-record hash. Changing this file changes nothing
about what the runtime will permit.

**Human sign-off is required and is not self-certifiable.** Before Phase 3 is marked
complete, the full conformance-probe suite must be reviewed by Warren personally, with
explicit confirmation that every probe is genuinely non-destructive and non-weaponized *as
written*, not merely as intended. Automated tests passing is not sufficient, and the
implementing session cannot discharge this on its own behalf.
