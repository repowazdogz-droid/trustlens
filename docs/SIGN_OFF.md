# Sign-off record

Human sign-offs on gates that are, by design, not self-certifiable. One entry per sign-off.
An entry is a record of something a person did; nothing in this repository writes one on
their behalf.

---

## SO-1 — Isolation mechanism and sandbox threat model

| Field | Value |
|---|---|
| **Signed by** | Warren |
| **Date** | 2026-07-22 |
| **Documents** | `SANDBOX_THREAT_MODEL.md`, `docs/SPEC_phase3_isolation_selection.md` |
| **Document state at sign-off** | commit `0e2ff28` |
| **Verdict** | **APPROVED — SCOPED** |

### Approved

Building the sandbox against **gVisor / systrap, `--network=none`, rootless**, with the §4
config-injection constraint binding, **for**:

- development
- testing
- artifacts whose threat model is **hostile userspace code**

### Explicitly NOT approved

- Running genuinely hostile artifacts of the kind the **July 2026 motivating incident**
  involved — agentic attacker, chained zero-days, potential kernel-level exploitation.
- Treating gVisor as sufficient containment for the actual threat class TrustLens exists to
  defend against.

### Conditions attached

1. §2 of the threat model to state explicitly that the no-kernel-0-day assumption is in
   tension with the tool's own purpose; that gVisor is correct for development and
   userspace-threat artifacts; that **Firecracker on real KVM hardware is REQUIRED** before
   this is pointed at artifacts whose threat model includes kernel exploitation; and that the
   `EXPERIMENTAL` lock enforces exactly this boundary. → Discharged as §2.1.
2. §8 to stay as written. The import guard is honestly scoped as catching import-mediated
   flow and explicitly not proving non-interference. **A dynamic taint analysis is not to be
   built under time pressure to close this** — an honestly-labelled weaker check is worth
   more than an ambitious one trusted beyond its coverage. The admission stays adjacent to
   the guard. → Discharged: §8 unchanged, admission retained in place.
3. The `EXPERIMENTAL` lock and its code-enforced review gate remain in force.

### What this sign-off does NOT grant

**Promotion out of `EXPERIMENTAL` is a separate future sign-off, not given here**, and stated
by the signer as one that **will not be given for a gVisor-only configuration**.

Sign-off on the **conformance-probe suite** is also separate and outstanding. Those probes do
not exist yet; when they do they require explicit confirmation that each is non-destructive
and non-weaponized *as written*, not merely as intended.

---

## SO-2 — Conformance probe suite

| Field | Value |
|---|---|
| **Signed by** | Warren |
| **Presented** | 2026-07-23 |
| **Date** | 2026-07-23 |
| **Document reviewed** | `docs/PROBE_SUITE_REVIEW.md` |
| **Code reviewed** | `trustlens/sandbox/probes.py`, `trustlens/sandbox/conformance.py` |
| **Verdict** | **GIVEN** — distinct from SO-1 |

Separate from SO-1 and non-delegable; discharged by Warren's own review, not by the tests
passing.

### Approved

- **All twelve probes as non-weaponized as written.** Each attempts a prohibited operation in
  its most benign observable form. The structural audit
  (`tests/sandbox/test_probes_non_weaponized.py`) is accepted as a *supporting control* that
  forbids known-bad shapes rather than certifying intent.
- **PR-1, PR-2 and PR-3 as correctly fixed.** All three moved from proxy tests (namespace
  artifacts, uid mapping, locale vars) to direct tests of the property actually in question
  (host-planted sentinel; `mknod` capability; real credential-pattern env leakage). Right
  direction; reasoning holds.
- **The ground-truth validation as sufficient.** 8/12 `DEVIATES` uncontained establishes the
  probes detect the absence of containment, so the 12/12 `CONFORMS` inside the sandbox carries
  evidential weight rather than being an untested green.

### What this sign-off does NOT grant

SO-2 approves that the probes are **safe and sound**. It grants **no promotion**. `EXPERIMENTAL`
stands. `status.promote()` must continue to refuse gVisor unconditionally. Any future promotion
is a separate sign-off **not given here**, and stated by the signer as one that **will not be
given for a gVisor-only configuration**.

---

## Outstanding sign-offs

| Gate | State |
|---|---|
| Promotion out of `EXPERIMENTAL` | **NOT GIVEN** — and not available on a gVisor-only configuration |
