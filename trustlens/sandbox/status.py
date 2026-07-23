"""The EXPERIMENTAL lock, enforced in code rather than in documentation.

`SANDBOX_THREAT_MODEL.md` §2.1 records a boundary that a document cannot hold on its own:

    The sandbox may not be promoted to "trusted for hostile input" while running on gVisor,
    because gVisor was never signed off for that case.

The sign-off of 2026-07-22 (`docs/SIGN_OFF.md`, SO-1) approved gVisor for development,
testing, and artifacts whose threat model is hostile userspace code. It explicitly did not
approve it for artifacts of the kind the July 2026 motivating incident involved — an agentic
attacker chaining zero-days — and the signer stated that promotion out of `EXPERIMENTAL`
"will not be given for a gVisor-only configuration".

So the promotion path is closed *for this mechanism specifically*, and closing it is this
module's whole job. `promote()` refuses on gVisor regardless of what review record is
presented, because a review record authorising a gVisor-only promotion would be authorising
something the sign-off withheld. It is not enough for the refusal to live in prose that a
later session may not read.

This is deliberately annoying to work around. That is the point: the failure mode being
prevented is a future change that quietly relaxes the boundary while every test still passes.
"""

from __future__ import annotations

import enum
import re

#: Verbatim, and asserted against the schema. The schema requires this exact string on any
#: EXPERIMENTAL sandbox record, so it is not free text.
BANNER = "EXPERIMENTAL — DO NOT USE FOR SUSPECTED ZERO-DAY OR HOSTILE ARTIFACTS"

#: The mechanism this package implements. Compared against `MECHANISMS_NEVER_PROMOTABLE`.
ISOLATION_MECHANISM = "gvisor"

#: Mechanisms for which promotion out of EXPERIMENTAL is refused unconditionally, because no
#: human sign-off authorises it for them. Adding a mechanism here is a safety change; removing
#: one is a claim that a human signed it off, and needs a `docs/SIGN_OFF.md` entry to be true.
MECHANISMS_NEVER_PROMOTABLE = frozenset({"gvisor"})

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PromotionRefused(RuntimeError):
    """Raised when something tries to leave EXPERIMENTAL without the sign-off that permits it."""


@enum.unique
class SandboxStatus(enum.Enum):
    """The two states the schema permits. Not a boolean, for the same reason `Status` is not."""

    EXPERIMENTAL = "EXPERIMENTAL"
    REVIEWED = "REVIEWED"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            raise TypeError(
                f"Refusing to compare SandboxStatus.{self.name} with the string {other!r}. "
                "A silent False here is the 'treat as reviewed' branch."
            )
        return self is other

    def __hash__(self) -> int:
        return hash(self.value)


def promote(
    *,
    mechanism: str,
    review_record_hash: str | None,
    approved_profiles: tuple[str, ...],
) -> SandboxStatus:
    """Return the sandbox status, refusing promotion that no sign-off authorises.

    Three independent refusals, in order. The first is the one that matters here and the one
    a future change is most likely to try to route around.
    """
    if mechanism.lower() in MECHANISMS_NEVER_PROMOTABLE:
        raise PromotionRefused(
            f"Refusing to promote a {mechanism!r} sandbox out of EXPERIMENTAL.\n"
            "gVisor was signed off (docs/SIGN_OFF.md SO-1, 2026-07-22) for development, "
            "testing, and artifacts whose threat model is hostile userspace code. It was "
            "NOT signed off as sufficient containment for the threat class TrustLens exists "
            "to defend against — an agentic attacker chaining zero-days, as in the July 2026 "
            "motivating incident. The signer stated that promotion out of EXPERIMENTAL will "
            "not be given for a gVisor-only configuration.\n"
            "Per SANDBOX_THREAT_MODEL.md §2.1, artifacts whose threat model includes kernel "
            "exploitation REQUIRE Firecracker on real KVM hardware. If that is now available, "
            "this is a new mechanism and a new sign-off, not an edit to this function."
        )
    if not review_record_hash or not _SHA256.match(review_record_hash):
        raise PromotionRefused(
            "REVIEWED requires a sha256 review-record hash; got "
            f"{review_record_hash!r}. The schema refuses this too, but refusing it here "
            "means the record is never constructed rather than constructed and rejected."
        )
    if not approved_profiles:
        raise PromotionRefused(
            "REVIEWED requires at least one approved profile. A reviewed sandbox with no "
            "approved profile authorises nothing and would be a status without content."
        )
    return SandboxStatus.REVIEWED


def current_status() -> SandboxStatus:
    """The status of this sandbox as built. Always EXPERIMENTAL — see `promote()`."""
    return SandboxStatus.EXPERIMENTAL


def residual_uncertainty(mechanism: str = ISOLATION_MECHANISM) -> str:
    """The sentence that must appear on every record this sandbox produces.

    Written here rather than at the call site so it cannot drift into something softer.
    """
    return (
        f"This record describes one execution under an EXPERIMENTAL {mechanism} sandbox. "
        "The isolation mechanism is signed off for artifacts whose threat model is hostile "
        "userspace code, and is NOT signed off as containment against kernel-level "
        "exploitation — the threat class this tool's motivating incident represented. "
        "A run that observes nothing establishes that nothing was observed at userspace "
        "level during this one execution under this profile. It does not establish that the "
        "artifact is safe, and it carries no containment claim against a kernel exploit."
    )
