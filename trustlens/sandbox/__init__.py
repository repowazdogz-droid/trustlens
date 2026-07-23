"""Dynamic observation of an artifact inside a gVisor sandbox.

Signed off 2026-07-22 (`docs/SIGN_OFF.md`, SO-1) — **scoped**. Approved for development,
testing, and artifacts whose threat model is hostile userspace code. **Not** approved for
artifacts whose threat model includes kernel exploitation, which is the class the July 2026
motivating incident represented. `SANDBOX_THREAT_MODEL.md` §2.1 states the boundary;
`status.py` enforces it in code.

Nothing in this package may import from `trustlens.scanner` or `trustlens.mapper`. Anything
those packages return is artifact-derived by construction, and artifact-derived data must
never reach sandbox launch configuration (`SANDBOX_THREAT_MODEL.md` §4).
`tests/test_sandbox_config_isolation.py` enforces that.
"""

from .status import BANNER, ISOLATION_MECHANISM, SandboxStatus, PromotionRefused
from .profile import PROFILES, SandboxProfile, UnknownProfile
from .launch import ARTIFACT_MOUNT, LaunchConfig, LaunchConfigContaminated

__all__ = [
    "ARTIFACT_MOUNT",
    "BANNER",
    "ISOLATION_MECHANISM",
    "LaunchConfig",
    "LaunchConfigContaminated",
    "PROFILES",
    "PromotionRefused",
    "SandboxProfile",
    "SandboxStatus",
    "UnknownProfile",
]
