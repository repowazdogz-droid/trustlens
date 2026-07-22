"""Optional integration with the `trustlens-rbac` Go helper.

Built to `docs/SPEC_external_analyser_integration.md`, which the placement decision of
2026-07-22 fixed:

* **Out of the core path.** Nothing in `trustlens scan` or `trustlens map-credentials`
  imports or calls this module. It is reached only from the `trustlens rbac` subcommand.
* **Optional.** If the binary is absent, the capabilities it would have covered are
  reported `UNSUPPORTED` with the reason recorded — never a clean result, and never a
  failed run. The clean-clone property is preserved: the evidence model verifies with no Go
  toolchain present.
* **Allowlisted binary, resolved not inherited.** Only a binary named `trustlens-rbac` is
  ever executed, resolved from an explicit search order rather than trusted from `PATH` at
  call time.
* **Version recorded from the tool**, never assumed.
* **Exit code and stderr are evidence**, both captured. Exit 1 means some manifest failed
  to parse, which maps to `scope.failed` and therefore `PARTIAL` — not a clean result.
* **Scope stays TrustLens's own.** The helper's view of what it analysed contributes to
  findings and failures; it does not become TrustLens's scope on its own authority.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

BINARY_NAME = "trustlens-rbac"
TIMEOUT_SECONDS = 120

#: Capabilities this helper reports on when it is available.
HELPER_CAPABILITIES = ("k8s.api_access", "k8s.serviceaccount_token_access")


@dataclass
class HelperResult:
    available: bool
    binary_path: str | None
    version: str | None
    version_source: str
    exit_code: int | None = None
    stderr: str = ""
    decisions: list[dict] = field(default_factory=list)
    analysed: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)
    kubernetes_module: str | None = None
    unavailable_reason: str | None = None


def resolve_binary(explicit: str | None = None) -> str | None:
    """Find the helper. Only ever resolves a binary of the allowlisted name.

    An EXPLICIT path never falls back. If a caller names a binary and it does not resolve,
    the answer is "not found" — silently running a different binary than the one asked for
    is the same silent-substitution failure as an explicitly requested git ref falling back
    to HEAD, which this project already fixed once in `scanner/acquire.py`.
    """
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file() and os.access(candidate, os.X_OK) and candidate.name == BINARY_NAME:
            return str(candidate)
        return None

    candidates: list[Path] = []
    env = os.environ.get("TRUSTLENS_RBAC_BIN")
    if env:
        candidates.append(Path(env))
    candidates.append(Path(__file__).resolve().parents[2] / "go" / "rbac" / BINARY_NAME)
    found = shutil.which(BINARY_NAME)
    if found:
        candidates.append(Path(found))

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            if candidate.name != BINARY_NAME:
                # Refuse to execute anything not carrying the allowlisted name, even if a
                # caller pointed at it explicitly.
                continue
            return str(candidate)
    return None


def _version(binary: str) -> tuple[str | None, str]:
    """Read the version from the tool itself, or record that it could not be read."""
    try:
        proc = subprocess.run(
            [binary, "--help"], capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.SubprocessError):
        return None, "unknown"
    # The helper prints its version in its JSON output; --help is only used to confirm the
    # binary responds. A version that cannot be established is recorded as unknown rather
    # than guessed.
    if proc.returncode in (0, 2):
        return None, "reported_by_tool"
    return None, "unknown"


def run_helper(manifest_dir: Path, *, binary: str | None = None) -> HelperResult:
    """Invoke the helper if present. Absence is a recorded state, not an error."""
    resolved = resolve_binary(binary)
    if resolved is None:
        return HelperResult(
            available=False,
            binary_path=None,
            version=None,
            version_source="unknown",
            unavailable_reason=(
                f"the optional {BINARY_NAME} helper was not found. Build it with "
                "`cd go/rbac && go build -o trustlens-rbac .`, or set TRUSTLENS_RBAC_BIN. "
                "Its absence makes the capabilities it covers UNSUPPORTED; it does not make "
                "them clean."
            ),
        )

    try:
        proc = subprocess.run(
            [resolved, "--dir", str(manifest_dir)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return HelperResult(
            available=False,
            binary_path=resolved,
            version=None,
            version_source="unknown",
            unavailable_reason=f"{BINARY_NAME} timed out after {TIMEOUT_SECONDS}s",
        )
    except OSError as exc:
        return HelperResult(
            available=False,
            binary_path=resolved,
            version=None,
            version_source="unknown",
            unavailable_reason=f"{BINARY_NAME} could not be executed: {exc}",
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return HelperResult(
            available=False,
            binary_path=resolved,
            version=None,
            version_source="unknown",
            exit_code=proc.returncode,
            stderr=proc.stderr[:2000],
            unavailable_reason=(
                f"{BINARY_NAME} exit {proc.returncode} produced unparseable output: {exc}. "
                "Its result is discarded rather than partially trusted."
            ),
        )

    return HelperResult(
        available=True,
        binary_path=resolved,
        version=payload.get("tool_version"),
        version_source="reported_by_tool",
        exit_code=proc.returncode,
        stderr=proc.stderr[:2000],
        decisions=payload.get("decisions") or [],
        analysed=payload.get("analysed") or [],
        failed=payload.get("failed") or [],
        service_accounts=payload.get("service_accounts") or [],
        kubernetes_module=payload.get("kubernetes_module_version"),
    )


def external_tool_block(result: HelperResult, manifest_dir: Path) -> list[dict]:
    """The `tool.external_tools[]` entry, with the version actually executed."""
    if not result.available or not result.binary_path:
        return []
    return [
        {
            "name": BINARY_NAME,
            "version": result.version or "unknown",
            "invocation": f"{result.binary_path} --dir {manifest_dir}",
            "version_source": result.version_source if result.version else "unknown",
        }
    ]
