"""Every TARGET of every rule must be demonstrably matchable, not just every rule.

The standing audit, run one level below rule liveness. `test_rule_liveness.py` proves each
rule fires on *a* trigger; that leaves each rule's other targets unproven. A measurement
found 60 of 212 targets — 28% — had ever been matched. A mistyped target string (`subprocess.check_ouput`)
would sit in the rule set forever, matching nothing, and producing output identical to a
target that was checked and absent. That is the same failure this project keeps finding at
each new level, so it gets the same treatment.

Rather than hand-write 212 fixtures, a trigger is **generated per target** from the target's
own shape, and each must make its rule fire. A target that cannot be matched by a
straightforward use of itself is either mistyped or unreachable, and either way the rule set
is claiming coverage it does not have.
"""

from __future__ import annotations

import pytest

from trustlens.scanner.checks import python_surface as ps
from trustlens.scanner.pysource import parse_source

#: Extra keyword arguments needed to satisfy a rule's predicate, so a conditional rule can
#: be exercised on every one of its targets rather than only on the one hand-written trigger.
PREDICATE_ARGS: dict[str, str] = {
    "subprocess-shell-true": "shell=True",
    "torch-load-weights-only-false": "weights_only=False",
    "numpy-allow-pickle": "allow_pickle=True",
    "keras-safe-mode-false": "safe_mode=False",
    "archive-extraction-fully-trusted": "filter='fully_trusted'",
    "open-for-write": "'w'",
    # yaml-unsafe-load and archive-extraction-unfiltered fire on the ABSENCE of an
    # argument, so they need none added.
}

#: Targets excluded from generated coverage, each with a reason. An entry here is a
#: deliberate, stated gap rather than a silent one.
EXCLUDED_TARGETS: dict[str, str] = {
    # A method name on an arbitrary object; `import extractall` is not a thing. These are
    # exercised through the chained-call path in the hand-written liveness triggers.
    "extractall": "bare method name, exercised via tarfile.open(...).extractall()",
    "extract": "bare method name, exercised via the chained-call path",
    "bind": "bare method name on an arbitrary socket object",
    "listen": "bare method name on an arbitrary socket object",
    "write_text": "bare method name on an arbitrary Path object",
    "write_bytes": "bare method name on an arbitrary Path object",
    "unlink": "bare method name on an arbitrary Path object",
    "add_safe_globals": "bare method name, exercised via torch.serialization.add_safe_globals",
    "load_model": "bare function name, exercised via keras.models.load_model",
    "setup": "bare function name, exercised via setuptools.setup",
    "environ": "bare name, exercised via os.environ",
    "hf_hub_download": "bare function name, exercised via huggingface_hub.hf_hub_download",
    "snapshot_download": "bare function name, exercised via huggingface_hub.snapshot_download",
    "open": "builtin, exercised via the un-prefixed form",
    "eval": "builtin, exercised un-prefixed",
    "exec": "builtin, exercised un-prefixed",
    "compile": "builtin, exercised un-prefixed",
    "__import__": "builtin, exercised un-prefixed",
    "DefaultAzureCredential": "bare class name, exercised via azure.identity.DefaultAzureCredential",
    "load_incluster_config": "bare function name, exercised via kubernetes.config.*",
    "np.load": "conventional alias, exercised via the numpy.load form",
    "pd.read_pickle": "conventional alias, exercised via pandas.read_pickle",
    "torch.load.add_safe_globals": "not a real API path; retained defensively, cannot be exercised",
}


def _call_source(target: str, extra: str) -> str | None:
    """Build a minimal module that calls `target`, or None if it cannot be expressed."""
    if "." not in target:
        return f"def f(a):\n    return {target}(a{', ' + extra if extra else ''})\n"
    module, _, attr = target.rpartition(".")
    args = "a" + (", " + extra if extra else "")
    return f"import {module}\ndef f(a):\n    return {module}.{attr}({args})\n"


def _cases():
    out = []
    for rule in ps.RULES:
        for target in sorted(rule.targets):
            if target in EXCLUDED_TARGETS:
                continue
            out.append(pytest.param(rule.rule_id, target, id=f"{rule.rule_id}::{target}"))
    return out


@pytest.mark.parametrize("rule_id,target", _cases())
def test_every_target_is_matchable(rule_id, target):
    rule = next(r for r in ps.RULES if r.rule_id == rule_id)

    if rule.kind == "string":
        source = f"X = {target!r}\n"
    elif rule.kind == "subscript":
        module, _, attr = target.rpartition(".")
        source = (
            f"import {module}\ndef f():\n    return {module}.{attr}['HOME']\n"
            if module
            else f"def f(d):\n    return {target}['HOME']\n"
        )
    else:
        source = _call_source(target, PREDICATE_ARGS.get(rule_id, ""))

    assert source is not None
    pf = parse_source(source, "gen.py")
    assert pf.ok, f"generated trigger for {target} does not parse: {pf.failed_item}"

    fired = {h.rule.rule_id for h in ps.scan_file(pf)}
    assert rule_id in fired, (
        f"target {target!r} of rule {rule_id} did not match a straightforward use of "
        f"itself. Either the target string is wrong, or the rule cannot reach it.\n"
        f"Generated source:\n{source}\nRules that fired instead: {sorted(fired)}"
    )


def test_excluded_targets_are_all_real_targets():
    """An exclusion for a target that no longer exists means the list has gone stale."""
    all_targets = {t for r in ps.RULES for t in r.targets}
    orphans = set(EXCLUDED_TARGETS) - all_targets
    assert not orphans, f"exclusions for non-existent targets: {sorted(orphans)}"


def test_exclusions_are_a_small_and_stated_minority():
    """Exclusions must stay the exception. A growing list would hollow out the check."""
    all_targets = {t for r in ps.RULES for t in r.targets}
    ratio = len(EXCLUDED_TARGETS) / len(all_targets)
    assert ratio < 0.20, (
        f"{len(EXCLUDED_TARGETS)}/{len(all_targets)} targets excluded from coverage "
        f"({ratio:.0%}); the check is being hollowed out"
    )
    for target, reason in EXCLUDED_TARGETS.items():
        assert reason.strip(), f"{target} is excluded with no stated reason"


# ---------------------------------------------- the security-relevant string rules

@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",       # AWS / Azure / GCP IMDS, IPv4
        "fd00:ec2::254",         # AWS IMDS over IPv6
        "metadata.google.internal",  # GCP
        "169.254.170.2",         # ECS task metadata
        "100.100.100.200",       # Alibaba Cloud
        "192.0.0.192",           # Oracle Cloud
    ],
)
def test_every_metadata_endpoint_form_is_detected(address):
    """The brief asks for IPv4, IPv6 and provider-specific forms explicitly.

    Only the IPv4 address had ever been exercised before this test existed.
    """
    pf = parse_source(f"URL = 'http://{address}/latest/meta-data/'\n", "gen.py")
    fired = {h.rule.rule_id for h in ps.scan_file(pf)}
    assert "cloud-metadata-endpoint" in fired, f"{address} is not detected"


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd", "/etc/shadow", ".ssh/id_rsa", ".ssh/id_ed25519",
        "/proc/self/environ", ".netrc", ".git-credentials", ".npmrc", ".pypirc",
    ],
)
def test_every_sensitive_path_form_is_detected(path):
    pf = parse_source(f"P = {path!r}\n", "gen.py")
    fired = {h.rule.rule_id for h in ps.scan_file(pf)}
    assert "sensitive-path-literal" in fired, f"{path} is not detected"


@pytest.mark.parametrize(
    "command",
    ["pip install x", "pip3 install x", "conda install x", "apt-get install x",
     "apt install x", "npm install x", "uv pip install x", "poetry add x"],
)
def test_every_install_command_form_is_detected(command):
    pf = parse_source(f"CMD = {command!r}\n", "gen.py")
    fired = {h.rule.rule_id for h in ps.scan_file(pf)}
    assert "package-install-command" in fired, f"{command!r} is not detected"
