"""Every rule must be demonstrably capable of firing. No dead rules.

This is the standing form of the `env.credential_pattern_read` lesson. That bug was found
by accident: a capability that could never be reported looked exactly like a capability
that was reported clean. The same hazard exists one level down. Findings are emitted per
**capability**, but template-injection has 7 detectors behind 3 capabilities and
python_surface has 43 rules behind 26 capabilities. A rule with a broken pattern, an
unreachable target set, or a predicate that can never be true produces output *identical*
to a rule that ran correctly and matched nothing.

An audit found 13 rules that no fixture had ever exercised. Their ability to fire was
unproven — not wrong, but unproven, which is the state this file exists to eliminate.

The mechanism is a trigger table: every rule must have a minimal input that makes it fire.
`test_every_rule_has_a_trigger` fails when a rule is added without one, so this stays a
standing check rather than a one-off sweep.
"""

from __future__ import annotations

import pytest

from trustlens.scanner.checks import python_surface as ps
from trustlens.scanner.checks import template_injection as ti
from trustlens.scanner.pysource import parse_source

#: rule_id -> a minimal Python source that must make exactly that rule fire.
PYTHON_SURFACE_TRIGGERS: dict[str, str] = {
    # --- dynamic execution
    "exec-eval-builtin": "def f(s): return eval(s)\n",
    "dynamic-import": "import importlib\ndef f(n): return importlib.import_module(n)\n",
    "code-object-construction": "import types\ndef f(c, g): return types.FunctionType(c, g)\n",
    # --- process / shell
    "subprocess-invocation": "import subprocess\ndef f(c): subprocess.run(c)\n",
    "subprocess-shell-true": "import subprocess\ndef f(c): subprocess.run(c, shell=True)\n",
    "os-shell-exec": "import os\ndef f(c): os.system(c)\n",
    # --- deserialization
    "pickle-load": "import pickle\ndef f(b): return pickle.loads(b)\n",
    "marshal-load": "import marshal\ndef f(b): return marshal.loads(b)\n",
    "yaml-unsafe-load": "import yaml\ndef f(t): return yaml.load(t)\n",
    "yaml-unsafe-api": "import yaml\ndef f(t): return yaml.unsafe_load(t)\n",
    "torch-load-weights-only-false": (
        "import torch\ndef f(p): return torch.load(p, weights_only=False)\n"
    ),
    "torch-safe-globals-widening": (
        "import torch\ndef f(g): torch.serialization.add_safe_globals(g)\n"
    ),
    "numpy-allow-pickle": "import numpy\ndef f(p): return numpy.load(p, allow_pickle=True)\n",
    "keras-safe-mode-false": (
        "import keras\ndef f(p): return keras.models.load_model(p, safe_mode=False)\n"
    ),
    # --- network
    "http-client": "import requests\ndef f(u): return requests.get(u)\n",
    "raw-socket": "import socket\ndef f(): return socket.socket()\n",
    "socket-listen": "def f(s): s.listen(5)\n",
    "dns-lookup": "import socket\ndef f(h): return socket.gethostbyname(h)\n",
    "legacy-network-protocol": "import ftplib\ndef f(h): return ftplib.FTP(h)\n",
    "remote-artifact-fetch": (
        "import huggingface_hub\ndef f(r): return huggingface_hub.hf_hub_download(r)\n"
    ),
    # --- environment
    "env-named-read": "import os\ndef f(): return os.getenv('HOME')\n",
    "env-enumeration": "import os\ndef f(): return os.environ.copy()\n",
    "env-subscript": "import os\ndef f(): return os.environ['HOME']\n",
    "env-inherited-by-subprocess": "import os\ndef f(p, a, e): os.execve(p, a, e)\n",
    # --- cloud / orchestration
    "cloud-metadata-endpoint": "URL = 'http://169.254.169.254/latest/meta-data/'\n",
    "k8s-serviceaccount-path": "P = '/var/run/secrets/kubernetes.io/serviceaccount/token'\n",
    "docker-socket-path": "P = '/var/run/docker.sock'\n",
    "cloud-credential-file": "P = '~/.aws/credentials'\n",
    "cloud-sdk-credential-discovery": "import boto3\ndef f(): return boto3.Session()\n",
    "k8s-api-client": (
        "import kubernetes\ndef f(): kubernetes.config.load_incluster_config()\n"
    ),
    "docker-client": "import docker\ndef f(): return docker.from_env()\n",
    # --- filesystem
    "open-for-write": "def f(p): return open(p, 'w')\n",
    "path-write": "import shutil\ndef f(a, b): shutil.copy(a, b)\n",
    "filesystem-delete": "import os\ndef f(p): os.remove(p)\n",
    "permission-change": "import os\ndef f(p): os.chmod(p, 0o777)\n",
    "archive-extraction-unfiltered": (
        "import tarfile\ndef f(s, d): tarfile.open(s).extractall(d)\n"
    ),
    "archive-extraction-fully-trusted": (
        "import tarfile\ndef f(s, d): tarfile.open(s).extractall(d, filter='fully_trusted')\n"
    ),
    "archive-open": "import tarfile\ndef f(s): return tarfile.open(s)\n",
    "sensitive-path-literal": "P = '/etc/passwd'\n",
    "path-traversal-literal": "P = '../../etc/hosts'\n",
    # --- package / build
    "package-install-command": "CMD = 'pip install requests'\n",
    "pip-internal-api": "import pip\ndef f(a): pip.main(a)\n",
    "setuptools-build-hook": "import setuptools\nsetuptools.setup(name='x')\n",
}

#: detector rule_id -> a config VALUE that must make that detector fire.
TEMPLATE_TRIGGERS: dict[str, str] = {
    "ssti-gadget": "{{ cycler.__init__.__globals__ }}",
    "resolver-eval": "${eval:1+1}",
    "jinja-block": "{% for x in y %}{% endfor %}",
    "jinja-expression": "{{ name }}",
    "resolver-env": "${oc.env:HOME}",
    "shell-substitution": "$(whoami)",
    # yaml-python-tag is driven from tag sightings rather than scalar text, and has its own
    # dedicated control in test_template_injection.py.
}

_TAG_DRIVEN = {"yaml-python-tag"}


# ------------------------------------------------------------------ the standing check

def test_every_python_surface_rule_has_a_trigger():
    """A new rule without a trigger fails here, which is what makes this standing."""
    missing = {r.rule_id for r in ps.RULES} - set(PYTHON_SURFACE_TRIGGERS)
    assert not missing, (
        f"rules with no liveness trigger: {sorted(missing)}. Every rule must have a "
        "minimal input proving it can fire; otherwise a dead rule is indistinguishable "
        "from one that ran and matched nothing."
    )


def test_every_template_detector_has_a_trigger():
    missing = {d.rule_id for d in ti.DETECTORS} - set(TEMPLATE_TRIGGERS) - _TAG_DRIVEN
    assert not missing, f"detectors with no liveness trigger: {sorted(missing)}"


def test_no_orphan_triggers():
    """A trigger for a rule that no longer exists means the table has gone stale."""
    orphans = set(PYTHON_SURFACE_TRIGGERS) - {r.rule_id for r in ps.RULES}
    assert not orphans, f"triggers for non-existent rules: {sorted(orphans)}"
    orphans_t = set(TEMPLATE_TRIGGERS) - {d.rule_id for d in ti.DETECTORS}
    assert not orphans_t, f"triggers for non-existent detectors: {sorted(orphans_t)}"


# ------------------------------------------------------------------ liveness proofs

@pytest.mark.parametrize("rule_id", sorted(PYTHON_SURFACE_TRIGGERS))
def test_python_surface_rule_actually_fires(rule_id):
    source = PYTHON_SURFACE_TRIGGERS[rule_id]
    pf = parse_source(source, "trigger.py")
    assert pf.ok, f"the trigger for {rule_id} does not parse: {pf.failed_item}"
    fired = {h.rule.rule_id for h in ps.scan_file(pf)}
    assert rule_id in fired, (
        f"rule {rule_id} did not fire on its own trigger:\n{source}\nfired instead: {sorted(fired)}"
    )


@pytest.mark.parametrize("rule_id", sorted(TEMPLATE_TRIGGERS))
def test_template_detector_actually_fires(rule_id):
    from trustlens.scanner.config_parse import ScalarValue

    value = TEMPLATE_TRIGGERS[rule_id]
    matches, _ = ti.scan_value("cfg.yaml", ScalarValue(pointer="/k", value=value, line=1))
    fired = {m.detector.rule_id for m in matches}
    assert rule_id in fired, (
        f"detector {rule_id} did not fire on its own trigger {value!r}; fired: {sorted(fired)}"
    )


# ------------------------------------------------- the finding must name what ran

def test_finding_records_the_rules_that_were_evaluated():
    """A reader must be able to tell which rules ran, not only which fired.

    Without this, a capability reporting clean gives no way to distinguish "12 rules ran
    and matched nothing" from "the rule set for this capability is empty".
    """
    from pathlib import Path

    result = ps.run(Path("examples/repos/clean_tabular"))
    for finding in result.findings:
        basis = finding["confidence_basis"]
        assert "rule(s)" in basis, f"{finding['capability']} does not state its rule count"


def test_clean_finding_states_a_nonzero_rule_count():
    from pathlib import Path
    import re

    result = ps.run(Path("examples/repos/clean_tabular"))
    for finding in result.findings:
        if finding["status"] != "NOT_FOUND_WITHIN_ANALYSED_SCOPE":
            continue
        match = re.search(r"any of the (\d+) rule\(s\)", finding["confidence_basis"])
        assert match, f"{finding['capability']}: clean basis does not state how many rules ran"
        assert int(match.group(1)) > 0, (
            f"{finding['capability']} reports clean with ZERO rules — that is 'not checked', "
            "not 'checked and found nothing'"
        )


def test_template_clean_findings_state_their_detector_count():
    """Same standing check applied to the template family.

    A clean result must say how many detectors were evaluated. Stating only the file count
    leaves 'seven detectors ran and matched nothing' indistinguishable from 'no detectors
    exist for this capability'.
    """
    from pathlib import Path
    import re

    result = ti.run(Path("examples/repos/clean_tabular"))
    for finding in result.findings:
        assert finding["status"] == "NOT_FOUND_WITHIN_ANALYSED_SCOPE"
        match = re.search(r"(\d+)[^.]{0,40}?detector\(s\)", finding["confidence_basis"])
        assert match, (
            f"{finding['capability']}: clean basis states no detector count — "
            f"{finding['confidence_basis']!r}"
        )
        assert int(match.group(1)) > 0, f"{finding['capability']} reports clean with 0 detectors"
