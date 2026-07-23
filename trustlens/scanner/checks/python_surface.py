"""Rule-driven static checks over Python source.

One tree walk, many independent rules. Each rule states its own invariant and its own
blind spot, and findings are never collapsed into a score — the brief requires each check
to remain separately visible, and a reader must be able to see which rule fired and why.

Rules resolve through the file's import alias map, so `import subprocess as sp` followed by
`sp.Popen(..., shell=True)` matches. Renaming an import would otherwise be a one-line
bypass of every rule in this file, and the planted-case controls exercise exactly that.

Families implemented here, from the Phase 1 scope:

* 2 — dynamic execution
* 3 — process and shell invocation
* 6 — dangerous deserialization

Remaining families are added as further rule sets against the same engine.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ...evidence import make_evidence, make_finding, make_scope
from ..config_parse import iter_config_files, parse_config
from ..pysource import (
    PythonFile,
    call_names,
    call_suffix,
    dotted_name,
    is_literal_false,
    is_literal_true,
    keyword_of,
    load_python_files,
    resolve,
)

RULE_VERSION = "0.1.0"

Predicate = Callable[[ast.Call, dict], bool]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    family: str
    capability: str
    targets: frozenset[str]
    what: str
    blind_spot: str
    escalated: bool = False
    predicate: Predicate | None = None
    #: When set, the rule only fires if the predicate is TRUE; otherwise a call to a
    #: matching target with the predicate false is explicitly not a finding.
    predicate_note: str = ""
    #: "call"      — a call whose resolved callee is in `targets`
    #: "string"    — a string literal containing one of `targets` as a substring
    #: "subscript" — an index into a resolved name in `targets`, e.g. os.environ[...]
    kind: str = "call"
    #: When True (default), a bare target also matches the *last segment* of a qualified call,
    #: so `{"extractall"}` catches `x.extractall()`. This is the intended over-report for
    #: method-name rules (bind/listen, extractall/extract, write_text/unlink, setup).
    #: Set False for rules whose bare targets are BUILTINS (eval/exec/compile): a builtin must
    #: match an unqualified call only, never the suffix of an unrelated qualified call like
    #: `re.compile` / `df.eval` / `model.compile`. See study D1.
    match_suffix: bool = True


# --------------------------------------------------------------------------- predicates

def _shell_true(call: ast.Call, aliases: dict) -> bool:
    return is_literal_true(keyword_of(call, "shell"))


def _unsafe_yaml_loader(call: ast.Call, aliases: dict) -> bool:
    """yaml.load is unsafe unless an explicitly safe Loader is supplied."""
    loader = keyword_of(call, "Loader")
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    if loader is None:
        return True  # no Loader at all: the historically unsafe default
    name = resolve(dotted_name(loader), aliases).rsplit(".", 1)[-1]
    return name not in {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


def _weights_only_false(call: ast.Call, aliases: dict) -> bool:
    """Only an explicit weights_only=False is flagged.

    PyTorch changed the default to True, so an omitted argument is the safe modern case and
    flagging it would produce noise on every ordinary torch.load in the ecosystem. An
    artifact pinned to an old torch is a version question this check cannot see, and that
    is recorded as a gap in CLAIMS.md rather than guessed at.
    """
    return is_literal_false(keyword_of(call, "weights_only"))


def _allow_pickle_true(call: ast.Call, aliases: dict) -> bool:
    return is_literal_true(keyword_of(call, "allow_pickle"))


def _safe_mode_false(call: ast.Call, aliases: dict) -> bool:
    return is_literal_false(keyword_of(call, "safe_mode"))


# ------------------------------------------------------------------------------- rules

RULES: tuple[Rule, ...] = (
    # ---------------------------------------------------------------- family 2
    Rule(
        rule_id="exec-eval-builtin",
        family="dynamic_execution",
        capability="execution.dynamic_eval",
        targets=frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}),
        escalated=True,
        # Builtins only: match an unqualified eval()/exec()/compile() or the explicit
        # builtins.* form, NEVER the last segment of a qualified call. Without this,
        # re.compile / df.eval / model.compile all falsely matched execution.dynamic_eval
        # (a false positive on a FOUND). Regression: tests/scanner/test_exec_eval_builtin_fp.py.
        match_suffix=False,
        what="A builtin that executes or compiles code supplied at runtime",
        blind_spot=(
            "A call reached indirectly, e.g. through getattr(builtins, 'ev'+'al'), is not "
            "matched. Only a syntactically visible callee is. A builtin shadowed by a "
            "same-named method on another object is intentionally not matched (that is the "
            "fix for the re.compile false positive)."
        ),
    ),
    Rule(
        rule_id="dynamic-import",
        family="dynamic_execution",
        capability="execution.dynamic_import",
        targets=frozenset(
            {"__import__", "builtins.__import__", "importlib.import_module",
             "importlib.__import__", "importlib.util.spec_from_file_location"}
        ),
        what="A module imported by a name computed at runtime",
        blind_spot=(
            "The imported module name is not resolved. A constant import here is "
            "indistinguishable from an attacker-controlled one without dataflow."
        ),
    ),
    Rule(
        rule_id="code-object-construction",
        family="dynamic_execution",
        capability="execution.dynamic_eval",
        targets=frozenset({"types.FunctionType", "types.CodeType"}),
        escalated=True,
        what="Direct construction of a function or code object",
        blind_spot="Legitimate in metaprogramming libraries; rare in dataset or model code.",
    ),
    # ---------------------------------------------------------------- family 3
    Rule(
        rule_id="subprocess-invocation",
        family="process_shell",
        capability="process.subprocess",
        targets=frozenset(
            {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
             "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"}
        ),
        what="A child process is created",
        blind_spot=(
            "Does not establish that the command is attacker-controlled, nor that the call "
            "is reached at runtime."
        ),
    ),
    Rule(
        rule_id="subprocess-shell-true",
        family="process_shell",
        capability="process.shell",
        targets=frozenset(
            {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
             "subprocess.check_output"}
        ),
        escalated=True,
        predicate=_shell_true,
        predicate_note="only when shell=True is written literally",
        what="A child process is created through a shell, so the argument is a command line",
        blind_spot=(
            "shell=True passed via a variable or **kwargs is not matched; only a literal "
            "True is. A shell-less call that invokes /bin/sh explicitly is caught by the "
            "shell-binary rule instead."
        ),
    ),
    Rule(
        rule_id="os-shell-exec",
        family="process_shell",
        capability="process.shell",
        targets=frozenset({"os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
                           "os.spawnv", "os.spawnve", "pty.spawn"}),
        escalated=True,
        what="A shell or process is executed through the os module",
        blind_spot="Does not resolve the command string.",
    ),
    # ---------------------------------------------------------------- family 6
    Rule(
        rule_id="pickle-load",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset(
            {"pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
             "_pickle.load", "_pickle.loads", "dill.load", "dill.loads",
             "cloudpickle.load", "cloudpickle.loads", "joblib.load",
             "pandas.read_pickle", "pd.read_pickle", "shelve.open"}
        ),
        escalated=True,
        what="Deserialization that can construct arbitrary objects and execute code on load",
        blind_spot=(
            "Establishes the call site, not the trustworthiness of the data it reads. A "
            "pickle load of a file the repository itself ships is still arbitrary code."
        ),
    ),
    Rule(
        rule_id="marshal-load",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"marshal.load", "marshal.loads"}),
        escalated=True,
        what="marshal deserialization, which accepts code objects",
        blind_spot="Rare outside interpreter internals; presence is itself unusual.",
    ),
    Rule(
        rule_id="yaml-unsafe-load",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"yaml.load"}),
        escalated=True,
        predicate=_unsafe_yaml_loader,
        predicate_note="only when no Loader, or a non-safe Loader, is supplied",
        what="yaml.load without a safe Loader, which can construct arbitrary Python objects",
        blind_spot=(
            "A Loader passed through a variable is treated as unsafe, which may over-report. "
            "yaml.safe_load is never flagged."
        ),
    ),
    Rule(
        rule_id="yaml-unsafe-api",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"yaml.unsafe_load", "yaml.full_load", "yaml.unsafe_load_all", "yaml.full_load_all"}),
        escalated=True,
        what="A PyYAML entry point that permits arbitrary object construction",
        blind_spot="full_load is narrower than unsafe_load but still constructs Python objects.",
    ),
    Rule(
        rule_id="torch-load-weights-only-false",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"torch.load", "torch.serialization.load"}),
        escalated=True,
        predicate=_weights_only_false,
        predicate_note="only when weights_only=False is written literally",
        what="torch.load with the pickle guard explicitly disabled",
        blind_spot=(
            "An omitted weights_only is NOT flagged, because current PyTorch defaults it to "
            "True. An artifact pinned to an older torch would be unsafe and is not detected."
        ),
    ),
    Rule(
        rule_id="torch-safe-globals-widening",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"torch.serialization.add_safe_globals", "torch.load.add_safe_globals",
                           "add_safe_globals"}),
        what="The torch.load allowlist is widened, re-admitting types the guard excluded",
        blind_spot="Widening may be entirely legitimate; it is reported as surface, not fault.",
    ),
    Rule(
        rule_id="numpy-allow-pickle",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"numpy.load", "np.load"}),
        escalated=True,
        predicate=_allow_pickle_true,
        predicate_note="only when allow_pickle=True is written literally",
        what="numpy.load with pickle enabled, which deserializes arbitrary objects",
        blind_spot="allow_pickle defaults to False and an omitted argument is not flagged.",
    ),
    Rule(
        rule_id="keras-safe-mode-false",
        family="deserialization",
        capability="execution.deserialization",
        targets=frozenset({"keras.models.load_model", "keras.saving.load_model",
                           "tensorflow.keras.models.load_model", "load_model"}),
        escalated=True,
        predicate=_safe_mode_false,
        predicate_note="only when safe_mode=False is written literally",
        what="Keras model loading with unsafe lambda deserialization enabled",
        blind_spot=(
            "safe_mode defaults to True in Keras v3 and an omitted argument is not flagged. "
            "Lambda layers inside a .keras archive are a separate, unimplemented check."
        ),
    ),
)

#: Environment variable names whose value is credential-shaped. Matched against the KEY
#: only — TrustLens records the name of a variable and never its value.
CREDENTIAL_ENV_PATTERNS = (
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "APIKEY", "API_KEY", "PRIVATE_KEY",
    "ACCESS_KEY", "CREDENTIAL", "SESSION_TOKEN", "AUTH", "_PAT", "CLIENT_SECRET",
)


def _env_key_is_credential_shaped(key: str) -> bool:
    upper = key.upper()
    return any(pattern in upper for pattern in CREDENTIAL_ENV_PATTERNS)


NETWORK_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="http-client",
        family="network",
        capability="network.outbound",
        targets=frozenset(
            {"urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request",
             "requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
             "requests.patch", "requests.request", "requests.Session",
             "httpx.get", "httpx.post", "httpx.stream", "httpx.Client", "httpx.AsyncClient",
             "http.client.HTTPConnection", "http.client.HTTPSConnection",
             "urllib3.PoolManager", "aiohttp.ClientSession"}
        ),
        what="An outbound HTTP request is issued",
        blind_spot=(
            "The destination is not resolved. A constant URL to a well-known host and an "
            "attacker-controlled one are indistinguishable without dataflow."
        ),
    ),
    Rule(
        rule_id="raw-socket",
        family="network",
        capability="network.outbound",
        targets=frozenset({"socket.socket", "socket.create_connection", "ssl.wrap_socket"}),
        what="A raw network socket is created",
        blind_spot="A socket used only to listen is reported here as well; see network.listen.",
    ),
    Rule(
        rule_id="socket-listen",
        family="network",
        capability="network.listen",
        targets=frozenset({"bind", "listen"}),
        what="A socket is bound or placed in listening state",
        blind_spot=(
            "Matched on the bare method name, so any object with a bind() or listen() "
            "method matches. This rule over-reports by design and is not escalated."
        ),
    ),
    Rule(
        rule_id="dns-lookup",
        family="network",
        capability="network.dns",
        targets=frozenset(
            {"socket.gethostbyname", "socket.getaddrinfo", "socket.gethostbyaddr"}
        ),
        what="A DNS lookup is performed",
        blind_spot="Name resolution alone does not establish that a connection follows.",
    ),
    Rule(
        rule_id="legacy-network-protocol",
        family="network",
        capability="network.outbound",
        targets=frozenset({"ftplib.FTP", "telnetlib.Telnet", "smtplib.SMTP", "paramiko.SSHClient"}),
        what="A non-HTTP network client is created",
        blind_spot="Presence in ML dataset code is unusual and is reported as surface.",
    ),
    Rule(
        rule_id="remote-artifact-fetch",
        family="network",
        capability="network.package_fetch",
        targets=frozenset(
            {"huggingface_hub.hf_hub_download", "huggingface_hub.snapshot_download",
             "hf_hub_download", "snapshot_download",
             "torch.hub.load", "torch.hub.load_state_dict_from_url",
             "torch.utils.model_zoo.load_url", "gdown.download", "wget.download"}
        ),
        what="A remote artifact is downloaded at runtime",
        blind_spot=(
            "Does not check whether the download is pinned to an immutable revision; "
            "Bandit's B615 covers the unpinned Hugging Face case and is integrated separately."
        ),
    ),
)


ENVIRONMENT_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="env-named-read",
        family="environment",
        capability="env.named_read",
        targets=frozenset({"os.getenv", "os.environ.get", "environ.get"}),
        what="A named environment variable is read",
        blind_spot="The variable name is not resolved when it is computed at runtime.",
    ),
    Rule(
        rule_id="env-enumeration",
        family="environment",
        capability="env.enumeration",
        targets=frozenset(
            {"os.environ.keys", "os.environ.items", "os.environ.values", "os.environ.copy",
             "environ.keys", "environ.items", "environ.copy"}
        ),
        escalated=True,
        what="The whole process environment is enumerated rather than a named variable read",
        blind_spot=(
            "dict(os.environ) and {**os.environ} are separate constructs; the first is "
            "matched by the subscript rule set, the second is a known miss."
        ),
    ),
    Rule(
        rule_id="env-subscript",
        family="environment",
        capability="env.named_read",
        kind="subscript",
        targets=frozenset({"os.environ", "environ"}),
        what="A named environment variable is read by subscript",
        blind_spot="A computed key is recorded as a read without the name.",
    ),
    Rule(
        rule_id="env-inherited-by-subprocess",
        family="environment",
        capability="env.enumeration",
        targets=frozenset({"os.execve", "os.spawnve", "os.putenv"}),
        what="The process environment is passed to or modified for a child process",
        blind_spot="subprocess calls inherit the environment implicitly and are not matched here.",
    ),
)


CLOUD_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="cloud-metadata-endpoint",
        family="cloud",
        capability="cloud.metadata_endpoint",
        kind="string",
        targets=frozenset(
            {
                "169.254.169.254",          # AWS / Azure / GCP IMDS
                "metadata.google.internal",  # GCP
                "metadata.goog",             # GCP alternate
                "fd00:ec2::254",             # AWS IMDS over IPv6
                "169.254.170.2",             # ECS task metadata
                "100.100.100.200",           # Alibaba Cloud
                "192.0.0.192",               # Oracle Cloud
            }
        ),
        escalated=True,
        what="A cloud instance metadata endpoint address appears as a literal",
        blind_spot=(
            "An address assembled at runtime, or reached via a redirect or a hostname not "
            "in this list, is not matched. Documentation quoting the address also matches."
        ),
    ),
    Rule(
        rule_id="k8s-serviceaccount-path",
        family="cloud",
        capability="k8s.serviceaccount_token_access",
        kind="string",
        targets=frozenset({"/var/run/secrets/kubernetes.io/serviceaccount"}),
        escalated=True,
        what="The in-cluster service-account token mount path appears as a literal",
        blind_spot="Reading the path does not establish that the token is used against the API.",
    ),
    Rule(
        rule_id="docker-socket-path",
        family="cloud",
        capability="container.docker_socket",
        kind="string",
        targets=frozenset({"/var/run/docker.sock", "docker.sock"}),
        escalated=True,
        what="The Docker daemon socket path appears as a literal",
        blind_spot="Access to this socket is generally equivalent to host root; presence is surface.",
    ),
    Rule(
        rule_id="cloud-credential-file",
        family="cloud",
        capability="cloud.credential_file_access",
        kind="string",
        targets=frozenset(
            {".aws/credentials", ".aws/config", ".config/gcloud", ".azure/credentials",
             ".kube/config", "gcloud/application_default_credentials.json"}
        ),
        escalated=True,
        what="A well-known cloud or cluster credential file path appears as a literal",
        blind_spot="Presence of the path does not establish that the file is read.",
    ),
    Rule(
        rule_id="cloud-sdk-credential-discovery",
        family="cloud",
        capability="cloud.sdk_credential_discovery",
        targets=frozenset(
            {"boto3.Session", "boto3.client", "boto3.resource", "botocore.session.get_session",
             "google.auth.default", "azure.identity.DefaultAzureCredential",
             "DefaultAzureCredential"}
        ),
        what="A cloud SDK entry point that discovers ambient credentials is constructed",
        blind_spot=(
            "Credential discovery is implicit in these SDKs; this reports the entry point, "
            "not a specific credential source."
        ),
    ),
    Rule(
        rule_id="k8s-api-client",
        family="cloud",
        capability="k8s.api_access",
        targets=frozenset(
            {"kubernetes.config.load_incluster_config", "kubernetes.config.load_kube_config",
             "load_incluster_config", "kubernetes.client.CoreV1Api"}
        ),
        escalated=True,
        what="A Kubernetes API client is configured",
        blind_spot="Does not establish which API operations are attempted or permitted.",
    ),
    Rule(
        rule_id="docker-client",
        family="cloud",
        capability="container.docker_socket",
        targets=frozenset({"docker.from_env", "docker.DockerClient"}),
        escalated=True,
        what="A Docker client is constructed, which reaches the daemon socket",
        blind_spot="Does not establish that the daemon is reachable in the target environment.",
    ),
)


#: Named extraction filters that constrain member paths. `data` is the strict filter that
#: became the default in Python 3.14; `tar` is looser but still rejects absolute paths.
#: Verified from the tarfile documentation, retrieved 2026-07-22.
SAFE_EXTRACTION_FILTERS = frozenset({"data", "tar"})


def _extraction_filter_literal(call: ast.Call) -> str | None:
    node = keyword_of(call, "filter")
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _no_extraction_filter(call: ast.Call, aliases: dict) -> bool:
    """Fire only when no filter argument is supplied at all.

    An explicit filter='data' or filter='tar' is the documented way to get constrained
    extraction on every Python version, so flagging it would fire on code that has already
    done the right thing — the fastest way to lose a user's trust in a scanner. An explicit
    filter='fully_trusted' is handled by its own escalated rule, so it is excluded here to
    avoid reporting one call twice. A filter supplied through a variable is not evaluated
    and is NOT flagged, because the finding's own wording ("without an explicit extraction
    filter") would otherwise be false; that is a recorded miss rather than a silent one.
    """
    return keyword_of(call, "filter") is None


def _fully_trusted_filter(call: ast.Call, aliases: dict) -> bool:
    return _extraction_filter_literal(call) == "fully_trusted"


def _write_mode(call: ast.Call, aliases: dict) -> bool:
    """open() is a write only when its mode says so. Reading is not a finding."""
    mode = keyword_of(call, "mode")
    if mode is None and len(call.args) >= 2:
        mode = call.args[1]
    if mode is None:
        return False  # default mode is 'r'
    if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str):
        return False  # computed mode: not claimed either way
    return any(ch in mode.value for ch in "wax+")


FILESYSTEM_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="open-for-write",
        family="filesystem",
        capability="filesystem.write",
        targets=frozenset({"open", "builtins.open", "io.open", "codecs.open"}),
        predicate=_write_mode,
        predicate_note="only when a literal mode containing w, a, x or + is supplied",
        what="A file is opened for writing",
        blind_spot=(
            "A computed mode string is not claimed in either direction, so open(p, m) with "
            "a variable mode is not reported as a write."
        ),
    ),
    Rule(
        rule_id="path-write",
        family="filesystem",
        capability="filesystem.write",
        targets=frozenset({"write_text", "write_bytes", "shutil.copy", "shutil.copy2",
                           "shutil.copyfile", "shutil.copytree", "shutil.move", "os.rename",
                           "os.replace", "os.makedirs", "os.mkdir"}),
        what="A filesystem write, copy or directory creation",
        blind_spot=(
            "write_text and write_bytes are matched on the bare method name, so any object "
            "exposing them matches. Over-reports by design."
        ),
    ),
    Rule(
        rule_id="filesystem-delete",
        family="filesystem",
        capability="filesystem.delete",
        targets=frozenset({"os.remove", "os.unlink", "os.rmdir", "os.removedirs",
                           "shutil.rmtree", "unlink"}),
        escalated=True,
        what="A file or directory is deleted",
        blind_spot="Deletion of a temporary file the code itself created is equally matched.",
    ),
    Rule(
        rule_id="permission-change",
        family="filesystem",
        capability="filesystem.permission_change",
        targets=frozenset({"os.chmod", "os.chown", "os.lchown", "os.fchmod"}),
        escalated=True,
        what="File permissions or ownership are changed",
        blind_spot="Does not resolve the target path or the resulting mode.",
    ),
    Rule(
        rule_id="archive-extraction-unfiltered",
        family="filesystem",
        capability="filesystem.archive_extraction",
        targets=frozenset({"extractall", "extract", "shutil.unpack_archive"}),
        predicate=_no_extraction_filter,
        predicate_note=(
            "only when no filter= is supplied; an explicit filter='data' or 'tar' is not flagged"
        ),
        what=(
            "An archive is extracted without an explicit extraction filter, so whether "
            "member paths are constrained depends on the consuming Python version"
        ),
        blind_spot=(
            "Python 3.14 changed the default extraction filter to 'data'; 3.13 and earlier "
            "defaulted to the equivalent of 'fully_trusted'. The consuming Python version "
            "is NOT visible in the artifact, so this finding does not assert which applies. "
            "A filter supplied through a variable is not evaluated and is not flagged; "
            "that is a recorded miss."
        ),
    ),
    Rule(
        rule_id="archive-extraction-fully-trusted",
        family="filesystem",
        capability="filesystem.archive_extraction",
        targets=frozenset({"extractall", "extract", "shutil.unpack_archive"}),
        escalated=True,
        predicate=_fully_trusted_filter,
        predicate_note="only when filter='fully_trusted' is written literally",
        what=(
            "An archive is extracted with the filter explicitly set to fully_trusted, "
            "which permits absolute paths and paths outside the destination"
        ),
        blind_spot=(
            "Legitimate where the archive is genuinely trusted; the point is that the "
            "choice was made explicitly and is visible."
        ),
    ),
    Rule(
        rule_id="archive-open",
        family="filesystem",
        capability="filesystem.archive_extraction",
        targets=frozenset({"tarfile.open", "zipfile.ZipFile"}),
        what="An archive is opened (listing or reading members is not extraction)",
        blind_spot=(
            "Opening an archive is not extracting it. Reported as surface only, and "
            "deliberately not escalated, because inspecting an archive is routine."
        ),
    ),
    Rule(
        rule_id="sensitive-path-literal",
        family="filesystem",
        capability="filesystem.read_sensitive_path",
        kind="string",
        targets=frozenset(
            {"/etc/passwd", "/etc/shadow", ".ssh/id_rsa", ".ssh/id_ed25519",
             "/proc/self/environ", "/root/", ".netrc", ".git-credentials", ".npmrc",
             ".pypirc", "id_rsa.pub"}
        ),
        escalated=True,
        what="A well-known sensitive filesystem path appears as a literal",
        blind_spot="Presence of the path does not establish that it is opened.",
    ),
    Rule(
        rule_id="path-traversal-literal",
        family="filesystem",
        capability="filesystem.path_traversal",
        kind="string",
        targets=frozenset({"../../", "..\\..\\"}),
        what="A path literal containing repeated parent-directory traversal",
        blind_spot=(
            "A single '..' is too common to match. Traversal assembled at runtime from "
            "segments is not detected; the config-side case is covered by the template check."
        ),
    ),
)


PACKAGE_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="package-install-command",
        family="package_build",
        capability="package.install_at_runtime",
        kind="string",
        targets=frozenset(
            {"pip install", "pip3 install", "pip.main", "conda install", "apt-get install",
             "apt install", "npm install", "uv pip install", "poetry add"}
        ),
        escalated=True,
        what="A package-installation command appears as a literal",
        blind_spot=(
            "Matched as text, so the same string in documentation or a README-style config "
            "field matches. Pair with process.subprocess evidence before treating as live."
        ),
    ),
    Rule(
        rule_id="pip-internal-api",
        family="package_build",
        capability="package.manager_invocation",
        targets=frozenset({"pip.main", "pip._internal.main", "pkg_resources.require"}),
        escalated=True,
        what="A package manager is driven through its Python API at runtime",
        blind_spot="pip's internal API is unsupported by pip itself; presence is unusual.",
    ),
    Rule(
        rule_id="setuptools-build-hook",
        family="package_build",
        capability="execution.build_hook",
        targets=frozenset({"setuptools.setup", "distutils.core.setup", "setup"}),
        what="A packaging entry point that executes at install or build time",
        blind_spot=(
            "Matching `setup` by bare name over-reports on any function called setup(). "
            "The repository-shape check distinguishes an actual setup.py."
        ),
    ),
)


RULES = RULES + NETWORK_RULES + ENVIRONMENT_RULES + CLOUD_RULES + FILESYSTEM_RULES + PACKAGE_RULES

FAMILIES = tuple(dict.fromkeys(r.family for r in RULES))

#: Capabilities produced at match time rather than declared by a static rule. They are
#: always emitted with an explicit status so a clean repository still makes a statement
#: about them.
DERIVED_CAPABILITIES = ("env.credential_pattern_read",)

#: Which rule actually evaluates each derived capability. Without this a derived
#: capability's clean result would report that zero rules ran, which is indistinguishable
#: from never having been checked — the exact confusion the five-state taxonomy exists to
#: prevent, reappearing one level below the capability.
DERIVED_CAPABILITY_SOURCES = {
    "env.credential_pattern_read": ("env-subscript",),
}

#: String rules are reusable outside Python source — a metadata endpoint in a YAML file is
#: the same finding as one in a .py file.
STRING_RULES = tuple(r for r in RULES if r.kind == "string")


# ------------------------------------------------------------------------------- engine

@dataclass
class Hit:
    rule: Rule
    path: str
    line: int
    matched_name: str
    excerpt: str


def scan_file(pf: PythonFile, rules: tuple[Rule, ...] = RULES) -> list[Hit]:
    """Match every rule against one parsed file. Never executes the file."""
    if not pf.ok or pf.tree is None:
        return []
    hits: list[Hit] = []
    source_lines = (pf.source or "").splitlines()

    def _line_text(line: int) -> str:
        return source_lines[line - 1].strip()[:200] if 0 < line <= len(source_lines) else ""

    call_rules = [r for r in rules if r.kind == "call"]
    string_rules = [r for r in rules if r.kind == "string"]
    subscript_rules = [r for r in rules if r.kind == "subscript"]

    for node in ast.walk(pf.tree):
        # ---- calls
        if isinstance(node, ast.Call):
            exact = call_names(node, pf.aliases)
            suffix = call_suffix(node, pf.aliases)
            if not exact and suffix is None:
                continue
            for rule in call_rules:
                # A bare target matches the call's last segment only for suffix rules; a
                # builtin rule (match_suffix=False) matches the exact name only, so
                # `re.compile` no longer collides with the builtin `compile`.
                names = (exact | {suffix}) if (rule.match_suffix and suffix) else exact
                if not (names & rule.targets):
                    continue
                if rule.predicate is not None and not rule.predicate(node, pf.aliases):
                    continue
                line = getattr(node, "lineno", 0)
                resolved = resolve(dotted_name(node.func), pf.aliases)
                hits.append(
                    Hit(
                        rule=rule,
                        path=pf.path,
                        line=line,
                        matched_name=resolved or dotted_name(node.func),
                        excerpt=_line_text(line),
                    )
                )

        # ---- string literals (endpoints, credential paths)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for rule in string_rules:
                match = next((t for t in rule.targets if t in node.value), None)
                if match is None:
                    continue
                line = getattr(node, "lineno", 0)
                hits.append(
                    Hit(
                        rule=rule,
                        path=pf.path,
                        line=line,
                        matched_name=match,
                        excerpt=node.value[:200],
                    )
                )

        # ---- subscripts, e.g. os.environ["AWS_SECRET_ACCESS_KEY"]
        elif isinstance(node, ast.Subscript):
            base = resolve(dotted_name(node.value), pf.aliases)
            if not base:
                continue
            for rule in subscript_rules:
                if base not in rule.targets:
                    continue
                line = getattr(node, "lineno", 0)
                key = node.slice.value if isinstance(node.slice, ast.Constant) else None
                key_text = key if isinstance(key, str) else "<computed>"
                # The NAME of a credential-shaped variable is recorded; the value never is.
                capability = (
                    "env.credential_pattern_read"
                    if isinstance(key, str) and _env_key_is_credential_shaped(key)
                    else rule.capability
                )
                effective = (
                    rule
                    if capability == rule.capability
                    else Rule(
                        rule_id=f"{rule.rule_id}-credential-shaped",
                        family=rule.family,
                        capability=capability,
                        targets=rule.targets,
                        kind=rule.kind,
                        escalated=True,
                        what="A credential-shaped environment variable is read by name",
                        blind_spot=(
                            "Classification is by variable NAME only. A credential held in a "
                            "variable with an ordinary name is not classified as one, and a "
                            "non-secret variable whose name matches is over-classified."
                        ),
                    )
                )
                hits.append(
                    Hit(
                        rule=effective,
                        path=pf.path,
                        line=line,
                        matched_name=f"{base}[{key_text!r}]",
                        excerpt=_line_text(line),
                    )
                )
    return hits


def scan_strings(
    items: list[tuple[str, str, int | None]],
    rules: tuple[Rule, ...] = STRING_RULES,
) -> list[Hit]:
    """Apply the string rules to arbitrary (text, path, line) triples.

    Exposed so a metadata endpoint in a YAML file produces the same finding as one in a
    Python file. A rule that only looks at .py files would miss the config-borne case,
    which is the more likely place to find a hardcoded endpoint.
    """
    hits: list[Hit] = []
    for text, path, line in items:
        for rule in rules:
            match = next((t for t in rule.targets if t in text), None)
            if match is None:
                continue
            hits.append(
                Hit(rule=rule, path=path, line=line or 0, matched_name=match, excerpt=text[:200])
            )
    return hits


@dataclass
class SurfaceResult:
    findings: list[dict]
    scope: dict
    hits: list[Hit]
    files: list[PythonFile]


def run(
    root: Path,
    *,
    excluded_dirs: set[str] | None = None,
    families: tuple[str, ...] | None = None,
    component: str = "scanner",
    include_configs: bool = True,
) -> SurfaceResult:
    """Run the Python-surface checks over a repository root."""
    excluded_dirs = excluded_dirs or {"vendor", ".git", "node_modules", "__pycache__"}
    rules = RULES if families is None else tuple(r for r in RULES if r.family in families)

    files = load_python_files(root, excluded_dirs)
    analysed = [f.path for f in files if f.ok]
    failed = [f.failed_item for f in files if not f.ok]
    excluded = [
        {
            "path": f"{d}/",
            "reason": "default policy exclusion for vendored, metadata or cache directories",
            "kind": "policy_exclusion",
        }
        for d in sorted(excluded_dirs)
        if (root / d).exists()
    ]

    hits: list[Hit] = []
    for pf in files:
        hits += scan_file(pf, rules)

    # String rules apply to configuration too. A hardcoded metadata endpoint is more likely
    # to sit in a YAML file than in Python, and a rule that only reads .py files would miss
    # the commoner case entirely.
    languages = ["python"]
    if include_configs:
        active_string_rules = tuple(r for r in rules if r.kind == "string")
        if active_string_rules:
            languages += ["yaml", "json", "toml"]
            for cfg_path in iter_config_files(root, excluded=excluded_dirs):
                rel = str(cfg_path.relative_to(root))
                parsed = parse_config(cfg_path, rel)
                if not parsed.ok:
                    failed.append(parsed.failed_item)
                    continue
                analysed.append(rel)
                hits += scan_strings(
                    [(s.value, rel, s.line) for s in parsed.scalars], active_string_rules
                )

    scope = make_scope(
        analysed=sorted(analysed),
        languages=languages,
        excluded=excluded,
        failed=failed,
    )

    by_capability: dict[str, list[Hit]] = defaultdict(list)
    for h in hits:
        by_capability[h.rule.capability].append(h)

    # Include capabilities that only appear at match time — the credential-shaped
    # environment read is derived from the key, not declared by a static rule. Deriving the
    # list from `rules` alone produced a Hit with no corresponding Finding, which is a
    # silently dropped detection.
    #
    # DERIVED_CAPABILITIES are included unconditionally so that they always receive an
    # explicit status. Emitting them only when they matched meant a clean repository
    # produced no statement about them at all, which the assembler's coverage
    # reconciliation correctly flagged as a promised-but-undelivered capability.
    capabilities = sorted(
        {r.capability for r in rules} | set(by_capability) | set(DERIVED_CAPABILITIES)
    )
    findings = []
    for capability in capabilities:
        cap_hits = by_capability.get(capability, [])
        if cap_hits:
            status = "FOUND"
        elif failed:
            status = "PARTIAL"
        else:
            status = "NOT_FOUND_WITHIN_ANALYSED_SCOPE"

        # A derived capability has no rule of its own. Attributing it to the rule that
        # actually produces it stops a clean result reading "evaluated by 0 rules", which
        # is 'not checked' wearing the clothes of 'checked and found nothing'.
        cap_rules = [r for r in rules if r.capability == capability]
        if not cap_rules:
            source_ids = DERIVED_CAPABILITY_SOURCES.get(capability, ())
            cap_rules = [r for r in rules if r.rule_id in source_ids]
        limitations = [
            "Establishes that the construct appears in parsed source; does not establish "
            "that it executes at runtime.",
            "Analysis is per-file and syntactic. A call assembled dynamically or reached "
            "through an indirection is not matched.",
        ] + sorted({r.blind_spot for r in cap_rules})

        rules_fired = sorted({h.rule.rule_id for h in cap_hits})
        basis = (
            f"{len(cap_hits)} call site(s) matched {len(rules_fired)} rule(s) "
            f"({', '.join(rules_fired)}) across {len(analysed)} parsed Python file(s). "
            "Import aliases were resolved before matching."
            if cap_hits
            else (
                f"No call site matched any of the {len(cap_rules)} rule(s) for this "
                f"capability across {len(analysed)} parsed Python file(s)."
            )
        )
        conditional = [r for r in cap_rules if r.predicate is not None]
        if conditional:
            basis += " Conditional rules fired only under their stated condition: " + "; ".join(
                f"{r.rule_id} ({r.predicate_note})" for r in conditional
            ) + "."

        findings.append(
            make_finding(
                capability=capability,
                status=status,
                detection_method="static_ast",
                rule_id=f"python-surface:{capability}",
                rule_version=RULE_VERSION,
                source_component=component,
                scope=scope,
                evidence=[
                    make_evidence(
                        kind="file_line",
                        path=h.path,
                        line=h.line,
                        excerpt=h.excerpt,
                        detail=f"rule={h.rule.rule_id} resolved={h.matched_name}",
                    )
                    for h in cap_hits
                ],
                confidence_basis=basis,
                limitations=limitations,
            )
        )

    return SurfaceResult(findings=findings, scope=scope, hits=hits, files=files)
