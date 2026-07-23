"""Conformance probes — the payload that runs INSIDE the sandbox to test its boundary.

This module is executed inside the sandbox rootfs. It attempts each prohibited operation from
the Phase 3 probe list and reports, in structured form, whether the boundary held. It is part
of the trusted harness — it is placed in an operator-controlled rootfs, it is NOT an artifact,
and nothing here is derived from a scanned artifact.

## Two binding constraints, restated at the top of the file that must honour them

**Non-weaponized as written, not merely as intended.** No probe contains a sandbox-escape
exploit, a CVE proof-of-concept, or any code whose *success* would compromise a host. Every
probe attempts an operation that is expected to be *refused*, using the most benign form of
that operation available:

* the process-signalling probe uses signal 0 (the null signal), which checks permission and
  delivers nothing;
* the privilege probe attempts `setuid` and reads `/proc/self/uid_map`, and contains no
  exploit that could actually gain privilege;
* the device probe *opens* device nodes read-only and never reads or writes their contents
  (no `/dev/mem` read, no `/proc/sysrq-trigger` write — those would be destructive even as a
  test);
* the write probe targets the read-only rootfs, never a host control file.

Run this module on a bare host as an unprivileged user and it does nothing but fail to do
things and print JSON. That is the test of "non-weaponized as written": read the code and the
worst case is a harmless `EPERM`.

**Detonate-then-defuse applies to the probes themselves.** A probe that can only ever report
`CONFORMS` proves nothing — the same lesson the config-injection guard taught. Each probe's
verdict is computed from observed facts, so that running this module *outside* a sandbox makes
the containment-dependent probes report `DEVIATES`. That negative control is what shows the
probes can actually detect the absence of containment; it is exercised by
`tests/sandbox/test_probes_negative_control.py`.

## Verdicts

* `CONFORMS`   — the boundary held: the prohibited operation was blocked, or the dangerous
                 object was absent, or the limit was enforced.
* `DEVIATES`   — the boundary did NOT hold: the prohibited operation succeeded. This is a
                 containment finding and is the most important output this module produces.
* `INCONCLUSIVE` — the probe could not determine an answer (it could not even set up its
                 test). Never treated as `CONFORMS`.

A single `DEVIATES` means the sandbox fails this suite. An all-`CONFORMS` run means only that
no gap was found *among these probed classes, in this environment* — it is
`NOT_FOUND_WITHIN_ANALYSED_SCOPE`, never a clean bill of health, and it says nothing about
gVisor's strength against a kernel exploit (`SANDBOX_THREAT_MODEL.md` §2.1, §7).
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys

CONFORMS = "CONFORMS"
DEVIATES = "DEVIATES"
INCONCLUSIVE = "INCONCLUSIVE"

#: The mount destinations the harness itself creates. A mount outside this set is host-derived
#: and a mount-isolation deviation. Kept in sync with `launch.py`'s spec by
#: `tests/sandbox/test_probe_expectations_match_launch.py`.
EXPECTED_MOUNT_DESTS = frozenset({"/", "/proc", "/tmp", "/artifact", "/dev", "/sys"})

#: Environment names the signed-off profiles allow through. Anything else present is a
#: sanitisation deviation.
EXPECTED_ENV_NAMES = frozenset({"PATH", "HOME", "LANG"})

#: A path the harness plants on the host OUTSIDE the rootfs and OUTSIDE /artifact, so the
#: filesystem-read probe has a concrete host target to fail to read. The harness passes the
#: same constant; it is not artifact-derived.
HOST_SENTINEL_PATH = "/trustlens-host-sentinel-do-not-leak"


def _result(probe_id, category, attempted, expectation, observed, verdict, detail=""):
    return {
        "probe_id": probe_id,
        "category": category,
        "attempted": attempted,
        "expectation": expectation,
        "observed": observed,
        "verdict": verdict,
        "detail": detail,
    }


# --------------------------------------------------------------------------- 1. host fs read

def probe_host_filesystem_read():
    """Attempt to read a HOST-planted sentinel. Benign: one read-only open, no exfiltration.

    Soundness correction (found running against real gVisor, docs/COVERAGE_GAPS.md, and
    surfaced in docs/PROBE_SUITE_REVIEW.md as finding PR-1). An earlier version also tried
    `/etc/shadow` and `/proc/1/environ`. Those are FALSE host-leak signals: inside the
    sandbox's own mount and pid namespaces they read the *sandbox's* `/etc/shadow` (which comes
    from the operator-supplied base image) and the *sandbox init's* environ — neither is a host
    file. Flagging them made a correctly-contained sandbox report a deviation, which is the
    cardinal sin for this kind of tool: a clean input must never raise a false flag.

    The only sound signal is a file the harness plants on the HOST, outside the sandbox's mount
    namespace and outside `/artifact`. Our rootfs does not contain it, so reading it from inside
    can succeed only if the mount boundary leaked. That is a true positive by construction.
    """
    readable = []
    try:
        with open(HOST_SENTINEL_PATH, "rb") as handle:
            handle.read(1)
        readable.append(HOST_SENTINEL_PATH)
    except OSError:
        pass
    if readable:
        return _result(
            "fs.host_read", "host_filesystem_read",
            f"open+read1 of {HOST_SENTINEL_PATH}", "refused or absent",
            f"readable: {readable}", DEVIATES,
            "a host-planted sentinel was readable from inside the sandbox — the mount "
            "boundary leaked",
        )
    return _result(
        "fs.host_read", "host_filesystem_read",
        f"open+read1 of {HOST_SENTINEL_PATH}", "refused or absent",
        "none readable", CONFORMS,
    )


# -------------------------------------------------------------------------- 2. host fs write

def probe_host_filesystem_write():
    """Attempt to write to the read-only rootfs. Benign: never touches a host control file."""
    targets = ["/trustlens-probe-write", "/artifact/trustlens-probe-write"]
    wrote = []
    for path in targets:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
            wrote.append(path)
            try:
                os.unlink(path)
            except OSError:
                pass
        except OSError:
            continue
    if wrote:
        return _result(
            "fs.write", "host_filesystem_write",
            f"O_CREAT on {targets}", "all refused (read-only)",
            f"writable: {wrote}", DEVIATES,
            "a location that should be read-only accepted a write",
        )
    return _result(
        "fs.write", "host_filesystem_write",
        f"O_CREAT on {targets}", "all refused (read-only)",
        "none writable", CONFORMS,
    )


# -------------------------------------------------------------------------- 3. host PID view

def probe_host_pid_visibility():
    """List visible PIDs. Benign: reads /proc only."""
    host_markers = ("dockerd", "containerd", "systemd", "kubelet")
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError as exc:
        return _result(
            "pid.visibility", "host_pid_visibility",
            "list /proc", "only sandbox PIDs visible",
            f"could not read /proc: {exc}", INCONCLUSIVE,
        )
    seen_markers = []
    for pid in pids:
        try:
            with open(f"/proc/{pid}/comm", "r") as handle:
                comm = handle.read().strip()
        except OSError:
            continue
        if comm in host_markers:
            seen_markers.append((pid, comm))
    # In a pid namespace the sandbox sees a small, self-contained process table.
    if seen_markers or len(pids) > 50:
        return _result(
            "pid.visibility", "host_pid_visibility",
            "list /proc and read comm", "only sandbox PIDs visible",
            f"pids={len(pids)} host-markers={seen_markers}", DEVIATES,
            "host processes appear to be visible from inside the sandbox",
        )
    return _result(
        "pid.visibility", "host_pid_visibility",
        "list /proc and read comm", "only sandbox PIDs visible",
        f"pids={len(pids)}, no host process markers", CONFORMS,
    )


# ------------------------------------------------------------------------ 4. signal host pid

def probe_signal_host_process():
    """Attempt to reach processes with signal 0. Benign: the null signal delivers nothing."""
    # Probe a spread of low PIDs that would be host processes if the pid namespace leaked.
    # Signal 0 performs the permission/existence check WITHOUT sending a signal, so nothing is
    # ever actually signalled — this is the non-destructive form by construction.
    reachable = []
    own_pids = set()
    try:
        own_pids = {int(n) for n in os.listdir("/proc") if n.isdigit()}
    except OSError:
        pass
    for pid in (1, 2, 100, 300, 1000):
        if pid in own_pids and pid != 1:
            # A pid we can see inside our namespace is our own; not a host-reachability signal.
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue  # ESRCH: no such process in our namespace — good
        except PermissionError:
            continue  # EPERM: exists but we cannot signal it — also fine
        else:
            # pid 1 inside a namespace is the sandbox init; reaching it is expected and not a
            # host reach. Any OTHER reachable pid would be.
            if pid != 1:
                reachable.append(pid)
    if reachable:
        return _result(
            "signal.host", "signal_host_process",
            "os.kill(pid, 0) for host-range pids", "no host process reachable",
            f"reachable: {reachable}", DEVIATES,
            "a non-namespace process was reachable with the null signal",
        )
    return _result(
        "signal.host", "signal_host_process",
        "os.kill(pid, 0) for host-range pids", "no host process reachable",
        "no host process reachable", CONFORMS,
    )


# -------------------------------------------------------------------- 5. privilege escalation

def probe_privilege_confinement():
    """Test capability confinement with a benign privileged syscall. No exploit, no exploit PoC.

    Soundness correction (found running against real gVisor; docs/PROBE_SUITE_REVIEW.md finding
    PR-2). An earlier version judged confinement from `/proc/self/uid_map` — a *namespaces*
    concept. gVisor does not confine by uid mapping: the Sentry is the boundary, and being uid 0
    *inside* the sandbox says nothing about host privilege because the sandbox's "kernel" is the
    Sentry, not the host. So a uid_map of "0 0" flagged a correctly-contained gVisor sandbox as
    a deviation — a false alarm on a clean input.

    The sound, mechanism-independent test is to attempt an operation that genuinely requires a
    host capability and observe that it is refused. `mknod` of a character device requires
    `CAP_MKNOD`; a confined sandbox denies it with `EPERM`. This is benign as written: it
    creates a harmless node in `/tmp` (device 1,3 — the numbers of `/dev/null`) and unlinks it
    immediately, and if the sandbox is doing its job the call never succeeds at all. A success
    is a true positive — a real capability leak — not an inference from a uid model.
    """
    import stat

    detail = {"uid": os.getuid(), "euid": os.geteuid()}
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                if line.startswith("NoNewPrivs:"):
                    detail["no_new_privs"] = line.split()[1].strip()
    except OSError:
        pass

    node = "/tmp/trustlens-priv-probe-node"
    try:
        os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except PermissionError:
        return _result("priv.confinement", "privilege_escalation",
                       "mknod(char device)", "refused (CAP_MKNOD denied)",
                       json.dumps(detail), CONFORMS)
    except OSError as exc:
        if exc.errno == errno.EPERM:
            return _result("priv.confinement", "privilege_escalation",
                           "mknod(char device)", "refused (CAP_MKNOD denied)",
                           json.dumps(detail), CONFORMS)
        detail["mknod_error"] = f"{errno.errorcode.get(exc.errno, exc.errno)}"
        return _result("priv.confinement", "privilege_escalation",
                       "mknod(char device)", "refused (CAP_MKNOD denied)",
                       json.dumps(detail), INCONCLUSIVE,
                       "mknod failed for a reason other than permission; confinement not shown")
    else:
        try:
            os.unlink(node)
        except OSError:
            pass
        return _result("priv.confinement", "privilege_escalation",
                       "mknod(char device)", "refused (CAP_MKNOD denied)",
                       json.dumps(detail), DEVIATES,
                       "creating a device node succeeded — CAP_MKNOD is available inside the "
                       "sandbox, a real privileged-capability leak")


# ------------------------------------------------------------------- 6. blocked outbound conn

def _connect_blocked(host, port, timeout=2.0):
    """Return (blocked: bool, detail). A refused/unreachable connection is 'blocked'."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return False, "connected"
    except OSError as exc:
        return True, f"{errno.errorcode.get(exc.errno, exc.errno)}: {exc}"


def probe_blocked_outbound():
    """Attempt outbound TCP to public addresses. Benign: a connect attempt, no payload."""
    results = {}
    any_connected = False
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        blocked, detail = _connect_blocked(host, port)
        results[f"{host}:{port}"] = detail
        any_connected = any_connected or not blocked
    if any_connected:
        return _result("net.outbound", "blocked_outbound_connection",
                       "TCP connect to public IPs", "all blocked (--network=none)",
                       json.dumps(results), DEVIATES,
                       "an outbound connection succeeded under a no-network policy")
    return _result("net.outbound", "blocked_outbound_connection",
                   "TCP connect to public IPs", "all blocked (--network=none)",
                   json.dumps(results), CONFORMS)


# --------------------------------------------------------------------- 7. cloud metadata

def probe_cloud_metadata():
    """Attempt to reach the cloud metadata endpoint. Benign: a connect attempt, no payload."""
    blocked, detail = _connect_blocked("169.254.169.254", 80, timeout=2.0)
    if not blocked:
        return _result("net.metadata", "cloud_metadata_access",
                       "TCP connect 169.254.169.254:80", "blocked",
                       detail, DEVIATES,
                       "the cloud metadata endpoint was reachable")
    return _result("net.metadata", "cloud_metadata_access",
                   "TCP connect 169.254.169.254:80", "blocked",
                   detail, CONFORMS)


# ---------------------------------------------------------------------- 8. device access

def probe_device_access():
    """Attempt read-only opens of dangerous device nodes. Benign: never reads their contents."""
    devices = ["/dev/kvm", "/dev/mem", "/dev/sda", "/dev/kmsg"]
    opened = []
    for path in devices:
        try:
            fd = os.open(path, os.O_RDONLY)
            os.close(fd)          # opened only; contents never read
            opened.append(path)
        except OSError:
            continue
    if opened:
        return _result("dev.access", "device_access",
                       f"O_RDONLY open of {devices}", "all absent or refused",
                       f"openable: {opened}", DEVIATES,
                       "a sensitive device node was openable from inside the sandbox")
    return _result("dev.access", "device_access",
                   f"O_RDONLY open of {devices}", "all absent or refused",
                   "none openable", CONFORMS)


# ------------------------------------------------------------------ 9. resource limits

def probe_resource_limits():
    """Verify configured limits are in force. Benign: reads limits, never exhausts them."""
    try:
        import resource
    except ImportError:
        return _result("res.limits", "resource_limit_enforcement",
                       "getrlimit", "finite limits enforced",
                       "resource module unavailable", INCONCLUSIVE)
    detail = {}
    unlimited = []
    for name in ("RLIMIT_NOFILE", "RLIMIT_NPROC", "RLIMIT_AS"):
        const = getattr(resource, name, None)
        if const is None:
            continue
        soft, hard = resource.getrlimit(const)
        detail[name] = {"soft": soft, "hard": hard}
        # RLIMIT_AS is not always set by us; only NOFILE is asserted finite.
        if name == "RLIMIT_NOFILE" and hard == resource.RLIM_INFINITY:
            unlimited.append(name)
    if unlimited:
        return _result("res.limits", "resource_limit_enforcement",
                       "getrlimit(RLIMIT_NOFILE)", "finite limit enforced",
                       json.dumps(detail), DEVIATES,
                       f"expected a finite limit but found unlimited: {unlimited}")
    return _result("res.limits", "resource_limit_enforcement",
                   "getrlimit(RLIMIT_NOFILE)", "finite limit enforced",
                   json.dumps(detail), CONFORMS)


# ---------------------------------------------------------------------- 10. DNS policy

def probe_dns_policy():
    """Attempt name resolution. Benign: a lookup, no connection follows."""
    try:
        infos = socket.getaddrinfo("example.com", 80, proto=socket.IPPROTO_TCP)
        return _result("net.dns", "dns_policy",
                       "getaddrinfo(example.com)", "resolution unavailable (no network)",
                       f"resolved to {[i[4][0] for i in infos][:3]}", DEVIATES,
                       "DNS resolution succeeded under a no-network policy")
    except OSError as exc:
        return _result("net.dns", "dns_policy",
                       "getaddrinfo(example.com)", "resolution unavailable (no network)",
                       f"{type(exc).__name__}: {exc}", CONFORMS)


# ------------------------------------------------------------------- 11. mount isolation

def _read_mounts():
    for candidate in ("/proc/self/mountinfo", "/proc/mounts"):
        try:
            with open(candidate) as handle:
                return candidate, handle.read()
        except OSError:
            continue
    return None, None


def probe_mount_isolation():
    """Read the mount table and assert only expected mounts. Benign: reads /proc only."""
    source, text = _read_mounts()
    if text is None:
        return _result("mnt.isolation", "mount_isolation",
                       "read mount table", "only harness mounts present",
                       "no mount table readable", INCONCLUSIVE)
    dests = set()
    for line in text.splitlines():
        fields = line.split()
        if source.endswith("mountinfo"):
            # mountinfo: field 5 (0-indexed 4) is the mount point
            if len(fields) >= 5:
                dests.add(fields[4])
        else:
            # /proc/mounts: field 2 (0-indexed 1) is the mount point
            if len(fields) >= 2:
                dests.add(fields[1])
    unexpected = sorted(
        d for d in dests
        if d not in EXPECTED_MOUNT_DESTS and not d.startswith(("/dev/", "/proc/", "/sys/"))
    )
    if unexpected:
        return _result("mnt.isolation", "mount_isolation",
                       "read mount table", "only harness mounts present",
                       f"unexpected mounts: {unexpected}", DEVIATES,
                       "a mount outside the harness set is visible (possible host bind mount)")
    return _result("mnt.isolation", "mount_isolation",
                   "read mount table", "only harness mounts present",
                   f"mounts: {sorted(dests)}", CONFORMS)


# ----------------------------------------------------------------- 12. env sanitisation

def probe_environment_sanitisation():
    """Assert no HOST environment variable leaked in. Benign: reads os.environ.

    Soundness correction (found running against real gVisor; docs/PROBE_SUITE_REVIEW.md finding
    PR-3). The probe's purpose is to detect *host* environment variables — credentials, tokens,
    `AWS_*`, hostnames — leaking into the sandbox. The container runtime injects a locale
    variable (`LC_CTYPE`) of its own, which is not host-derived and is not a secret; flagging it
    made a correctly-sanitised sandbox report a deviation. Locale variables (`LC_*`) are
    therefore treated as runtime defaults, not leaks. Everything else outside the allowlist is
    still a finding — an `AWS_SECRET_ACCESS_KEY` would be caught exactly as before.
    """
    present = set(os.environ)
    leaked = sorted(
        name for name in present - EXPECTED_ENV_NAMES
        if not name.startswith("LC_")  # runtime-injected locale, not host leakage
    )
    if leaked:
        return _result("env.sanitisation", "environment_sanitisation",
                       "read os.environ", f"only {sorted(EXPECTED_ENV_NAMES)} (+ LC_*) present",
                       f"unexpected env names: {leaked}", DEVIATES,
                       "an environment variable outside the allowlist reached the sandbox")
    return _result("env.sanitisation", "environment_sanitisation",
                   "read os.environ", f"only {sorted(EXPECTED_ENV_NAMES)} (+ LC_*) present",
                   f"env names: {sorted(present)}", CONFORMS)


#: The suite, in the Phase 3 spec's order. A list so the harness can report count and order.
PROBES = [
    probe_host_filesystem_read,
    probe_host_filesystem_write,
    probe_host_pid_visibility,
    probe_signal_host_process,
    probe_privilege_confinement,
    probe_blocked_outbound,
    probe_cloud_metadata,
    probe_device_access,
    probe_resource_limits,
    probe_dns_policy,
    probe_mount_isolation,
    probe_environment_sanitisation,
]


def run_all():
    """Run every probe and return the list of result dicts. Never raises: a probe that throws
    becomes an INCONCLUSIVE result, because a crashing probe must not be read as a clean pass.
    """
    results = []
    for probe in PROBES:
        try:
            results.append(probe())
        except Exception as exc:  # a probe bug must not masquerade as containment
            results.append(_result(
                getattr(probe, "__name__", "unknown"), "probe_error",
                probe.__name__, "probe completes", f"probe raised {type(exc).__name__}: {exc}",
                INCONCLUSIVE, "the probe itself failed; this is not evidence of containment",
            ))
    return results


def main():
    results = run_all()
    # A single, parseable line the harness reads back. Marker prefix so it is unambiguous even
    # if the sandboxed program emitted other output.
    sys.stdout.write("TRUSTLENS_PROBE_RESULTS " + json.dumps(results) + "\n")
    sys.stdout.flush()
    # Exit code encodes the worst verdict, so a caller that only sees the code is not misled.
    verdicts = {r["verdict"] for r in results}
    if DEVIATES in verdicts:
        return 2
    if INCONCLUSIVE in verdicts:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
