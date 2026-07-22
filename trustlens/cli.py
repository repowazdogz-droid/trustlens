"""TrustLens command line.

Exit codes are part of the evidence, because a pipeline reads them instead of the report:

* ``0`` — analysis completed over its recorded scope and found nothing.
* ``1`` — analysis completed and findings were reported.
* ``2`` — **analysis did not complete**: a coverage gap, a scope failure, or a check that
  raised. This is deliberately NOT ``0``. A caller that treats an incomplete scan as a
  clean one reproduces, at the process boundary, exactly the false-clean failure the whole
  evidence model exists to prevent.
* ``3`` — usage or input error.

``scan`` never fetches and never executes the artifact. ``plan`` performs a dry run and
writes nothing. ``acquire`` is the only subcommand that touches a remote, and it refuses to
run without an explicit authorization acknowledgement.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import acquire as acquire_mod
from .scanner.assemble import scan as run_scan, summarise
from .scanner.report import discrepancy_level, render
from .mapper.assemble import DescriptionError, map_credentials

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2
EXIT_USAGE = 3


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    result = run_scan(root)
    summary = summarise(result)

    if args.format == "json":
        print(json.dumps({"summary": summary, "record": result.record}, indent=2, sort_keys=True))
    else:
        print(render(result.record, summary))

    if args.output:
        Path(args.output).write_text(
            json.dumps(result.record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"\nEvidence record written to {args.output}", file=sys.stderr)

    incomplete = bool(result.coverage_gaps) or bool(result.record["scope"]["failed"])
    found = bool(summary["found"])

    if incomplete:
        print(
            "\nAnalysis did not complete over the intended scope. Exit code 2 — this is "
            "not a clean result.",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if found else EXIT_CLEAN


def _cmd_map_credentials(args: argparse.Namespace) -> int:
    """Offline credential reachability. Spawns nothing, contacts nothing."""
    try:
        result = map_credentials(Path(args.description))
    except DescriptionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    record = result.record
    if args.format == "json":
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        ref = record["environment_description_ref"]
        print("TrustLens credential reachability")
        print("=" * 70)
        # Surfaced prominently, not buried: every path below is only as current as this.
        print(f"Description captured : {ref['description_captured_at']}  ({ref['captured_at_basis']})")
        print(f"Description          : {ref['description_id']}")
        print("")
        for finding in sorted(record["findings"], key=lambda f: (f["status"], f["capability"])):
            print(f"  [{finding['status']}] {finding['capability']}")
            for ev in finding["evidence"][:6]:
                print(f"      {ev['detail']}")
            if finding["status"] == "UNSUPPORTED":
                print(f"      Not assessed: {finding['unsupported_construct'][:110]}")
        if record["contradictions"]:
            print("")
            print("Contradictions (recorded, not reconciled):")
            for c in record["contradictions"]:
                print(f"  [{c['contradiction_id']}] {c['summary']}")
        if record["scope"]["failed"]:
            print("")
            print("Inputs that could not be read:")
            for f in record["scope"]["failed"]:
                print(f"  {f['path']} — {f['kind']}: {f['reason'][:90]}")
        print("")
        print(f"Residual uncertainty: {record['residual_uncertainty']}")

    if args.output:
        Path(args.output).write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if record["scope"]["failed"] or result.coverage_gaps:
        print(
            "\nThe model is incomplete: some inputs could not be read. Exit 2 — not a "
            "clean result.",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE
    found = any(f["status"] == "FOUND" for f in record["findings"])
    return EXIT_FINDINGS if found else EXIT_CLEAN


def _cmd_rbac(args: argparse.Namespace) -> int:
    """Optional Go helper. Kept fully out of the core scan path by design."""
    from .mapper import rbac_helper

    manifest_dir = Path(args.manifests)
    if not manifest_dir.is_dir():
        print(f"error: {manifest_dir} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    result = rbac_helper.run_helper(manifest_dir, binary=args.binary)
    if not result.available:
        print(f"UNSUPPORTED: {result.unavailable_reason}", file=sys.stderr)
        print(json.dumps({"available": False, "reason": result.unavailable_reason}, indent=2))
        # Absence is not a clean result and not a crash: the capabilities are unassessed.
        return EXIT_INCOMPLETE

    payload = {
        "available": True,
        "binary": result.binary_path,
        "tool_version": result.version,
        "kubernetes_semantics": result.kubernetes_module,
        "analysed": result.analysed,
        "failed": result.failed,
        "service_accounts": result.service_accounts,
        "decisions": result.decisions,
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("TrustLens RBAC (upstream Kubernetes authorizer)")
        print("=" * 70)
        print(f"Semantics from : Kubernetes {result.kubernetes_module}")
        print(f"Analysed       : {len(result.analysed)} manifest file(s)")
        print("")
        allowed = [d for d in result.decisions if d["allowed"]]
        if not allowed:
            print("  No probed verb was allowed for any service account in these manifests.")
            print(f"  {len(result.decisions)} probe(s) were evaluated; this is a result over")
            print("  the probed set, not a statement that nothing is permitted.")
        for d in allowed:
            print(f"  [ALLOWED] {d['subject']}: {d['verb']} {d['resource']}")
            print(f"            {d['reason'][:110]}")
        if result.failed:
            print("")
            print("Manifests that could not be read:")
            for f in result.failed:
                print(f"  {f['path']} — {f['kind']}: {f['reason'][:80]}")
        print("")
        print("These decisions establish what the SUPPLIED MANIFESTS would permit. They do")
        print("not establish what any live cluster permits. No cluster was contacted.")

    if result.failed:
        print("\nSome manifests could not be read. Exit 2 — not a clean result.", file=sys.stderr)
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if any(d["allowed"] for d in result.decisions) else EXIT_CLEAN


def _cmd_plan(args: argparse.Namespace) -> int:
    try:
        plan = acquire_mod.plan(args.source, ref=args.ref)
    except acquire_mod.AcquisitionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(plan.describe())
    return EXIT_CLEAN


def _cmd_acquire(args: argparse.Namespace) -> int:
    if not args.i_am_authorised:
        print(
            "error: acquisition requires --i-am-authorised, and an --acknowledgement "
            "recording who authorised the fetch and on what basis. Run `trustlens plan` "
            "first to see what would be fetched.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        plan = acquire_mod.plan(args.source, ref=args.ref)
        print(plan.describe(), file=sys.stderr)
        record = acquire_mod.acquire(
            plan,
            Path(args.destination),
            authorization_acknowledgement=args.acknowledgement or "",
            i_am_authorised_to_fetch_this=True,
        )
    except acquire_mod.AcquisitionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(json.dumps(acquire_mod.to_artifact_block(record), indent=2, sort_keys=True))
    if record.moved_since_plan:
        print(
            "\nNote: the source moved between the dry run and the fetch. The pinned commit "
            f"{record.commit} was acquired, not the current head {record.head_at_fetch}.",
            file=sys.stderr,
        )
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustlens",
        description=(
            "Compare what an ML dataset or repository is declared to be with what static "
            "analysis shows it can actually do. Does not determine malicious intent, "
            "certify artifacts as safe, or guarantee containment."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="statically analyse a local directory")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", choices=("text", "json"), default="text")
    p_scan.add_argument("--output", help="write the evidence record to this path")
    p_scan.set_defaults(func=_cmd_scan)

    p_map = sub.add_parser(
        "map-credentials",
        help="offline credential reachability from an environment description",
    )
    p_map.add_argument("description", help="path to a trustlens_env_v1 description")
    p_map.add_argument("--format", choices=("text", "json"), default="text")
    p_map.add_argument("--output", help="write the evidence record to this path")
    p_map.set_defaults(func=_cmd_map_credentials)

    p_rbac = sub.add_parser(
        "rbac",
        help="OPTIONAL: evaluate Kubernetes RBAC with the upstream authorizer (separate binary)",
    )
    p_rbac.add_argument("manifests", help="directory of Kubernetes manifests")
    p_rbac.add_argument("--binary", help="path to the trustlens-rbac helper")
    p_rbac.add_argument("--format", choices=("text", "json"), default="text")
    p_rbac.set_defaults(func=_cmd_rbac)

    p_plan = sub.add_parser(
        "plan", help="dry run: show what a fetch would retrieve, writing nothing"
    )
    p_plan.add_argument("source")
    p_plan.add_argument("--ref", default="HEAD")
    p_plan.set_defaults(func=_cmd_plan)

    p_acq = sub.add_parser("acquire", help="fetch a remote repository at a pinned commit")
    p_acq.add_argument("source")
    p_acq.add_argument("destination")
    p_acq.add_argument("--ref", default="HEAD")
    p_acq.add_argument(
        "--i-am-authorised",
        action="store_true",
        help="acknowledge that you own the source or have permission to retrieve it",
    )
    p_acq.add_argument(
        "--acknowledgement", help="who authorised this fetch, and on what basis"
    )
    p_acq.set_defaults(func=_cmd_acquire)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
