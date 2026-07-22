#!/usr/bin/env python3
"""Regenerate the example evidence records under `examples/records/`.

The examples are generated rather than hand-written so that they cannot drift out of
conformance with the schema, and so that a reader can see exactly which builder calls
produce a conforming record. Run from a clean clone:

    python3 examples/generate_examples.py && python3 -m pytest tests -q

Timestamps and identities are fixed constants: regenerating must be byte-identical, or
the reproducibility claim in REPRODUCIBILITY.md would be untestable.
"""

from __future__ import annotations

import json
from pathlib import Path

from trustlens.evidence import make_evidence, make_finding, make_record, make_scope
from trustlens.evidence.schema import validate_record

OUT = Path(__file__).resolve().parent / "records"
TOOL_VERSION = "0.1.0"
COMMIT = "0000000000000000000000000000000000000000"

PY_FILES = [f"loader.py"] + [f"src/mod_{i}.py" for i in range(1, 17)]


def _write(name: str, record: dict, corpus: dict[str, dict] | None = None) -> None:
    # A composing record is validated against its inputs, so that strength and
    # incompleteness propagation across records are actually checked rather than assumed.
    validate_record(record, corpus=corpus)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(
        json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {name}  record_id={record['record_id']}")


# --------------------------------------------------------------------------------------
# 1. Scanner (Phase 1) — declared passive data, statically reachable execution and network,
#    one clean check, one PARTIAL check, one unsupported construct.
# --------------------------------------------------------------------------------------

def scanner_record() -> dict:
    artifact = {
        "artifact_id": "example-dataset-repo",
        "artifact_type": "huggingface_dataset_repository",
        "declared_kind": "dataset",
        "source": "https://huggingface.co/datasets/example-org/example-tabular",
        "immutable_reference": "9f2c1a4e5b6d7c8f9a0b1c2d3e4f5a6b7c8d9e0f",
        "acquisition_method": "already_local",
        "acquisition_authorised_by": None,
        "acquired_at": "2026-07-20T09:00:00+00:00",
        "content_hash": "b" * 64,
        "content_hash_method": "directory_manifest_v1",
        "file_count": 23,
        "total_bytes": 184320,
    }
    run = {
        "started_at": "2026-07-20T09:00:01+00:00",
        "completed_at": "2026-07-20T09:00:07+00:00",
        "execution_mode": "static_analysis",
        "invocation": "trustlens scan ./example-tabular --format json",
        "config_hash": None,
        "reasoning_notes": [
            "Acquisition skipped: artifact already present locally.",
            "Enumerated 23 files; 17 Python, 5 config, 1 markdown.",
            "Excluded vendor/ (4 files) by default policy exclusion.",
            "config/legacy.yaml failed to decode as UTF-8; recorded as a scope failure, "
            "which forces the template check to PARTIAL rather than clean.",
        ],
    }
    py_scope = make_scope(analysed=PY_FILES, languages=["python"])

    dynamic_import = make_finding(
        capability="execution.dynamic_import",
        status="FOUND",
        detection_method="static_ast",
        rule_id="exec-dynamic-import",
        rule_version="1.0.0",
        source_component="scanner",
        scope=py_scope,
        evidence=[
            make_evidence(
                kind="file_line",
                path="loader.py",
                line=14,
                excerpt="mod = importlib.import_module(cfg['builder_module'])",
            )
        ],
        confidence_basis=(
            "A call to importlib.import_module was found in a parsed syntax tree, with "
            "its module argument read from repository configuration rather than a "
            "literal. The construct exists in the file; whether the enclosing function "
            "runs during dataset loading is not established by this check."
        ),
        limitations=[
            "Does not establish that the import executes during any particular workflow.",
            "Does not resolve the imported module name, which comes from configuration.",
            "Syntactic match only — no data-flow analysis was performed by this rule.",
        ],
    )

    network = make_finding(
        capability="network.outbound",
        status="FOUND",
        detection_method="static_ast",
        rule_id="net-urlopen",
        rule_version="1.1.0",
        source_component="scanner",
        scope=py_scope,
        evidence=[
            make_evidence(
                kind="file_line",
                path="loader.py",
                line=31,
                excerpt="with urllib.request.urlopen(remote_url) as resp:",
            )
        ],
        confidence_basis=(
            "urllib.request.urlopen is called on a name bound earlier in the same "
            "function. The destination is not a literal and was not resolved."
        ),
        limitations=[
            "Destination host is not resolved; the URL is constructed at runtime.",
            "Does not establish that the call is reached during dataset loading.",
        ],
    )

    shell = make_finding(
        capability="process.shell",
        status="NOT_FOUND_WITHIN_ANALYSED_SCOPE",
        detection_method="static_ast",
        rule_id="process-shell",
        rule_version="1.2.0",
        source_component="scanner",
        scope=make_scope(
            analysed=PY_FILES,
            languages=["python"],
            excluded=[
                {
                    "path": "vendor/",
                    "reason": "default policy exclusion for vendored third-party code",
                    "kind": "policy_exclusion",
                }
            ],
        ),
        confidence_basis=(
            "All 17 Python files parsed successfully and no shell-invoking construct "
            "matched process-shell v1.2.0 in any of them."
        ),
        limitations=[
            "States only that no match was found in the 17 files listed, under this rule set.",
            "vendor/ was excluded and was not examined at all.",
            "Shell invocation reached through an unanalysed language or a dynamically "
            "constructed call would not be matched.",
        ],
    )

    template = make_finding(
        capability="template.injection_surface",
        status="PARTIAL",
        detection_method="static_ast",
        rule_id="template-jinja-config",
        rule_version="0.9.0",
        source_component="scanner",
        scope=make_scope(
            analysed=[
                "config/dataset_infos.yaml",
                "config/features.yaml",
                "config/splits.yaml",
                "config/builder.toml",
            ],
            languages=["yaml", "toml"],
            failed=[
                {
                    "path": "config/legacy.yaml",
                    "reason": "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff "
                    "in position 0 — file is not valid UTF-8",
                    "kind": "decode_error",
                }
            ],
        ),
        confidence_basis=(
            "Four of five configuration files were parsed and checked for "
            "expression-bearing values. The fifth could not be decoded, so the check did "
            "not cover the intended scope."
        ),
        limitations=[
            "config/legacy.yaml was not analysed at all; it may contain the very "
            "construct this rule looks for.",
            "This result must not be read as 'no template injection surface'. Analysis "
            "of the intended scope did not complete.",
        ],
    )

    fs_write = make_finding(
        capability="filesystem.write_outside_scratch",
        status="FOUND",
        detection_method="static_ast_dataflow",
        rule_id="fs-write-outside-declared-cache",
        rule_version="1.0.0",
        source_component="scanner",
        scope=py_scope,
        evidence=[
            make_evidence(
                kind="file_line",
                path="loader.py",
                line=52,
                excerpt="open(os.path.join(cache_dir, '..', '..', target), 'w')",
            )
        ],
        confidence_basis=(
            "A write-mode open() receives a path built by joining the declared cache "
            "directory with parent-directory traversal segments, so the resulting path "
            "escapes the declared cache root. Source-to-sink flow was traced within the "
            "function."
        ),
        limitations=[
            "The final destination depends on the runtime value of cache_dir and target, "
            "neither of which is resolved statically.",
            "Does not establish that this line executes.",
        ],
    )

    native = make_finding(
        capability="execution.native_extension",
        status="UNSUPPORTED",
        detection_method="static_ast",
        rule_id="native-extension",
        rule_version="0.1.0",
        source_component="scanner",
        scope=make_scope(analysed=[], languages=[]),
        unsupported_construct=(
            "Compiled extension module (data/_fast_parse.cpython-311-x86_64-linux-gnu.so)"
        ),
        confidence_basis=(
            "The scanner has no analyser for compiled native code. This is recorded as "
            "an unassessed construct rather than omitted from the report."
        ),
        limitations=[
            "The scanner cannot assess compiled extensions at all — this is not a clean "
            "result for that file, it is an absence of any result.",
        ],
    )

    findings = [dynamic_import, network, shell, template, fs_write, native]

    declared = [
        {
            "capability": "execution.dynamic_import",
            "declaration": "not_required",
            "declared_by": "dataset_card",
            "source": make_evidence(
                kind="declaration_text",
                path="README.md",
                line=8,
                excerpt="This dataset contains tabular records only and requires no custom code.",
            ),
            "verbatim": "This dataset contains tabular records only and requires no custom code.",
            "extraction_rule_id": "declared-dataset-card",
            "extraction_rule_version": "1.0.0",
        },
        {
            "capability": "network.outbound",
            "declaration": "not_required",
            "declared_by": "dataset_card",
            "source": make_evidence(
                kind="declaration_text",
                path="README.md",
                line=9,
                excerpt="All data is bundled in the repository; no download step is needed.",
            ),
            "verbatim": "All data is bundled in the repository; no download step is needed.",
            "extraction_rule_id": "declared-dataset-card",
            "extraction_rule_version": "1.0.0",
        },
    ]

    contradictions = [
        {
            "contradiction_id": "C-001",
            "summary": (
                "The dataset card states no custom code is required, while a dynamic "
                "import driven by repository configuration is present in loader.py."
            ),
            "between": [
                {
                    "evidence_kind": "declared",
                    "ref": "0",
                    "assertion": "dataset card declares custom code not required",
                },
                {
                    "evidence_kind": "static",
                    "ref": dynamic_import["finding_id"],
                    "assertion": "importlib.import_module reached at loader.py:14",
                },
            ],
            "reconciled": False,
            "capability": "execution.dynamic_import",
        },
        {
            "contradiction_id": "C-002",
            "summary": (
                "The dataset card states no download step is needed, while an outbound "
                "HTTP call is present in loader.py."
            ),
            "between": [
                {
                    "evidence_kind": "declared",
                    "ref": "1",
                    "assertion": "dataset card declares no download step",
                },
                {
                    "evidence_kind": "static",
                    "ref": network["finding_id"],
                    "assertion": "urllib.request.urlopen reached at loader.py:31",
                },
            ],
            "reconciled": False,
            "capability": "network.outbound",
        },
    ]

    return make_record(
        component="scanner",
        tool_version=TOOL_VERSION,
        commit=COMMIT,
        artifact=artifact,
        run=run,
        scope=make_scope(
            analysed=PY_FILES
            + [
                "config/dataset_infos.yaml",
                "config/features.yaml",
                "config/splits.yaml",
                "config/builder.toml",
                "README.md",
            ],
            languages=["python", "yaml", "toml", "markdown"],
            excluded=[
                {
                    "path": "vendor/",
                    "reason": "default policy exclusion for vendored third-party code",
                    "kind": "policy_exclusion",
                }
            ],
            failed=[
                {
                    "path": "config/legacy.yaml",
                    "reason": "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff "
                    "in position 0 — file is not valid UTF-8",
                    "kind": "decode_error",
                }
            ],
        ),
        declared_capabilities=declared,
        findings=findings,
        contradictions=contradictions,
        unknowns=[
            {
                "subject": "Destination host of the outbound request at loader.py:31",
                "reason": "The URL is assembled at runtime from configuration values.",
                "would_be_resolved_by": "A sandboxed execution recording the connection attempt.",
            },
            {
                "subject": "Whether the repository declares a scratch or cache path",
                "reason": "No declaration of a writable working directory was found in the "
                "dataset card or configuration.",
                "would_be_resolved_by": "An operator-supplied declared cache path.",
            },
        ],
        unsupported=[
            {
                "construct": "Compiled native extension module",
                "where": "data/_fast_parse.cpython-311-x86_64-linux-gnu.so",
                "reason": "No analyser for compiled code is implemented.",
            }
        ],
        residual_uncertainty=(
            "One configuration file could not be decoded and was not analysed, so the "
            "template-injection check is incomplete. One compiled extension is present "
            "and cannot be assessed at all. Runtime reachability of every static finding "
            "is unestablished."
        ),
        claims={
            "establishes": [
                "The listed static checks ran over the recorded scope at the recorded "
                "rule versions.",
                "The constructs cited at the recorded file and line positions are present "
                "in the artifact.",
                "The dataset card's declarations conflict with two constructs found in "
                "loader.py.",
            ],
            "does_not_establish": [
                "That any construct executes at runtime, in this or any workflow.",
                "That the artifact is malicious, or that any finding is exploitable.",
                "That the artifact is free of capabilities the analysed rules do not cover.",
                "That config/legacy.yaml is free of template-injection surface — it was "
                "not analysed.",
            ],
        },
        environment_description_ref=None,
        sandbox=None,
    )


# --------------------------------------------------------------------------------------
# 2. Credential reachability mapper (Phase 2) — offline, config-derived, timestamped.
# --------------------------------------------------------------------------------------

ENV_REF = {
    "description_id": "prod-dataset-processing-v3",
    "description_captured_at": "2026-06-01T00:00:00+00:00",
    "captured_at_basis": "operator_asserted",
    "description_hash": "c" * 64,
    "source_format": "trustlens_env_v1",
}


def credential_mapper_record() -> dict:
    scope = make_scope(
        analysed=[
            "env/dataset-worker.yaml",
            "iam/dataset-worker-role.json",
            "k8s/rbac/cluster-reader.yaml",
            "k8s/networkpolicy/dataset-processing.yaml",
        ],
        languages=["trustlens_env_v1", "iam_policy_json", "kubernetes_manifest"],
    )

    env_read = make_finding(
        capability="env.credential_pattern_read",
        status="FOUND",
        detection_method="config_derivation",
        rule_id="env-credential-readable",
        rule_version="1.0.0",
        source_component="credential_mapper",
        scope=scope,
        environment_description_ref=ENV_REF,
        evidence=[
            make_evidence(
                kind="config_key",
                path="env/dataset-worker.yaml",
                pointer="/processes/dataset-worker/environment/AWS_SECRET_ACCESS_KEY",
                excerpt="AWS_SECRET_ACCESS_KEY: <redacted>",
                redacted=True,
                detail="Variable name recorded; value never read or stored.",
            )
        ],
        confidence_basis=(
            "The supplied environment description lists AWS_SECRET_ACCESS_KEY in the "
            "dataset-worker process environment. This is what the description says was "
            "true when it was captured on 2026-06-01."
        ),
        limitations=[
            "Derived from a description captured 2026-06-01; the live environment may differ.",
            "Does not establish that the credential is valid, unexpired, or in use.",
            "TrustLens cannot verify the operator-asserted capture time.",
        ],
    )

    s3 = make_finding(
        capability="reachability.resource_access",
        status="FOUND",
        detection_method="policy_evaluation",
        rule_id="iam-allows-action-on-resource",
        rule_version="1.0.0",
        source_component="credential_mapper",
        scope=scope,
        environment_description_ref=ENV_REF,
        evidence=[
            make_evidence(
                kind="policy_statement",
                path="iam/dataset-worker-role.json",
                pointer="/Statement/0",
                excerpt='{"Effect":"Allow","Action":"s3:GetObject","Resource":'
                '"arn:aws:s3:::prod-data/*"}',
                detail="Statement Sid: AllowDatasetRead",
            )
        ],
        confidence_basis=(
            "An Allow statement for s3:GetObject on arn:aws:s3:::prod-data/* is present "
            "in the attached role policy, with no matching Deny under the recorded "
            "interpretation rules."
        ),
        limitations=[
            "Evaluates only the supplied policy documents. Service control policies, "
            "permission boundaries and bucket policies not supplied were not considered.",
            "Does not establish that the object read would succeed at runtime.",
            "Derived from a description captured 2026-06-01.",
        ],
    )

    k8s_api = make_finding(
        capability="k8s.api_access",
        status="UNKNOWN",
        detection_method="config_derivation",
        rule_id="k8s-serviceaccount-to-api",
        rule_version="1.0.0",
        source_component="credential_mapper",
        scope=scope,
        environment_description_ref=ENV_REF,
        unknown_reason=(
            "The description records a mounted service-account token but does not state "
            "whether the API server is network-reachable from the dataset-processing "
            "namespace. Neither reachability nor its absence can be derived."
        ),
        confidence_basis=(
            "Required information is absent from the supplied description, so no "
            "determination is made in either direction."
        ),
        limitations=[
            "This is not a finding that the API is unreachable. It is an absence of "
            "information from which either conclusion could be drawn.",
        ],
    )

    metadata_contradiction_a = make_finding(
        capability="cloud.metadata_endpoint",
        status="FOUND",
        detection_method="policy_evaluation",
        rule_id="netpol-permits-link-local",
        rule_version="1.0.0",
        source_component="credential_mapper",
        scope=scope,
        environment_description_ref=ENV_REF,
        evidence=[
            make_evidence(
                kind="policy_statement",
                path="k8s/networkpolicy/dataset-processing.yaml",
                pointer="/spec/egress/0/to/0/ipBlock/cidr",
                excerpt="cidr: 0.0.0.0/0",
                detail="No except clause covering 169.254.169.254/32.",
            )
        ],
        confidence_basis=(
            "The egress rule permits 0.0.0.0/0 with no exception for the link-local "
            "range, so link-local traffic is permitted by this policy."
        ),
        limitations=[
            "Considers only the supplied NetworkPolicy. A CNI-level or host-level block "
            "not described here would not be visible.",
            "Derived from a description captured 2026-06-01.",
        ],
    )

    return make_record(
        component="credential_mapper",
        tool_version=TOOL_VERSION,
        commit=COMMIT,
        artifact={
            "artifact_id": "prod-dataset-processing-v3",
            "artifact_type": "environment_description",
            "declared_kind": None,
            "source": "operator-supplied offline description",
            "immutable_reference": None,
            "acquisition_method": "user_supplied_path",
            "acquisition_authorised_by": None,
            "acquired_at": "2026-07-20T10:00:00+00:00",
            "content_hash": "c" * 64,
            "content_hash_method": "directory_manifest_v1",
            "file_count": 4,
            "total_bytes": 9216,
        },
        run={
            "started_at": "2026-07-20T10:00:01+00:00",
            "completed_at": "2026-07-20T10:00:02+00:00",
            "execution_mode": "offline_modelling",
            "invocation": "trustlens map-credentials ./env-description --format json",
            "config_hash": None,
            "reasoning_notes": [
                "Offline modelling only: no cloud API was contacted and no credential was used.",
                "Environment description capture time 2026-06-01T00:00:00+00:00 "
                "(operator-asserted, 49 days before this run).",
                "Contradiction detected between the description's metadata-access claim "
                "and the supplied NetworkPolicy; recorded rather than reconciled.",
            ],
        },
        scope=scope,
        declared_capabilities=[
            {
                "capability": "cloud.metadata_endpoint",
                "declaration": "explicitly_absent",
                "declared_by": "operator_statement",
                "source": make_evidence(
                    kind="config_key",
                    path="env/dataset-worker.yaml",
                    pointer="/network/metadata_endpoint_blocked",
                    excerpt="metadata_endpoint_blocked: true",
                ),
                "verbatim": "metadata_endpoint_blocked: true",
                "extraction_rule_id": "declared-env-description",
                "extraction_rule_version": "1.0.0",
            }
        ],
        findings=[env_read, s3, k8s_api, metadata_contradiction_a],
        contradictions=[
            {
                "contradiction_id": "C-101",
                "summary": (
                    "The environment description asserts the metadata endpoint is "
                    "blocked, while the supplied NetworkPolicy permits egress to "
                    "0.0.0.0/0 with no exception for 169.254.169.254/32."
                ),
                "between": [
                    {
                        "evidence_kind": "declared",
                        "ref": "0",
                        "assertion": "operator asserts metadata_endpoint_blocked: true",
                    },
                    {
                        "evidence_kind": "configured",
                        "ref": metadata_contradiction_a["finding_id"],
                        "assertion": "NetworkPolicy egress permits link-local range",
                    },
                ],
                "reconciled": False,
                "capability": "cloud.metadata_endpoint",
            }
        ],
        unknowns=[
            {
                "subject": "Kubernetes API network reachability from the processing namespace",
                "reason": "Not stated in the supplied description.",
                "would_be_resolved_by": "A NetworkPolicy or CNI configuration covering the "
                "API server endpoint.",
            }
        ],
        unsupported=[],
        residual_uncertainty=(
            "Every path in this record is derived from a description captured "
            "2026-06-01T00:00:00+00:00 and asserted by an operator. TrustLens cannot "
            "verify that the description matched production when captured, nor that it "
            "still does. One contradiction is unresolved and one reachability question "
            "is unanswerable from the supplied inputs."
        ),
        claims={
            "establishes": [
                "The configured reachability derivable from the supplied descriptions "
                "under the recorded interpretation rules, as of 2026-06-01T00:00:00+00:00.",
                "One contradiction between the operator's assertion and the supplied "
                "NetworkPolicy.",
            ],
            "does_not_establish": [
                "That the supplied descriptions match current production.",
                "That any credential is valid or any reachable service is exploitable.",
                "That every identity or network path has been modelled.",
                "That a path absent from this model is impossible.",
            ],
        },
        environment_description_ref=ENV_REF,
        sandbox=None,
    )


# --------------------------------------------------------------------------------------
# 3. Sandbox (Phase 3) — EXPERIMENTAL, banner carried in the evidence itself.
# --------------------------------------------------------------------------------------

EXPERIMENTAL_BANNER = "EXPERIMENTAL — DO NOT USE FOR SUSPECTED ZERO-DAY OR HOSTILE ARTIFACTS"


def sandbox_record() -> dict:
    scope = make_scope(
        analysed=["loader.py"],
        languages=["python"],
    )
    sandbox = {
        "sandbox_status": "EXPERIMENTAL",
        "security_review_complete": False,
        "review_record_hash": None,
        "approved_profiles": [],
        "profile_used": "fixture-only",
        "isolation_mechanism": "PLACEHOLDER — selected in Phase 3, not in Phase 0",
        "isolation_version": "unset",
        "host_kernel": "unset",
        "image_or_vm_hash": "0" * 64,
        "policy_hashes": {},
        "network_rules": ["deny-all-egress (illustrative)"],
        "environment_allowlist": ["PATH", "HOME"],
        "mounted_paths": ["/workspace/scratch:rw"],
        "resource_limits": {"memory_bytes": 536870912, "pids": 64},
        "timeout_seconds": 30,
        "command": "python -c 'import loader; loader.build()'",
        "termination_reason": "completed",
        "banner": EXPERIMENTAL_BANNER,
    }

    observed_network = make_finding(
        capability="cloud.metadata_endpoint",
        status="FOUND",
        detection_method="dynamic_blocked_observation",
        rule_id="observed-metadata-attempt",
        rule_version="1.0.0",
        source_component="sandbox",
        scope=scope,
        evidence=[
            make_evidence(
                kind="network_event",
                path=None,
                detail="connect() to 169.254.169.254:80 — blocked by sandbox egress policy",
                excerpt="tcp 169.254.169.254:80 EPERM",
            )
        ],
        confidence_basis=(
            "The process attempted a connection to the IPv4 cloud metadata address and "
            "the configured egress policy blocked it. Both the attempt and the block "
            "were recorded during this run."
        ),
        limitations=[
            "Establishes what happened in this one execution, under this profile, with "
            "these inputs. It does not establish behavior under other inputs.",
            "Does not establish that the block would hold outside this sandbox.",
            "Absence of further attempts does not establish absence of dormant behavior.",
        ],
    )

    scratch_write = make_finding(
        capability="filesystem.write",
        status="FOUND",
        detection_method="dynamic_observation",
        rule_id="observed-file-write",
        rule_version="1.0.0",
        source_component="sandbox",
        scope=scope,
        evidence=[
            make_evidence(
                kind="filesystem_event",
                path="/workspace/scratch/part-0000.arrow",
                detail="openat(O_WRONLY|O_CREAT) succeeded — inside the allowed scratch mount",
            )
        ],
        confidence_basis="A write to the allowed scratch mount was observed and permitted.",
        limitations=[
            "Establishes only what this execution did.",
            "Permitted here by design; this is a positive control for the allow path.",
        ],
    )

    return make_record(
        component="sandbox",
        tool_version=TOOL_VERSION,
        commit=COMMIT,
        artifact={
            "artifact_id": "example-dataset-repo",
            "artifact_type": "huggingface_dataset_repository",
            "declared_kind": "dataset",
            "source": "https://huggingface.co/datasets/example-org/example-tabular",
            "immutable_reference": "9f2c1a4e5b6d7c8f9a0b1c2d3e4f5a6b7c8d9e0f",
            "acquisition_method": "already_local",
            "acquisition_authorised_by": None,
            "acquired_at": "2026-07-20T09:00:00+00:00",
            "content_hash": "b" * 64,
            "content_hash_method": "directory_manifest_v1",
            "file_count": 23,
            "total_bytes": 184320,
        },
        run={
            "started_at": "2026-07-20T11:00:00+00:00",
            "completed_at": "2026-07-20T11:00:31+00:00",
            "execution_mode": "sandboxed_execution",
            "invocation": "trustlens sandbox-run ./example-tabular --profile fixture-only",
            "config_hash": None,
            "reasoning_notes": [
                EXPERIMENTAL_BANNER,
                "Sandbox status EXPERIMENTAL: no validated security review record is "
                "present, so no hostile-input profile is available.",
                "This example record is illustrative of the schema. The isolation "
                "mechanism is chosen in Phase 3 and is a placeholder here.",
            ],
        },
        scope=scope,
        declared_capabilities=[],
        findings=[observed_network, scratch_write],
        contradictions=[],
        unknowns=[
            {
                "subject": "Behavior under inputs other than the one supplied",
                "reason": "Only one execution with one input was performed.",
                "would_be_resolved_by": "Further executions; note that no finite set of "
                "executions establishes absence of conditionally triggered behavior.",
            }
        ],
        unsupported=[],
        residual_uncertainty=(
            "This record describes one execution under an EXPERIMENTAL sandbox whose "
            "isolation boundary has not been reviewed. It carries no containment claim."
        ),
        claims={
            "establishes": [
                "The artifact exhibited the recorded behaviors during this recorded execution.",
                "The configured sandbox blocked or allowed the recorded operations as recorded.",
                "The exact sandbox profile and environment used are preserved in this record.",
            ],
            "does_not_establish": [
                "Absence of dormant, delayed or conditionally triggered behavior.",
                "Safety under different inputs.",
                "Resistance to unknown sandbox escapes.",
                "That the artifact is safe to run in production.",
                "That the observed behavior matches behavior outside the sandbox.",
            ],
        },
        environment_description_ref=None,
        sandbox=sandbox,
    )


# --------------------------------------------------------------------------------------
# 4. Blast radius (Phase 4) — composition, with a PARTIAL edge carried through.
# --------------------------------------------------------------------------------------

def blast_radius_record(scanner: dict, mapper: dict) -> dict:
    scan_by_capability = {f["capability"]: f for f in scanner["findings"]}
    map_by_capability = {f["capability"]: f for f in mapper["findings"]}

    exec_edge = scan_by_capability["execution.dynamic_import"]
    cred_edge = map_by_capability["env.credential_pattern_read"]
    s3_edge = map_by_capability["reachability.resource_access"]
    partial_edge = scan_by_capability["template.injection_surface"]

    scope = make_scope(
        analysed=[exec_edge["finding_id"], cred_edge["finding_id"], s3_edge["finding_id"]],
        languages=["trustlens_evidence"],
    )

    path = make_finding(
        capability="reachability.resource_access",
        status="FOUND",
        detection_method="graph_derivation",
        rule_id="path-exec-to-credential-to-resource",
        rule_version="1.0.0",
        source_component="blast_radius",
        scope=scope,
        derived_from=[
            exec_edge["finding_id"],
            cred_edge["finding_id"],
            s3_edge["finding_id"],
        ],
        environment_description_ref=ENV_REF,
        evidence=[
            make_evidence(
                kind="graph_edge",
                path=None,
                detail=(
                    "dataset worker -> Python execution (static, loader.py:14) -> AWS "
                    "credential readable (configured, captured 2026-06-01) -> "
                    "s3:GetObject on prod-data (configured, captured 2026-06-01)"
                ),
            )
        ],
        confidence_basis=(
            "Composed from one static finding and two configuration-derived findings. "
            "The weakest input is CONFIG_DERIVED and the composition is INFERRED, so "
            "this path is a modelled path, not an observed one."
        ),
        limitations=[
            "No edge in this path was dynamically observed.",
            "The credential and policy edges rest on a description captured 2026-06-01 "
            "and may be stale.",
            "Composition does not establish that the path is traversable end to end.",
            "This is a simulation, not a penetration test.",
        ],
    )

    partial_path = make_finding(
        capability="template.injection_surface",
        status="PARTIAL",
        detection_method="graph_derivation",
        rule_id="path-template-injection-entry",
        rule_version="1.0.0",
        source_component="blast_radius",
        scope=make_scope(
            analysed=[partial_edge["finding_id"]],
            languages=["trustlens_evidence"],
            failed=[
                {
                    "path": "config/legacy.yaml",
                    "reason": "Upstream scanner finding is PARTIAL: this file was never "
                    "analysed, so no entry-point conclusion can be drawn from it.",
                    "kind": "parse_error",
                }
            ],
        ),
        derived_from=[partial_edge["finding_id"]],
        confidence_basis=(
            "The upstream template-injection check did not complete over its intended "
            "scope, so this entry point can be neither confirmed nor excluded. The "
            "incompleteness propagates rather than being discharged here."
        ),
        limitations=[
            "This path must not be rendered with the confidence of a fully evidenced path.",
            "It must equally not be dropped from the report; a silently omitted "
            "incomplete path reads as an excluded path.",
        ],
    )

    mitigations = [
        {
            "mitigation_id": "M-001",
            "triggering_finding_ids": [s3_edge["finding_id"], path["finding_id"]],
            "affected_resource": "IAM role dataset-worker-role",
            "proposed_change": (
                "Remove the s3:GetObject Allow on arn:aws:s3:::prod-data/* from "
                "dataset-worker-role, or scope it to the specific prefixes the loader "
                "requires."
            ),
            "expected_path_removed": (
                "dataset worker -> AWS credential -> s3:GetObject on prod-data"
            ),
            "trade_offs": (
                "Any legitimate loader path that reads prod-data will fail until the "
                "required prefixes are enumerated and re-granted."
            ),
            "evidence_basis": (
                "Statement 0 of the attached role policy, from an environment "
                "description captured 2026-06-01T00:00:00+00:00."
            ),
            "dynamically_verified": False,
            "residual_risk": (
                "Other roles assumable by the worker were not supplied and were not "
                "modelled; removing this grant does not address them."
            ),
            "environment_description_ref": ENV_REF,
        },
        {
            "mitigation_id": "M-002",
            "triggering_finding_ids": [
                map_by_capability["cloud.metadata_endpoint"]["finding_id"]
            ],
            "affected_resource": (
                "NetworkPolicy dataset-processing, egress rule 0"
            ),
            "proposed_change": (
                "Add an except clause for 169.254.169.254/32 (and fd00:ec2::254/128 "
                "where IPv6 egress is permitted) to the 0.0.0.0/0 egress ipBlock."
            ),
            "expected_path_removed": (
                "dataset worker -> cloud metadata endpoint -> instance role credentials"
            ),
            "trade_offs": (
                "Workloads in this namespace that legitimately read instance metadata "
                "will break; those should use projected service-account tokens instead."
            ),
            "evidence_basis": (
                "The supplied NetworkPolicy permits the link-local range, contradicting "
                "the operator's assertion that metadata access is blocked "
                "(contradiction C-101)."
            ),
            "dynamically_verified": False,
            "residual_risk": (
                "A CNI-level block may already exist and was not described; if so this "
                "change is redundant rather than harmful."
            ),
            "environment_description_ref": ENV_REF,
        },
    ]

    return make_record(
        component="blast_radius",
        tool_version=TOOL_VERSION,
        commit=COMMIT,
        artifact={
            "artifact_id": "example-dataset-repo",
            "artifact_type": "huggingface_dataset_repository",
            "declared_kind": "dataset",
            "source": "https://huggingface.co/datasets/example-org/example-tabular",
            "immutable_reference": "9f2c1a4e5b6d7c8f9a0b1c2d3e4f5a6b7c8d9e0f",
            "acquisition_method": "already_local",
            "acquisition_authorised_by": None,
            "acquired_at": "2026-07-20T09:00:00+00:00",
            "content_hash": "b" * 64,
            "content_hash_method": "directory_manifest_v1",
            "file_count": 23,
            "total_bytes": 184320,
        },
        run={
            "started_at": "2026-07-20T12:00:00+00:00",
            "completed_at": "2026-07-20T12:00:01+00:00",
            "execution_mode": "offline_modelling",
            "invocation": "trustlens blast-radius --scan scan.json --env env.json",
            "config_hash": None,
            "reasoning_notes": [
                "Composed 1 fully-evidenced path and 1 incomplete path.",
                "The incomplete path is retained and labelled; dropping it would read as "
                "an excluded path.",
                "Two configuration-derived edges carry capture time "
                "2026-06-01T00:00:00+00:00.",
            ],
        },
        scope=scope,
        declared_capabilities=[],
        findings=[path, partial_path],
        contradictions=[],
        mitigations=mitigations,
        generic_advice=[
            "Review whether dataset-processing workloads need any standing cloud "
            "credentials at all, after the specific changes above are applied."
        ],
        unknowns=[
            {
                "subject": "Whether the modelled path is traversable end to end",
                "reason": "No edge in the path was dynamically observed.",
                "would_be_resolved_by": "A sandboxed execution under a reviewed profile.",
            }
        ],
        unsupported=[],
        residual_uncertainty=(
            "This is a simulation over declared, configured, static and inferred "
            "evidence, two edges of which rest on a description captured "
            "2026-06-01T00:00:00+00:00. One path is incomplete because an upstream check "
            "did not finish. Paths not modelled here are not thereby excluded."
        ),
        claims={
            "establishes": [
                "The simulator combined the supplied static and configured evidence.",
                "The displayed paths follow the recorded graph composition rules.",
                "Each mitigation corresponds to identified findings.",
            ],
            "does_not_establish": [
                "That the simulation contains every attacker path.",
                "That inferred paths are exploitable.",
                "That blocked paths remain blocked in production.",
                "That the mitigations are operationally safe without engineering review.",
                "That this is a penetration test.",
            ],
        },
        environment_description_ref=ENV_REF,
        sandbox=None,
        input_records=[
            {
                "record_id": scanner["record_id"],
                "content_hash": scanner["content_hash"],
                "component": "scanner",
            },
            {
                "record_id": mapper["record_id"],
                "content_hash": mapper["content_hash"],
                "component": "credential_mapper",
            },
        ],
    )


def main() -> None:
    scanner = scanner_record()
    mapper = credential_mapper_record()
    _write("scanner_record.json", scanner)
    _write("credential_mapper_record.json", mapper)
    _write("sandbox_record.json", sandbox_record())
    corpus = {r["record_id"]: r for r in (scanner, mapper)}
    _write("blast_radius_record.json", blast_radius_record(scanner, mapper), corpus=corpus)


if __name__ == "__main__":
    main()
