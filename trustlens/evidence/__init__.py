"""TrustLens shared evidence model.

Every TrustLens component emits records conforming to `schemas/evidence_record.schema.json`
so that declared, static, configured and dynamic evidence about the same artifact can be
compared directly. The rules that make that comparison trustworthy live here rather than
in documentation, because a rule that exists only in a document is a rule that a later
component can violate without noticing.
"""

from .builder import make_evidence, make_finding, make_record, make_scope
from .canonical import (
    NonCanonicalValueError,
    canonical_bytes,
    compute_content_hash,
    compute_finding_id,
    compute_record_id,
    seal,
)
from .consume import CapabilityView, FindingIndex
from .schema import (
    SCHEMA_VERSION,
    SchemaValidationError,
    load_record,
    load_schemas,
    schema_set,
    validate_record,
    validate_semantics,
    validate_structure,
)
from .status import (
    IncompleteAnalysisError,
    Status,
    StatusComparisonError,
    absence_within_scope,
    combine,
    is_complete,
    parse,
    require_complete_scope,
)

__all__ = [
    "SCHEMA_VERSION",
    "CapabilityView",
    "FindingIndex",
    "IncompleteAnalysisError",
    "NonCanonicalValueError",
    "SchemaValidationError",
    "Status",
    "StatusComparisonError",
    "absence_within_scope",
    "canonical_bytes",
    "combine",
    "compute_content_hash",
    "compute_finding_id",
    "compute_record_id",
    "is_complete",
    "load_record",
    "load_schemas",
    "make_evidence",
    "make_finding",
    "make_record",
    "make_scope",
    "parse",
    "require_complete_scope",
    "schema_set",
    "seal",
    "validate_record",
    "validate_semantics",
    "validate_structure",
]
