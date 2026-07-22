import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EXAMPLES = ROOT / "examples" / "records"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def example_records() -> dict[str, dict]:
    """Every generated example record, keyed by filename stem."""
    records = {}
    for path in sorted(EXAMPLES.glob("*.json")):
        records[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    assert records, "no example records found; run examples/generate_examples.py"
    return records


@pytest.fixture(scope="session")
def corpus(example_records) -> dict[str, dict]:
    """Example records keyed by record_id, for cross-record reference resolution."""
    return {r["record_id"]: r for r in example_records.values()}
