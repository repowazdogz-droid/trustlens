"""TrustLens test fixture - benign dataset loader."""
import csv
import json
from pathlib import Path


def load(path: Path):
    rows = list(csv.reader(path.open()))
    meta = json.loads((path.parent / "meta.json").read_text())
    return rows, meta
