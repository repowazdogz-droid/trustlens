"""TrustLens example - benign helper. Local file reads only."""
import json
from pathlib import Path


def load(path: Path):
    with open(path) as fh:                 # read mode: not a write
        return [json.loads(line) for line in fh]


def summarise(rows):
    return {"n": len(rows)}
