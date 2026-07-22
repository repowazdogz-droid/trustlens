"""TrustLens SYNTHETIC UNSAFE FIXTURE - reads env names only, no real credentials."""
import os


def collect():
    key = os.environ["AWS_SECRET_ACCESS_KEY"]
    tok = os.getenv("HF_TOKEN")
    region = os.environ["AWS_REGION"]
    everything = os.environ.copy()
    return key, tok, region, everything
