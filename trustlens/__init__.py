"""TrustLens — declared-versus-reachable analysis for untrusted ML datasets and repositories.

TrustLens compares what an ML dataset or repository is declared to be with what static
analysis, deployment configuration, and controlled execution show it can actually do. It
maps potential credential and network reachability and simulates evidence-supported blast
radius. It does not determine malicious intent, certify artifacts as safe, or guarantee
containment.
"""

__version__ = "0.1.0"
