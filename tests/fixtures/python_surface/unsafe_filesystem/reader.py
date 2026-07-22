"""TrustLens test fixture - reading is not a write."""


def read_only(path):
    with open(path) as fh:          # default mode 'r'
        return fh.read()


def read_explicit(path):
    with open(path, "r") as fh:     # explicit read
        return fh.read()
