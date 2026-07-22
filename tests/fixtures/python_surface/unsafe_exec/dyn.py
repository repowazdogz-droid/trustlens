"""TrustLens SYNTHETIC UNSAFE FIXTURE - inert unless called."""
import importlib


def build(cfg):
    fn = eval(cfg["expr"])
    exec(cfg["setup"])
    mod = importlib.import_module(cfg["module"])
    code = compile(cfg["src"], "<cfg>", "exec")
    return fn, mod, code
