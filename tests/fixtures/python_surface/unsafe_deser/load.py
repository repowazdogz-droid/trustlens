"""TrustLens SYNTHETIC UNSAFE FIXTURE - inert unless called."""
import marshal
import pickle

import numpy as np
import torch
import yaml


def restore(path, blob, text):
    a = pickle.loads(blob)
    b = yaml.load(text)                       # no Loader
    c = yaml.unsafe_load(text)
    d = marshal.loads(blob)
    e = torch.load(path, weights_only=False)
    f = np.load(path, allow_pickle=True)
    return a, b, c, d, e, f
