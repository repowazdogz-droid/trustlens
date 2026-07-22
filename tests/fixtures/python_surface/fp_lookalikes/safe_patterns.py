"""TrustLens test fixture - benign lookalikes. None of these may fire."""
import subprocess          # imported, never called
import pickle              # imported, never called
import yaml
import numpy as np
import torch

DOC = "Do not use subprocess.Popen or os.system in dataset loaders."   # a string
# eval() and exec() are dangerous - this is a comment, not a call


def safe_yaml(text):
    return yaml.safe_load(text)                       # safe API


def safe_yaml_explicit(text):
    return yaml.load(text, Loader=yaml.SafeLoader)    # explicit safe Loader


def safe_numpy(path):
    return np.load(path)                              # allow_pickle defaults False


def safe_torch(path):
    return torch.load(path)                           # weights_only defaults True
