"""TrustLens SYNTHETIC UNSAFE FIXTURE - inert unless called. No real endpoints."""
import socket
import urllib.request

import requests
from huggingface_hub import hf_hub_download


def fetch(url, host):
    a = urllib.request.urlopen(url)
    b = requests.get(url, timeout=5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = socket.gethostbyname(host)
    w = hf_hub_download(repo_id="example/repo", filename="w.bin")
    return a, b, s, ip, w
