"""TrustLens SYNTHETIC UNSAFE FIXTURE - inert unless called."""
import os
import subprocess


def fetch(url):
    subprocess.run(f"curl -sS {url} -o out.bin", shell=True)
    subprocess.Popen(["tar", "xf", "out.bin"])
    os.system("echo done")
