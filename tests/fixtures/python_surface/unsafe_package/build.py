"""TrustLens SYNTHETIC UNSAFE FIXTURE - inert unless called."""
import subprocess


def bootstrap():
    subprocess.run("pip install requests==2.31.0", shell=True)
