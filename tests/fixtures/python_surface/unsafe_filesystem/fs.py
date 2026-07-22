"""TrustLens SYNTHETIC UNSAFE FIXTURE - inert unless called."""
import os
import shutil
import tarfile

KEY_PATH = "~/.ssh/id_rsa"
ESCAPE = "../../etc/hosts"


def stage(src, dst):
    with open(dst, "w") as fh:
        fh.write("x")
    tarfile.open(src).extractall(path=dst)
    os.chmod(dst, 0o777)
    shutil.rmtree(dst)
