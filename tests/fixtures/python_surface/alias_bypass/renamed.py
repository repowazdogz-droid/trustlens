"""TrustLens SYNTHETIC UNSAFE FIXTURE - renamed imports must not evade the rules."""
import subprocess as sp
from pickle import loads as unpack
from os import system as run_it


def go(blob, cmd):
    sp.Popen(cmd, shell=True)
    run_it(cmd)
    return unpack(blob)
