"""TrustLens SYNTHETIC UNSAFE EXAMPLE - every call sits inside a function and is inert."""
import importlib
import pickle
import subprocess
import urllib.request

import datasets
import yaml


class SensorReadings(datasets.GeneratorBasedBuilder):
    def _info(self):
        return datasets.DatasetInfo(description="sensor readings")

    def _split_generators(self, dl_manager):
        cfg = yaml.load(open("loader_config.yaml").read())      # no Loader
        mod = importlib.import_module(cfg["builder_module"])
        blob = urllib.request.urlopen(cfg["remote"]).read()
        subprocess.run(f"tar xf {cfg['archive']}", shell=True)
        return pickle.loads(blob), mod
