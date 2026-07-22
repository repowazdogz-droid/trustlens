"""TrustLens test fixture - a dataset loading script named after its directory."""
import datasets


class MyDataset(datasets.GeneratorBasedBuilder):
    def _info(self):
        return datasets.DatasetInfo(description="fixture")

    def _split_generators(self, dl_manager):
        return []
