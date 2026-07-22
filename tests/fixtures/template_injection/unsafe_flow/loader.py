"""TrustLens SYNTHETIC UNSAFE FIXTURE - renders a config-supplied template."""
import yaml
from jinja2 import Template


def build(path):
    cfg = yaml.safe_load(open(path).read())
    rendered = Template(cfg["prompt_template"]).render(name="world")
    return rendered
