import subprocess
# UTF-8 BOM-prefixed source, as shipped by k9cli/video-vec2wav2-tokenizer (study corpus).
# Before the fix this failed ast.parse with "invalid non-printable character U+FEFF".
def run():
    subprocess.run(["echo", "hi"], shell=True)
