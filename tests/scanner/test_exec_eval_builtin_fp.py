r"""Regression control for the `re.compile` false positive found in the first external study.

Study reference: `study/results/DIVERGENCE_CATALOGUE.md` D1, `study/results/PHASE1_VERIFICATIONS.md`
V2/D1. The `exec-eval-builtin` rule targeted the bare name `compile`, and the call matcher
exposed the last segment of a qualified call, so `re.compile(r'\s+')` matched the builtin
`compile` and was reported `execution.dynamic_eval` = FOUND — a false positive on a `FOUND`,
which is a soundness violation of the scanner's contract.

The fix qualifies builtin targets to unqualified calls only (`Rule.match_suffix=False`). This
control locks it in **both directions**: the false positives must stay NOT_FOUND, and the real
builtins must stay FOUND. A fix that silenced the FP by matching nothing would fail the second
half.
"""

from __future__ import annotations

import ast

import pytest

from trustlens.scanner.checks import python_surface as ps
from trustlens.scanner.pysource import PythonFile


def _dynamic_eval_hits(src: str, aliases: dict[str, str] | None = None) -> list[str]:
    pf = PythonFile(path="t.py", tree=ast.parse(src), aliases=aliases or {})
    return [
        h.matched_name
        for h in ps.scan_file(pf)
        if h.rule.capability == "execution.dynamic_eval"
    ]


# --------------------------------------------------------- the false positives must NOT fire

def test_re_compile_the_exact_study_case_is_not_flagged():
    """`re.compile(r'\\s+')` — the verbatim line from codeparrot/github-code — is a regex
    compile, not dynamic code evaluation. It must be NOT_FOUND."""
    hits = _dynamic_eval_hits("import re\nPATTERN = re.compile(r'\\s+')\n", {"re": "re"})
    assert hits == [], f"re.compile must not match execution.dynamic_eval; got {hits}"


def test_pandas_df_eval_is_not_flagged():
    """`df.eval(...)` (pandas) matched the bare builtin `eval` before the fix."""
    assert _dynamic_eval_hits("df.eval('a + b')\n") == []


def test_keras_model_compile_is_not_flagged():
    """`model.compile(...)` (Keras) — ubiquitous in ML repos — matched bare `compile`."""
    assert _dynamic_eval_hits("model.compile(optimizer='adam')\n") == []


def test_chained_model_eval_is_not_flagged():
    """`get_model().eval()` (PyTorch) is a chained call; its bare attribute must not match the
    builtin `eval`. This is the subtle case a naive fix would miss."""
    assert _dynamic_eval_hits("get_model().eval()\n") == []


# ---------------------------------------------- the real builtins must STILL fire (positive control)

def test_bare_eval_still_fires():
    """The whole point: an unqualified `eval(...)` is a real dynamic-eval and must be FOUND."""
    hits = _dynamic_eval_hits("result = eval(user_input)\n")
    assert "eval" in hits, "unqualified eval() must still be FOUND"


def test_bare_compile_still_fires():
    """An unqualified `compile(...)` builtin must be FOUND — the fix must not silence it."""
    hits = _dynamic_eval_hits("code = compile(s, '<s>', 'exec')\n")
    assert "compile" in hits, "unqualified compile() must still be FOUND"


def test_bare_exec_still_fires():
    assert "exec" in _dynamic_eval_hits("exec(payload)\n")


def test_explicit_builtins_qualified_form_still_fires():
    """`builtins.eval(...)` is an explicit builtin reference and must be FOUND."""
    hits = _dynamic_eval_hits("import builtins\nbuiltins.eval(x)\n", {"builtins": "builtins"})
    assert "builtins.eval" in hits


def test_the_rule_is_marked_builtin_only():
    """The mechanism, asserted directly: exec-eval-builtin must not suffix-match."""
    rule = next(r for r in ps.RULES if r.rule_id == "exec-eval-builtin")
    assert rule.match_suffix is False


def test_intentional_suffix_rules_are_unaffected():
    """The fix must not disturb the deliberate method-name over-reporters (bind/extractall/…)."""
    # x.extractall() must still match archive_extraction via suffix.
    pf = PythonFile(path="t.py", tree=ast.parse("z.extractall()\n"), aliases={})
    caps = {h.rule.capability for h in ps.scan_file(pf)}
    assert "filesystem.archive_extraction" in caps
