"""A small, safe subset of the Sigma detection-rule format.

Supported:
  detection:
    <name>: {Field|modifier: value | [values]}    # fields AND-ed, list values OR-ed
    <name>: [{...}, {...}]                        # list of maps OR-ed
    condition: sel and not filter / (a or b) / 1 of sel* / all of them
  modifiers: contains, startswith, endswith, re, all (e.g. contains|all)
Matching is case-insensitive, as in Sigma.

Every rule is validated before it touches data. The validator is one of the
agent's safeguards: the LLM's output is treated as untrusted input.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

import yaml

from .data import FIELDS

MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
MAX_RULE_CHARS = 4000
MAX_REGEX_CHARS = 200
MAX_VALUES = 50


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    title: str
    selections: dict
    condition: str
    raw: dict = field(repr=False)
    _cond_fn: object = field(default=None, repr=False)

    def matches(self, event: dict) -> bool:
        return self._cond_fn(event)


# ------------------------------------------------------------- parsing --
def parse_rule(text: str) -> Rule:
    if len(text) > MAX_RULE_CHARS:
        raise RuleError(f"rule is {len(text)} chars; limit is {MAX_RULE_CHARS}")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise RuleError(f"invalid YAML: {e}") from None
    if not isinstance(doc, dict):
        raise RuleError("rule must be a YAML mapping")
    for key in ("title", "logsource", "detection"):
        if key not in doc:
            raise RuleError(f"missing required key '{key}'")
    det = doc["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError("detection must be a mapping with a 'condition'")
    condition = det["condition"]
    if not isinstance(condition, str):
        raise RuleError("condition must be a string")
    selections = {k: v for k, v in det.items() if k != "condition"}
    if not selections:
        raise RuleError("detection needs at least one selection")

    compiled = {name: _compile_selection(name, body) for name, body in selections.items()}
    cond_fn = _compile_condition(condition, compiled)
    return Rule(title=str(doc["title"]), selections=selections, condition=condition,
                raw=doc, _cond_fn=cond_fn)


def _compile_selection(name: str, body):
    if isinstance(body, dict):
        return _compile_map(name, body)
    if isinstance(body, list) and body and all(isinstance(m, dict) for m in body):
        maps = [_compile_map(name, m) for m in body]
        return lambda e: any(m(e) for m in maps)
    raise RuleError(f"selection '{name}' must be a mapping or a list of mappings")


def _compile_map(name: str, m: dict):
    checks = []
    for key, value in m.items():
        parts = str(key).split("|")
        fname, mods = parts[0], parts[1:]
        if fname not in FIELDS:
            raise RuleError(f"selection '{name}': unknown field '{fname}'. Valid: {', '.join(FIELDS)}")
        bad = [x for x in mods if x not in MODIFIERS]
        if bad:
            raise RuleError(f"selection '{name}': unknown modifier(s) {bad}")
        values = value if isinstance(value, list) else [value]
        if not values or len(values) > MAX_VALUES:
            raise RuleError(f"selection '{name}': field '{fname}' needs 1-{MAX_VALUES} values")
        if any(isinstance(v, (dict, list)) for v in values):
            raise RuleError(f"selection '{name}': values must be scalars")
        checks.append(_field_check(name, fname, mods, [str(v) for v in values]))
    if not checks:
        raise RuleError(f"selection '{name}' is empty")
    return lambda e: all(c(e) for c in checks)


def _field_check(name, fname, mods, values):
    want_all = "all" in mods
    kind = next((x for x in mods if x != "all"), "equals")
    if kind == "re":
        pats = []
        for v in values:
            if len(v) > MAX_REGEX_CHARS:
                raise RuleError(f"selection '{name}': regex longer than {MAX_REGEX_CHARS} chars")
            try:
                pats.append(re.compile(v, re.IGNORECASE))
            except re.error as err:
                raise RuleError(f"selection '{name}': bad regex {v!r}: {err}") from None
        test = lambda s, p: p.search(s) is not None  # noqa: E731
        vals = pats
    else:
        vals = [v.lower() for v in values]
        test = {
            "equals": lambda s, v: s == v,
            "contains": lambda s, v: v in s,
            "startswith": lambda s, v: s.startswith(v),
            "endswith": lambda s, v: s.endswith(v),
        }[kind]

    def check(e):
        s = str(e.get(fname, ""))
        s = s if kind == "re" else s.lower()
        agg = all if want_all else any
        return agg(test(s, v) for v in vals)
    return check


# ----------------------------------------------------------- condition --
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_*]*|\d+)")


def _compile_condition(text: str, sels: dict):
    tokens = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise RuleError(f"condition: unexpected text at '{text[pos:]}'")
        tokens.append(m.group(1))
        pos = m.end()
    i = 0

    def peek():
        return tokens[i].lower() if i < len(tokens) else None

    def take():
        nonlocal i
        t = tokens[i]
        i += 1
        return t

    def expr_or():
        left = expr_and()
        while peek() == "or":
            take()
            r = expr_and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, r)
        return left

    def expr_and():
        left = expr_not()
        while peek() == "and":
            take()
            r = expr_not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, r)
        return left

    def expr_not():
        if peek() == "not":
            take()
            inner = expr_not()
            return lambda e: not inner(e)
        return atom()

    def atom():
        t = peek()
        if t is None:
            raise RuleError("condition ends unexpectedly")
        if t == "(":
            take()
            inner = expr_or()
            if peek() != ")":
                raise RuleError("condition: missing ')'")
            take()
            return inner
        if t in ("1", "all") and i + 1 < len(tokens) and tokens[i + 1].lower() == "of":
            quant = take().lower()
            take()  # of
            if peek() is None:
                raise RuleError("condition: 'of' needs a target")
            pattern = take()
            names = list(sels) if pattern.lower() == "them" else fnmatch.filter(sels, pattern)
            if not names:
                raise RuleError(f"condition: '{pattern}' matches no selection")
            fns = [sels[n] for n in names]
            agg = any if quant == "1" else all
            return lambda e: agg(f(e) for f in fns)
        name = take()
        if name not in sels:
            raise RuleError(f"condition references unknown selection '{name}'. Defined: {', '.join(sels)}")
        return sels[name]

    if not tokens:
        raise RuleError("condition is empty")
    fn = expr_or()
    if i != len(tokens):
        raise RuleError(f"condition: unexpected '{tokens[i]}'")
    return fn


# ------------------------------------------------------------- scoring --
def score(rule: Rule, events: list[dict], target: str) -> dict:
    tp = fp = fn = tn = 0
    fps, fns = [], []
    for e in events:
        hit = rule.matches(e)
        pos = e.get("_label") == target
        if hit and pos:
            tp += 1
        elif hit and not pos:
            fp += 1
            fps.append(e)
        elif pos:
            fn += 1
            fns.append(e)
        else:
            tn += 1
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, recall=round(recall, 3),
                precision=round(precision, 3),
                fp_rate=round(fp / (fp + tn), 4) if fp + tn else 0.0,
                match_rate=round((tp + fp) / len(events), 4) if events else 0.0,
                _fps=fps, _fns=fns)
