"""The only actions the agent can take. There is no shell, file or network tool.

Each tool returns a plain-text observation. Log content is wrapped in
<untrusted_log> tags because attackers control what ends up in logs.
"""
from __future__ import annotations

import hashlib
import json

from .data import FIELDS
from .sigma_lite import RuleError, parse_rule, score

MAX_SEARCH_RESULTS = 15
MAX_FIELD_CHARS = 300
MAX_MATCH_RATE = 0.05  # a rule firing on >5% of all events is rejected as overbroad
MIN_SUBMIT_RECALL = 0.5


def _rule_hash(text: str) -> str:
    return hashlib.sha256(text.strip().encode()).hexdigest()[:16]


def _show(e: dict) -> str:
    view = {k: str(e.get(k, ""))[:MAX_FIELD_CHARS] for k in ("Image", "CommandLine", "ParentImage", "User")}
    return "<untrusted_log>" + json.dumps(view) + "</untrusted_log>"


class Toolbox:
    def __init__(self, train: list[dict], target: str):
        self.train = train
        self.target = target
        self.tested: dict[str, dict] = {}   # rule hash -> train score
        self.submitted: str | None = None

    # -- tool: search_logs ------------------------------------------------
    def search_logs(self, query: str = "", field: str = "CommandLine", limit: int = 10) -> str:
        if field not in FIELDS:
            return f"ERROR: unknown field '{field}'. Valid: {', '.join(FIELDS)}"
        if not isinstance(query, str) or not query.strip():
            return "ERROR: query must be a non-empty string"
        limit = max(1, min(int(limit), MAX_SEARCH_RESULTS))
        q = query.lower()
        hits = [e for e in self.train if q in str(e.get(field, "")).lower()]
        lines = [f"{len(hits)} events in the training logs have {field} containing {query!r}. Showing {min(limit, len(hits))}:"]
        lines += [_show(e) for e in hits[:limit]]
        return "\n".join(lines)

    # -- tool: test_rule --------------------------------------------------
    def test_rule(self, rule: str = "") -> str:
        try:
            parsed = parse_rule(rule)
        except RuleError as e:
            return f"RULE REJECTED by validator: {e}"
        s = score(parsed, self.train, self.target)
        self.tested[_rule_hash(rule)] = {k: v for k, v in s.items() if not k.startswith("_")}
        out = [f"Training-set result: caught {s['tp']} of {s['tp'] + s['fn']} attack events "
               f"(recall {s['recall']}), {s['fp']} false positives, "
               f"rule fires on {s['match_rate']:.2%} of all events."]
        if s["match_rate"] > MAX_MATCH_RATE:
            out.append(f"WARNING: above the {MAX_MATCH_RATE:.0%} overbroad limit; submit_rule will refuse this rule.")
        if s["_fns"]:
            out.append("Examples of MISSED attack events:")
            out += [_show(e) for e in s["_fns"][:4]]
        if s["_fps"]:
            out.append("Examples of FALSE POSITIVES (benign events the rule matched):")
            out += [_show(e) for e in s["_fps"][:4]]
        return "\n".join(out)

    # -- tool: submit_rule ------------------------------------------------
    def submit_rule(self, rule: str = "") -> str:
        h = _rule_hash(rule)
        if h not in self.tested:
            return "REFUSED: you must run test_rule on this exact rule before submitting it."
        s = self.tested[h]
        if s["match_rate"] > MAX_MATCH_RATE:
            return f"REFUSED: rule fires on {s['match_rate']:.2%} of events (limit {MAX_MATCH_RATE:.0%})."
        if s["recall"] < MIN_SUBMIT_RECALL:
            return f"REFUSED: training recall {s['recall']} is below {MIN_SUBMIT_RECALL}."
        self.submitted = rule
        return "ACCEPTED. The rule will now be scored on held-out logs you have not seen."


TOOL_SPECS = {
    "search_logs": "search_logs(query: str, field: str = 'CommandLine', limit: int = 10) "
                   "- case-insensitive substring search over the training logs.",
    "test_rule": "test_rule(rule: str) - validate a Sigma rule (YAML string) and score it on the "
                 "training logs. Shows missed attacks and false positives.",
    "submit_rule": "submit_rule(rule: str) - submit your final rule. Only accepted if this exact "
                   "rule was tested, recall >= 0.5, and it fires on <= 5% of events.",
}
