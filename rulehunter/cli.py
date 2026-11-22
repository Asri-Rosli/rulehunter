"""Command line entry point.

  python -m rulehunter list
  python -m rulehunter run --task certutil --backend ollama --model qwen2.5:7b
  python -m rulehunter run --task all --mode both --backend ollama --model qwen2.5:7b --repeats 3
  python -m rulehunter score --task certutil --rule examples/certutil_reference.yml
"""
from __future__ import annotations

import argparse
import csv
import json
import time
from dataclasses import asdict
from pathlib import Path

import yaml

from .agent import run_agent, run_oneshot
from .data import ensure_dataset
from .llm import make_llm
from .sigma_lite import RuleError, parse_rule, score
from .tools import Toolbox

ROOT = Path(__file__).resolve().parent.parent
TASK_DIR = ROOT / "tasks"
DATA_DIR = ROOT / "data"
RUNS_DIR = ROOT / "runs"


def load_tasks() -> dict[str, dict]:
    return {p.stem: yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(TASK_DIR.glob("*.yml"))}


def evaluate(rule_text: str | None, events: list[dict], target: str) -> dict:
    if not rule_text:
        return dict(valid=False, error="no rule submitted", recall=0.0, fp=0, fp_rate=0.0, precision=0.0)
    try:
        rule = parse_rule(rule_text)
    except RuleError as e:
        return dict(valid=False, error=str(e), recall=0.0, fp=0, fp_rate=0.0, precision=0.0)
    s = score(rule, events, target)
    return dict(valid=True, **{k: v for k, v in s.items() if not k.startswith("_")})


def cmd_run(args):
    tasks = load_tasks()
    names = list(tasks) if args.task == "all" else [args.task]
    for n in names:
        if n not in tasks:
            raise SystemExit(f"unknown task '{n}'. Try: {', '.join(tasks)}")
    train, test = ensure_dataset(DATA_DIR)
    modes = ["agent", "oneshot"] if args.mode == "both" else [args.mode]
    RUNS_DIR.mkdir(exist_ok=True)
    csv_path = RUNS_DIR / "results.csv"
    new_csv = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_csv:
            w.writerow(["time", "task", "mode", "backend", "model", "repeat", "stop_reason", "steps",
                        "valid", "test_recall", "test_fp", "test_fp_rate", "test_precision", "seconds"])
        for name in names:
            task = tasks[name]
            for mode in modes:
                for rep in range(1, args.repeats + 1):
                    llm = make_llm(args.backend, args.model, args.script)
                    t0 = time.time()
                    if mode == "agent":
                        tb = Toolbox(train, task["label"])
                        res = run_agent(llm, task, tb, max_steps=args.max_steps)
                    else:
                        res = run_oneshot(llm, task, train, seed=rep)
                    secs = round(time.time() - t0, 1)
                    ev = evaluate(res.rule, test, task["label"])
                    run_dir = RUNS_DIR / f"{time.strftime('%Y%m%d-%H%M%S')}_{name}_{mode}_{rep}"
                    run_dir.mkdir(parents=True)
                    (run_dir / "transcript.json").write_text(
                        json.dumps([asdict(s) for s in res.steps], indent=2), encoding="utf-8")
                    (run_dir / "rule.yml").write_text(res.rule or "", encoding="utf-8")
                    (run_dir / "result.json").write_text(json.dumps(
                        dict(task=name, mode=mode, stop_reason=res.stop_reason, test=ev), indent=2), encoding="utf-8")
                    w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), name, mode, args.backend, args.model or "",
                                rep, res.stop_reason, len(res.steps), ev["valid"], ev.get("recall", 0),
                                ev.get("fp", 0), ev.get("fp_rate", 0), ev.get("precision", 0), secs])
                    f.flush()
                    print(f"[{name} | {mode} | run {rep}] {res.stop_reason}, {len(res.steps)} steps -> "
                          f"held-out recall {ev.get('recall', 0)}, false positives {ev.get('fp', 0)}"
                          + ("" if ev["valid"] else f"  ({ev['error']})"))
    print(f"\nResults appended to {csv_path}. Summarise with: python -m rulehunter summary")


def cmd_score(args):
    tasks = load_tasks()
    _, test = ensure_dataset(DATA_DIR)
    ev = evaluate(Path(args.rule).read_text(encoding="utf-8"), test, tasks[args.task]["label"])
    print(json.dumps(ev, indent=2))


def cmd_summary(_args):
    path = RUNS_DIR / "results.csv"
    if not path.exists():
        raise SystemExit("no runs yet")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r["task"], r["mode"], r["model"]), []).append(r)
    print(f"{'task':<12} {'mode':<8} {'model':<18} {'runs':>4} {'valid':>6} {'recall':>7} {'FP':>6}")
    for (task, mode, model), rs in sorted(groups.items()):
        n = len(rs)
        valid = sum(r["valid"] == "True" for r in rs)
        rec = sum(float(r["test_recall"]) for r in rs) / n
        fp = sum(int(r["test_fp"]) for r in rs) / n
        print(f"{task:<12} {mode:<8} {model[:18]:<18} {n:>4} {valid:>6} {rec:>7.2f} {fp:>6.1f}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="rulehunter", description="LLM agent that writes and tests Sigma detection rules")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list tasks").set_defaults(fn=lambda a: [print(f"{k:<12} {v['title']}") for k, v in load_tasks().items()])
    r = sub.add_parser("run", help="run the agent and/or one-shot baseline")
    r.add_argument("--task", default="all")
    r.add_argument("--mode", choices=["agent", "oneshot", "both"], default="agent")
    r.add_argument("--backend", choices=["ollama", "openai", "anthropic", "scripted"], default="ollama")
    r.add_argument("--model")
    r.add_argument("--script", help="JSON list of replies for --backend scripted")
    r.add_argument("--max-steps", type=int, default=12)
    r.add_argument("--repeats", type=int, default=1)
    r.set_defaults(fn=cmd_run)
    s = sub.add_parser("score", help="score a hand-written rule on the held-out logs")
    s.add_argument("--task", required=True)
    s.add_argument("--rule", required=True)
    s.set_defaults(fn=cmd_score)
    sub.add_parser("summary", help="average results per task/mode/model").set_defaults(fn=cmd_summary)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
