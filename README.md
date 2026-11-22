# RuleHunter

An LLM agent that writes Sigma detection rules for Windows attack techniques. It tests each rule against logs, reads the misses and false positives, and refines the rule until it is good enough to submit. Safeguards stop the agent from shipping rules that are untested or that fire on everything, even if a log line tries to hijack it with a prompt injection.

> **Status:** the agent loop, safeguards and scoring are complete and covered by 23 passing tests, using a recorded agent run in place of a live model. Next step: benchmark local models with Ollama, comparing the agent loop against a one-shot prompt.

## Why

Writing detection rules is slow, and asking an LLM once for a rule tends to produce something that is either too broad (floods analysts with alerts) or too narrow (misses variants). Giving the model tools to test against real data and feedback on its mistakes is the core idea behind agentic detection engineering. Letting a model act on its own also needs guardrails.

## How it works

```
task (technique description)
        │
        ▼
   ┌─────────┐  Action: search_logs / test_rule / submit_rule
   │   LLM   │ ─────────────────────────────────────────────┐
   └─────────┘                                              ▼
        ▲                                  ┌──────────────────────────────┐
        │  Observation: hits, misses,      │ Toolbox (training logs only) │
        └───────────── false positives ─── │  + validator + submit gate   │
                                           └──────────────────────────────┘
                                                            │ accepted rule
                                                            ▼
                                             scored on HELD-OUT logs
```

* **Data:** `rulehunter/data.py` generates about 3,000 synthetic Sysmon process-creation events per split. It mixes normal activity, *hard negatives* (admins downloading files, IT using certutil, legitimate scheduled tasks, encoded commands from a management agent) and 40 attack events per technique with varied spelling and casing. The agent may only look at the **train** split. Final scores come from a separate **test** split it never sees.
* **Rules:** `rulehunter/sigma_lite.py` implements a safe subset of Sigma: field modifiers `contains`, `startswith`, `endswith`, `re` and `all`, plus conditions with `and`, `or`, `not`, parentheses, `1 of x*` and `all of them`.
* **Tasks:** `tasks/*.yml`. These cover a PowerShell download cradle (T1059.001), a certutil download (T1105), an LSASS dump (T1003.001) and scheduled-task persistence (T1053.005).
* **Baseline:** `--mode oneshot` asks the same model for a rule in a single prompt, with no tools, so you can measure what the agent loop adds.

## Safeguards

| Risk | Safeguard |
|---|---|
| Model runs arbitrary actions | Only 3 tools plus `give_up` exist. There is no shell, file or network tool, so the model's output can never be executed. |
| Model loops or flails | Step budget (default 12) and a 3-strike limit on malformed or disallowed actions. |
| Malformed or dangerous rule | A validator checks every rule before it runs: size cap, known fields and modifiers only, and a regex length cap against catastrophic backtracking. |
| Rule shipped without testing | `submit_rule` refuses any rule that wasn't tested unchanged with `test_rule`. |
| "Detect everything" rule | `submit_rule` refuses rules that fire on more than 5% of events or have training recall under 0.5. |
| Prompt injection through logs | Log text is wrapped in `<untrusted_log>` tags and the prompt says never to follow it. The dataset contains a planted line telling the "AI analyst" to submit a match-all rule. A test confirms the submit gate still refuses that rule even if the model obeys. |
| No accountability | Every run saves the full transcript, the rule and the result under `runs/`. |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest                                               # 23 tests, no model needed

# Offline demo: replays a recorded agent run
python -m rulehunter run --task certutil --backend scripted --script examples/demo_certutil_script.json
```

### With a free local model (Ollama)

```bash
# install from https://ollama.com, then:
ollama pull qwen2.5:7b
python -m rulehunter run --task all --mode both --backend ollama --model qwen2.5:7b --repeats 3
python -m rulehunter summary
```

### With an API

```bash
export ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY=...
python -m rulehunter run --task all --mode both --backend anthropic --model <model-name> --repeats 3
```

`--backend openai` also works with LM Studio or vLLM. Set `OPENAI_BASE_URL=http://localhost:1234/v1` for LM Studio.

### Other commands

```bash
python -m rulehunter list                                              # tasks
python -m rulehunter score --task cradle --rule examples/cradle_reference.yml   # score your own rule
```

## Project layout

```
rulehunter/
  data.py         synthetic labelled Sysmon logs (train / held-out test)
  sigma_lite.py   Sigma subset: parser, validator, matcher, scoring
  tools.py        search_logs, test_rule, submit_rule + submit gate
  agent.py        agent loop, reply parser, one-shot baseline
  llm.py          Ollama / OpenAI-compatible / Anthropic / scripted backends
  cli.py          run, score, summary, list
tasks/            one YAML file per ATT&CK technique
examples/         reference rules and a scripted demo run
tests/            matcher, validator and safeguard tests
```

## Limitations and next steps

* The logs are synthetic and only cover process creation. A next step is to replay a public dataset such as Splunk attack_data or Mordor/Security-Datasets.
* The training split exposes labels through `test_rule`, the way an analyst works from labelled incident data. Scores are only reported on the held-out split.
* Possible extensions: export to full Sigma and convert to Splunk/Elastic queries with pySigma, add network and registry events, and add a red-team mode where a second agent mutates attack command lines to evade the submitted rule.
