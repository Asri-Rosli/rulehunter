"""LLM backends. All expose chat(messages) -> str.

- ollama:    a free local model (default http://localhost:11434), e.g. llama3.1, qwen2.5
- openai:    any OpenAI-compatible endpoint (OpenAI, LM Studio, vLLM); key in OPENAI_API_KEY
- anthropic: Claude API; key in ANTHROPIC_API_KEY
- scripted:  replays canned replies from a JSON file, for tests and offline demos
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests

TIMEOUT = 180


class LLM:
    def chat(self, messages: list[dict]) -> str:
        raise NotImplementedError


class Ollama(LLM):
    def __init__(self, model: str, host: str | None = None, temperature: float = 0.2):
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.temperature = temperature

    def chat(self, messages):
        r = requests.post(f"{self.host}/api/chat", timeout=TIMEOUT, json={
            "model": self.model, "messages": messages, "stream": False,
            "options": {"temperature": self.temperature}})
        r.raise_for_status()
        return r.json()["message"]["content"]


class OpenAICompatible(LLM):
    def __init__(self, model: str, base_url: str | None = None, temperature: float = 0.2):
        self.model = model
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.key = os.environ.get("OPENAI_API_KEY", "not-needed-for-local")
        self.temperature = temperature

    def chat(self, messages):
        r = requests.post(f"{self.base_url}/chat/completions", timeout=TIMEOUT,
                          headers={"Authorization": f"Bearer {self.key}"},
                          json={"model": self.model, "messages": messages,
                                "temperature": self.temperature})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class Anthropic(LLM):
    def __init__(self, model: str, temperature: float = 0.2):
        self.model = model
        self.key = os.environ["ANTHROPIC_API_KEY"]
        self.temperature = temperature

    def chat(self, messages):
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        rest = [m for m in messages if m["role"] != "system"]
        r = requests.post("https://api.anthropic.com/v1/messages", timeout=TIMEOUT,
                          headers={"x-api-key": self.key, "anthropic-version": "2023-06-01"},
                          json={"model": self.model, "system": system, "messages": rest,
                                "max_tokens": 2000, "temperature": self.temperature})
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"])


class Scripted(LLM):
    def __init__(self, replies: list[str]):
        self.replies = list(replies)

    @classmethod
    def from_file(cls, path: str | Path):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def chat(self, messages):
        if not self.replies:
            return '{"thought": "out of script", "tool": "give_up", "args": {}}'
        return self.replies.pop(0)


def make_llm(backend: str, model: str | None, script: str | None = None) -> LLM:
    if backend == "scripted":
        if not script:
            raise SystemExit("--script is required with --backend scripted")
        return Scripted.from_file(script)
    if not model:
        raise SystemExit(f"--model is required with --backend {backend}")
    return {"ollama": Ollama, "openai": OpenAICompatible, "anthropic": Anthropic}[backend](model)
