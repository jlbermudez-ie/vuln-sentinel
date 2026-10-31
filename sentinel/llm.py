"""OpenRouter client (OpenAI-compatible chat completions) + a mock for tests."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import requests


class LLMError(RuntimeError):
    pass


def _extract_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    else:
        a, b = text.find("{"), text.rfind("}")
        if a == -1 or b == -1:
            raise LLMError(f"no JSON object in model output: {text[:200]!r}")
        text = text[a:b + 1]
    return json.loads(text)


class OpenRouterLLM:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.key = os.environ.get("OPENROUTER_API_KEY")
        if not self.key:
            raise LLMError("OPENROUTER_API_KEY is not set")
        self.calls = 0
        self.max_calls = int(cfg.get("max_calls_per_run", 8))

    def json(self, task: str, system: str, user: str) -> dict:
        if self.calls >= self.max_calls:
            raise LLMError(f"max_calls_per_run={self.max_calls} reached; skipping further model calls")
        self.calls += 1
        body = {
            "model": self.cfg["model"],
            "temperature": self.cfg.get("temperature", 0),
            "max_tokens": self.cfg.get("max_tokens", 4000),
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        headers = {
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            # Optional attribution headers recognised by OpenRouter
            "HTTP-Referer": os.getenv("GITHUB_SERVER_URL", "https://github.com") + "/" + os.getenv("GITHUB_REPOSITORY", "vuln-sentinel"),
            "X-Title": "vuln-sentinel",
        }
        last = None
        for _ in range(2):  # one retry on malformed JSON
            r = requests.post(f"{self.cfg['base_url']}/chat/completions", json=body, headers=headers, timeout=180)
            if r.status_code >= 400:
                raise LLMError(f"OpenRouter {r.status_code}: {r.text[:500]}")
            content = r.json()["choices"][0]["message"]["content"]
            try:
                return _extract_json(content)
            except (json.JSONDecodeError, LLMError) as e:
                last = e
                body["messages"].append({"role": "assistant", "content": content})
                body["messages"].append({"role": "user", "content": "Return ONLY the JSON object, no prose."})
        raise LLMError(f"model never returned valid JSON: {last}")


class MockLLM:
    """Returns canned answers from <dir>/<task>.json — used by tests and offline labs."""

    def __init__(self, directory: Path):
        self.dir = directory
        self.calls: list[tuple[str, str]] = []

    def json(self, task: str, system: str, user: str) -> dict:
        self.calls.append((task, user))
        return json.loads((self.dir / f"{task}.json").read_text())


def make_llm(cfg: dict, mock_dir: Path | None = None):
    return MockLLM(mock_dir) if mock_dir else OpenRouterLLM(cfg)
