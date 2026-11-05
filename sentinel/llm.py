"""OpenAI-compatible chat client. Point LLM_BASE_URL / LLM_MODEL at any model you run."""

import json
import os
import re

from .cache import cached, http_json


def enabled() -> bool:
    return bool(os.environ.get("LLM_BASE_URL") and os.environ.get("LLM_MODEL"))


def chat_json(system: str, user: str, sample: int = 0, temperature: float = 0.2, vary: bool = True) -> dict:
    """Ask for a JSON object. `sample` separates repeated votes in the cache.

    SENTINEL_RUN=n re-samples every call with vary=True (repeat experiments); search
    planning passes vary=False so repeats reuse the same Yuanbao queries.
    """
    model = os.environ.get("LLM_MODEL", "")
    body = {"model": model, "temperature": temperature,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if os.environ.get("LLM_REASONING_EFFORT"):
        body["reasoning_effort"] = os.environ["LLM_REASONING_EFFORT"]

    def fetch() -> dict:
        key = os.environ.get("LLM_API_KEY", "").strip()
        headers = {"Authorization": "Bearer " + key} if key else {}
        return http_json(os.environ["LLM_BASE_URL"].rstrip("/") + "/chat/completions", body, headers, 180)

    run = os.environ.get("SENTINEL_RUN", "0") if vary else "0"
    rec = cached("llm", body | {"_sample": sample} | ({"_run": run} if run != "0" else {}), fetch)
    text = rec["response"]["choices"][0]["message"].get("content") or ""
    return parse_json(text) | {"_usage": rec["response"].get("usage", {}), "_ms": rec["elapsed_ms"]}


def parse_json(text: str) -> dict:
    """Extract the last JSON object from a reply (tolerates <think> blocks and fences)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    candidate = m.group(1) if m else text[text.find("{"): text.rfind("}") + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return {"_parse_error": text[:400]}
