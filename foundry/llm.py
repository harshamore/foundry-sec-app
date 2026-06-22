"""Shared LLM client wrapper.

Centralises the Anthropic call so every role goes through the same budget meter
and the same JSON-extraction logic. If no key is configured, `available` is
False and roles fall back to their heuristic paths — the whole pipeline still
runs offline.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from .substrate import Substrate

DEFAULT_MODEL = "claude-sonnet-4-6"     # heavier pass: claude-opus-4-8


class LLM:
    def __init__(self, model: str = DEFAULT_MODEL, api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        if self.api_key:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key)
            except Exception:
                self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    def complete(self, substrate: Substrate, system: str, user: str,
                 max_tokens: int = 2000) -> Optional[str]:
        """One bounded call. Returns text, or None if unavailable/over budget."""
        if not self.available or not substrate.budget.can_spend():
            return None
        try:
            resp = self._client.messages.create(
                model=self.model, max_tokens=max_tokens,
                system=system, messages=[{"role": "user", "content": user}],
            )
            substrate.budget.spend(1)
            return "".join(b.text for b in resp.content if b.type == "text").strip()
        except Exception as e:
            substrate.emit("LLM", f"call failed: {e}")
            return None

    @staticmethod
    def parse_json(text: Optional[str]):
        """Extract a JSON array/object from a model response, fences or not."""
        if not text:
            return None
        t = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            m = re.search(r"(\[.*\]|\{.*\})", t, re.S)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    return None
        return None
