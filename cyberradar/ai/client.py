"""Cliente único para provedores com API compatível com OpenAI, com fallback em cadeia
e orçamento diário por provedor (contado em data/state.json)."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..config import env
from ..http import HttpClient

log = logging.getLogger(__name__)


class NoProviderAvailable(RuntimeError):
    pass


@dataclass
class Provider:
    name: str
    base_url: str
    model: str
    api_key: str | None
    daily_limit: int
    json_mode: bool
    public_data_only: bool

    @classmethod
    def from_cfg(cls, c: dict[str, Any]) -> "Provider | None":
        key_env = c.get("api_key_env")
        key = env(key_env) if key_env else None
        if not key:
            return None  # provedor não configurado → pulado
        base = env(c["base_url_env"]) if c.get("base_url_env") else None
        base = base or c["base_url"]
        if "{account_id}" in base:
            acct = env("CLOUDFLARE_ACCOUNT_ID")
            if not acct:
                return None
            base = base.replace("{account_id}", acct)
        model = (env(c["model_env"]) if c.get("model_env") else None) or c["model"]
        is_local = c.get("name") == "ollama"
        return cls(name=c["name"], base_url=base.rstrip("/"), model=model,
                   api_key=None if is_local else key, daily_limit=int(c.get("daily_limit", 50)),
                   json_mode=bool(c.get("json_mode", True)), public_data_only=bool(c.get("public_data_only", False)))


class AIClient:
    def __init__(self, http: HttpClient, cfg: dict[str, Any], state: dict[str, Any]):
        self.http = http
        self.cfg = cfg
        self.state = state
        self.providers = [p for p in (Provider.from_cfg(c) for c in cfg.get("providers", [])) if p]
        self.timeout = float(cfg.get("timeout_seconds", 60))
        self.temperature = float(cfg.get("temperature", 0.2))
        self._disabled_this_run: set[str] = set()

    @property
    def available(self) -> bool:
        return bool(self.cfg.get("enabled", True)) and bool(self.providers)

    def _usage(self) -> dict[str, int]:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        usage = self.state.setdefault("ai_usage", {})
        for d in list(usage):
            if d != today:
                del usage[d]
        return usage.setdefault(today, {})

    def chat_json(self, system: str, user: str, *, private_data: bool = False) -> tuple[Any, str]:
        """Retorna (objeto_json, "provedor/modelo"). Tenta cada provedor na ordem."""
        usage = self._usage()
        errors = []
        for p in self.providers:
            if p.name in self._disabled_this_run:
                continue
            if private_data and p.public_data_only:
                continue
            if usage.get(p.name, 0) >= p.daily_limit:
                continue
            usage[p.name] = usage.get(p.name, 0) + 1
            try:
                content = self._call(p, system, user)
                return extract_json(content), f"{p.name}/{p.model}"
            except RateLimited:
                log.warning("IA %s: limite atingido; desativando nesta execução", p.name)
                self._disabled_this_run.add(p.name)
                errors.append(f"{p.name}: 429")
            except Exception as exc:  # noqa: BLE001
                log.warning("IA %s: falha (%s)", p.name, exc)
                errors.append(f"{p.name}: {exc.__class__.__name__}")
        raise NoProviderAvailable("; ".join(errors) or "nenhum provedor configurado/disponível")

    def _call(self, p: Provider, system: str, user: str) -> str:
        body: dict[str, Any] = {
            "model": p.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.temperature,
        }
        if p.json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if p.api_key:
            headers["Authorization"] = f"Bearer {p.api_key}"
        if p.name == "openrouter":
            headers["X-Title"] = "CyberRadar"
        r = self.http.post(f"{p.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout,
                           retries=0)  # 429 → próximo provedor, sem insistir
        if r.status_code == 429:
            raise RateLimited()
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}")
        data = r.json()
        # Cloudflare às vezes embrulha em {"result": {...}}
        if "choices" not in data and isinstance(data.get("result"), dict):
            data = data["result"]
        return data["choices"][0]["message"]["content"] or ""


class RateLimited(Exception):
    pass


FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(content: str) -> Any:
    text = content.strip()
    m = FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    # remove raciocínio exposto por alguns modelos
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
        end = max(text.rfind("}"), text.rfind("]"))
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise
