"""Discord via webhook de canal (grátis)."""
from __future__ import annotations

from ..http import HttpClient


def send(http: HttpClient, webhook_url: str, text: str) -> None:
    if not webhook_url.startswith("https://"):
        raise ValueError("webhook inválido")
    r = http.post(webhook_url, json={"content": text[:1900], "allowed_mentions": {"parse": []}})
    if r.status_code not in (200, 204):
        raise RuntimeError(f"Discord HTTP {r.status_code}")
