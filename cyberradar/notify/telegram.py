"""Telegram Bot API (grátis). O bot precisa ser administrador do canal para postar."""
from __future__ import annotations

from ..http import HttpClient


def send(http: HttpClient, token: str, chat_id: str, text: str) -> None:
    r = http.post(f"https://api.telegram.org/bot{token}/sendMessage",
                  json={"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": False})
    if r.status_code != 200 or not r.json().get("ok"):
        raise RuntimeError(f"Telegram HTTP {r.status_code}")
