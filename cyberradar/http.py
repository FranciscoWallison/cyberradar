"""Cliente HTTP com retry/backoff, respeitando Retry-After e sem vazar segredos em log."""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

USER_AGENT = "CyberRadar/0.1 (+https://github.com; agregador de avisos de seguranca)"
RETRY_STATUS = {429, 500, 502, 503, 504}


class HttpClient:
    def __init__(self, transport: httpx.BaseTransport | None = None, timeout: float = 30.0,
                 max_retries: int = 4, sleep=time.sleep):
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        self.max_retries = max_retries
        self._sleep = sleep

    def request(self, method: str, url: str, *, retries: int | None = None, **kw: Any) -> httpx.Response:
        max_retries = self.max_retries if retries is None else retries
        delay = 2.0
        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                resp = self._client.request(method, url, **kw)
            except httpx.TransportError as exc:  # rede, DNS, timeout
                last_exc = exc
                log.warning("falha de rede em %s (%s), tentativa %d", _safe(url), exc.__class__.__name__, attempt + 1)
            else:
                if resp.status_code not in RETRY_STATUS:
                    return resp
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = max(delay, min(float(retry_after), 120.0))
                log.warning("HTTP %d em %s, tentativa %d", resp.status_code, _safe(url), attempt + 1)
                if attempt == max_retries:
                    return resp
            if attempt < max_retries:
                self._sleep(delay)
                delay = min(delay * 2, 120.0)
        assert last_exc is not None
        raise last_exc

    def get(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("POST", url, **kw)

    def close(self) -> None:
        self._client.close()


def _safe(url: str) -> str:
    """Remove query string e tokens embutidos (ex.: bot<TOKEN>) antes de logar."""
    base = url.split("?", 1)[0]
    if "api.telegram.org/bot" in base:
        return "https://api.telegram.org/bot***"
    if "discord.com/api/webhooks" in base:
        return "https://discord.com/api/webhooks/***"
    return base
