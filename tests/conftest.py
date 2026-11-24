import json
from pathlib import Path

import httpx
import pytest

from cyberradar import config
from cyberradar.http import HttpClient

FIX = Path(__file__).parent / "fixtures"
SECRET_ENVS = ["NVD_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "CLOUDFLARE_API_TOKEN",
               "CLOUDFLARE_ACCOUNT_ID", "MISTRAL_API_KEY", "OLLAMA_BASE_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
               "DISCORD_WEBHOOK_URL", "BLUESKY_HANDLE", "BLUESKY_APP_PASSWORD", "GITHUB_TOKEN", "SITE_URL",
               "SITE_BASE_PATH", "FEEDBACK_URL"]


class FakeNet:
    """Roteia requisições para fixtures; registra chamadas."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.ai_responses: list[tuple[int, dict]] = []
        self.kev_override: dict | None = None

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        host, path = req.url.host, req.url.path
        if path.endswith("/cves.json") and "nuclei-templates" in path:
            return httpx.Response(200, content=(FIX / "nuclei.jsonl").read_bytes())
        if path.endswith("modules_metadata_base.json"):
            return httpx.Response(200, json=json.loads((FIX / "msf.json").read_text(encoding="utf-8")))
        if "kev-data" in path or path.endswith("known_exploited_vulnerabilities.json"):
            return httpx.Response(200, json=self.kev_override or json.loads((FIX / "kev.json").read_text(encoding="utf-8")))
        if host == "services.nvd.nist.gov":
            return httpx.Response(200, json=json.loads((FIX / "nvd.json").read_text(encoding="utf-8")))
        if host == "api.first.org":
            return httpx.Response(200, json=json.loads((FIX / "epss.json").read_text(encoding="utf-8")))
        if host == "api.github.com":
            return httpx.Response(200, json=json.loads((FIX / "ghsa.json").read_text(encoding="utf-8")))
        if path.endswith("/chat/completions"):
            if self.ai_responses:
                code, body = self.ai_responses.pop(0)
                return httpx.Response(code, json=body)
            return httpx.Response(429, json={"error": "rate"})
        if host == "api.telegram.org":
            return httpx.Response(200, json={"ok": True})
        if host == "discord.com":
            return httpx.Response(204)
        if req.url.scheme == "https" and ("feed" in path or "rss" in path or path.endswith(".xml")):
            return httpx.Response(200, content=(FIX / "feed.xml").read_bytes(), headers={"Content-Type": "application/rss+xml"})
        return httpx.Response(404)


@pytest.fixture
def net():
    return FakeNet()


@pytest.fixture
def http(net):
    return HttpClient(transport=httpx.MockTransport(net), sleep=lambda s: None)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    for k in SECRET_ENVS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CYBERRADAR_NOW", "2026-11-24T12:00:00Z")
    monkeypatch.setenv("CYBERRADAR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERRADAR_OUT_DIR", str(tmp_path / "_site"))
    monkeypatch.setenv("CYBERRADAR_CONTENT_DIR", str(tmp_path / "content"))
    content = tmp_path / "content"
    import shutil
    shutil.copytree(config.ROOT / "content", content)
    s = config.load()
    # só um feed para os testes
    s.raw["feeds"] = [{"name": "Example News", "url": "https://news.example/feed.xml", "kind": "news", "lang": "en"}]
    monkeypatch.setattr("cyberradar.collectors.nvd.time.sleep", lambda s: None)
    return s
