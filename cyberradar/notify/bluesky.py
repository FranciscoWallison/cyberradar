"""Bluesky (AT Protocol). Use uma *App Password* (Configurações → Privacidade e segurança → App passwords)."""
from __future__ import annotations

from datetime import datetime, timezone

from ..http import HttpClient

PDS = "https://bsky.social/xrpc"
MAX_GRAPHEMES = 300


def build_record(text: str, url: str) -> dict:
    if len(text) > MAX_GRAPHEMES:
        keep = MAX_GRAPHEMES - len(url) - 2
        text = text[:keep].rstrip() + "… " + url
    record: dict = {"$type": "app.bsky.feed.post", "text": text,
                    "createdAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "langs": ["pt"]}
    b = text.encode("utf-8")
    u = url.encode("utf-8")
    start = b.rfind(u)
    if start >= 0:  # facet de link usa offsets em BYTES UTF-8
        record["facets"] = [{"index": {"byteStart": start, "byteEnd": start + len(u)},
                             "features": [{"$type": "app.bsky.richtext.facet#link", "uri": url}]}]
    return record


def post(http: HttpClient, handle: str, app_password: str, text: str, url: str) -> None:
    s = http.post(f"{PDS}/com.atproto.server.createSession", json={"identifier": handle, "password": app_password})
    if s.status_code != 200:
        raise RuntimeError(f"Bluesky login HTTP {s.status_code}")
    sess = s.json()
    r = http.post(f"{PDS}/com.atproto.repo.createRecord",
                  headers={"Authorization": f"Bearer {sess['accessJwt']}"},
                  json={"repo": sess["did"], "collection": "app.bsky.feed.post", "record": build_record(text, url)})
    if r.status_code != 200:
        raise RuntimeError(f"Bluesky post HTTP {r.status_code}")
