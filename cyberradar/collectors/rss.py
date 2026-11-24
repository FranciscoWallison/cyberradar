"""Feeds RSS/Atom. Guarda só título, trecho curto e link (direitos autorais — docs 04 §2.11)."""
from __future__ import annotations

import hashlib
import html
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser

from ..http import HttpClient
from . import find_cves

log = logging.getLogger(__name__)

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
TRACKING = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}
EXCERPT_MAX = 280


def clean_text(value: str) -> str:
    text = TAG_RE.sub(" ", value or "")
    text = html.unescape(text)
    return WS_RE.sub(" ", text).strip()


def excerpt(value: str, limit: int = EXCERPT_MAX) -> str:
    text = clean_text(value)
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "…"


def canonical_url(url: str) -> str:
    p = urlsplit(url.strip())
    q = [(k, v) for k, v in parse_qsl(p.query) if k.lower() not in TRACKING]
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/") or "/", urlencode(q), ""))


def item_id(url: str) -> str:
    return hashlib.sha256(canonical_url(url).encode()).hexdigest()[:16]


def _published(entry: Any) -> str:
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime(*t[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_feed(content: bytes, feed: dict[str, Any], max_items: int = 30) -> list[dict[str, Any]]:
    parsed = feedparser.parse(content)
    items = []
    for e in parsed.entries[:max_items]:
        link = e.get("link")
        title = clean_text(e.get("title", ""))
        if not link or not title or not link.startswith(("http://", "https://")):
            continue
        summary = e.get("summary") or e.get("description") or ""
        text_for_cves = f"{title} {clean_text(summary)}"
        items.append({
            "id": item_id(link),
            "url": canonical_url(link),
            "title": title[:300],
            "excerpt": excerpt(summary),
            "published": _published(e),
            "source": feed["name"],
            "kind": feed.get("kind", "news"),
            "lang": feed.get("lang", "en"),
            "cves": find_cves(text_for_cves),
        })
    return items


def fetch(http: HttpClient, feeds: list[dict[str, Any]], state: dict[str, Any], max_items: int = 30) -> list[dict[str, Any]]:
    etags = state.setdefault("feed_cache", {})
    out: list[dict[str, Any]] = []
    for feed in feeds:
        if not feed.get("enabled", True):
            continue
        cache = etags.get(feed["url"], {})
        headers = {}
        if cache.get("etag"):
            headers["If-None-Match"] = cache["etag"]
        if cache.get("modified"):
            headers["If-Modified-Since"] = cache["modified"]
        try:
            r = http.get(feed["url"], headers=headers, retries=1)
        except Exception as exc:  # noqa: BLE001
            log.warning("RSS %s: falha (%s)", feed["name"], exc.__class__.__name__)
            _mark(state, feed, ok=False)
            continue
        if r.status_code == 304:
            _mark(state, feed, ok=True)
            continue
        if r.status_code != 200:
            log.warning("RSS %s: HTTP %d", feed["name"], r.status_code)
            _mark(state, feed, ok=False)
            continue
        etags[feed["url"]] = {k: v for k, v in (("etag", r.headers.get("ETag")),
                                                  ("modified", r.headers.get("Last-Modified"))) if v}
        got = parse_feed(r.content, feed, max_items)
        log.info("RSS %s: %d itens", feed["name"], len(got))
        out.extend(got)
        _mark(state, feed, ok=True)
    return out


def _mark(state: dict[str, Any], feed: dict[str, Any], ok: bool) -> None:
    st = state.setdefault("sources_status", {})
    prev = st.get(feed["name"], {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    st[feed["name"]] = {
        "last_ok": now if ok else prev.get("last_ok"),
        "last_error": None if ok else now,
        "failures": 0 if ok else prev.get("failures", 0) + 1,
    }
