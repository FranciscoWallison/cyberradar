"""Agrupa notícias da mesma história: CVE em comum ou títulos quase iguais (Jaccard de shingles)."""
from __future__ import annotations

import re
import unicodedata
from typing import Any

STOP = {"the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "with", "by", "is", "are", "as",
        "at", "from", "new", "after", "via", "its", "it", "o", "a", "de", "da", "do", "em", "e", "para"}
THRESHOLD = 0.45
MIN_SHARED = 3


def _stem(w: str) -> str:
    for suf in ("ing", "ed", "es", "s"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def norm_tokens(title: str) -> list[str]:
    t = unicodedata.normalize("NFKD", title.lower())
    t = "".join(ch for ch in t if not unicodedata.combining(ch))
    return [_stem(w) for w in re.findall(r"[a-z0-9]+", t)
            if w not in STOP and len(w) > 1 and not w.isdigit() and w != "cve"]


def shingles(tokens: list[str]) -> set[str]:
    return set(tokens)


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def cluster(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Atribui `cluster` a cada item (id do item mais antigo do grupo). Union-find simples."""
    parent = {it["id"]: it["id"] for it in items}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    sh = {it["id"]: shingles(norm_tokens(it["title"])) for it in items}
    by_cve: dict[str, str] = {}
    for it in items:
        for c in it.get("cves", []):
            if c in by_cve:
                union(by_cve[c], it["id"])
            else:
                by_cve[c] = it["id"]
    ids = [it["id"] for it in items]
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = sh[ids[i]], sh[ids[j]]
            if len(a & b) >= MIN_SHARED and jaccard(a, b) >= THRESHOLD:
                union(ids[i], ids[j])
    groups: dict[str, list[dict[str, Any]]] = {}
    for it in items:
        groups.setdefault(find(it["id"]), []).append(it)
    for members in groups.values():
        members.sort(key=lambda x: x.get("published", ""))
        root = members[0]["id"]
        for m in members:
            m["cluster"] = root
    return items
