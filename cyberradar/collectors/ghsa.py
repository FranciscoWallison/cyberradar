"""GitHub Advisory Database (REST global advisories). Dados sob CC-BY 4.0 — exige atribuição.

Sem token: 60 req/h por IP. No GitHub Actions o GITHUB_TOKEN automático dá 5.000 req/h.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from ..config import env
from ..http import HttpClient
from ..storage import parse_dt

log = logging.getLogger(__name__)

API = "https://api.github.com/advisories"


def parse(adv: dict[str, Any]) -> dict[str, Any]:
    pkgs = []
    for v in adv.get("vulnerabilities") or []:
        p = v.get("package") or {}
        fp = v.get("first_patched_version")
        if isinstance(fp, dict):
            fp = fp.get("identifier")
        pkgs.append({
            "ecosystem": p.get("ecosystem"),
            "name": p.get("name"),
            "vulnerable": v.get("vulnerable_version_range"),
            "patched": fp,
        })
    cvss = None
    c = adv.get("cvss") or {}
    if c.get("score"):
        cvss = {"version": _cvss_ver(c.get("vector_string", "")), "vector": c.get("vector_string", ""),
                "baseScore": float(c["score"]), "severity": None, "assigner": "GitHub (GHSA)", "type": "Secondary"}
    for key in ("cvss_v4", "cvss_v3"):
        cs = (adv.get("cvss_severities") or {}).get(key) or {}
        if cs.get("score") and not cvss:
            cvss = {"version": _cvss_ver(cs.get("vector_string", "")), "vector": cs.get("vector_string", ""),
                    "baseScore": float(cs["score"]), "severity": None, "assigner": "GitHub (GHSA)", "type": "Secondary"}
    return {
        "ghsa_id": adv.get("ghsa_id"),
        "cve_id": (adv.get("cve_id") or "").upper() or None,
        "summary": adv.get("summary", ""),
        "description": (adv.get("description") or "")[:4000],
        "severity": (adv.get("severity") or "").upper(),
        "cvss": cvss,
        "cwe": [w["cwe_id"] for w in adv.get("cwes") or [] if w.get("cwe_id")],
        "packages": pkgs[:20],
        "url": adv.get("html_url"),
        "published": adv.get("published_at"),
        "updated": adv.get("updated_at"),
        "references": [r for r in (adv.get("references") or [])[:20] if isinstance(r, str)],
    }


def _cvss_ver(vector: str) -> str:
    m = re.match(r"CVSS:(\d\.\d)", vector or "")
    return m.group(1) if m else "3.1"


def fetch(http: HttpClient, since: datetime, pages: int = 2) -> list[dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    tok = env("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    params: dict[str, Any] = {"type": "reviewed", "sort": "updated", "direction": "desc", "per_page": 100}
    out: list[dict[str, Any]] = []
    url: str | None = API
    for _ in range(pages):
        if not url:
            break
        r = http.get(url, params=params if url == API else None, headers=headers)
        if r.status_code != 200:
            log.warning("GHSA: HTTP %d", r.status_code)
            break
        stop = False
        for adv in r.json():
            upd = parse_dt(adv.get("updated_at"))
            if upd and upd < since:
                stop = True
                break
            out.append(parse(adv))
        if stop:
            break
        url = r.links.get("next", {}).get("url")
    log.info("GHSA: %d advisories atualizados", len(out))
    return out
