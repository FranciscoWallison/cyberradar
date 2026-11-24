"""NVD CVE API 2.0 — coleta incremental por data de modificação.

Limites (doc oficial): 5 req/30 s sem chave; 50 req/30 s com chave (header `apiKey`).
Aviso obrigatório no site: "This product uses the NVD API but is not endorsed or certified by the NVD."
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from ..config import env
from ..http import HttpClient

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RANGE = timedelta(days=120)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _cpe_vendor_product(criteria: str) -> tuple[str, str, str]:
    # cpe:2.3:a:vendor:product:version:...
    parts = criteria.split(":")
    if len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    return "", "", ""


def _walk_cpe(nodes: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for node in nodes or []:
        for m in node.get("cpeMatch", []):
            if m.get("vulnerable"):
                yield m
        yield from _walk_cpe(node.get("children", []))


def parse_cve(item: dict[str, Any]) -> dict[str, Any]:
    c = item["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss: list[dict[str, Any]] = []
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        for m in c.get("metrics", {}).get(key, []):
            d = m.get("cvssData", {})
            if "baseScore" not in d:
                continue
            cvss.append({
                "version": ver,
                "vector": d.get("vectorString", ""),
                "baseScore": float(d["baseScore"]),
                "severity": (d.get("baseSeverity") or m.get("baseSeverity") or "").upper() or None,
                "assigner": m.get("source", ""),
                "type": m.get("type", ""),
            })
    cwes = sorted({
        d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    affected: dict[tuple[str, str], dict[str, Any]] = {}
    for conf in c.get("configurations", []):
        for m in _walk_cpe(conf.get("nodes", [])):
            vendor, product, version = _cpe_vendor_product(m.get("criteria", ""))
            if not vendor:
                continue
            entry = affected.setdefault((vendor, product), {"vendor": vendor, "product": product, "versions": []})
            rng = {k: m[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                     "versionEndIncluding", "versionEndExcluding") if k in m}
            if version not in ("*", "-", ""):
                rng["exact"] = version
            if rng and rng not in entry["versions"] and len(entry["versions"]) < 20:
                entry["versions"].append(rng)
    refs = []
    public_exploit = False
    for r in c.get("references", [])[:40]:
        tags = r.get("tags", [])
        if "Exploit" in tags:
            public_exploit = True
        refs.append({"url": r["url"], "kind": _ref_kind(tags), "tags": tags})
    rec: dict[str, Any] = {
        "id": c["id"],
        "published": c.get("published", "")[:19] + "Z",
        "lastModified": c.get("lastModified", "")[:19] + "Z",
        "vulnStatus": c.get("vulnStatus"),
        "description_official": desc,
        "cvss": cvss,
        "cwe": cwes,
        "affected": list(affected.values())[:30],
        "references": refs,
        "exploitation": {"publicExploit": public_exploit},
        "sources": [{"url": f"https://nvd.nist.gov/vuln/detail/{c['id']}", "name": "NVD", "kind": "official"}],
    }
    if c.get("cisaExploitAdd"):
        rec["nvd_kev_hint"] = {"dateAdded": c.get("cisaExploitAdd"), "action": c.get("cisaRequiredAction")}
    return rec


def _ref_kind(tags: list[str]) -> str:
    if "Exploit" in tags:
        return "exploit"
    if {"Vendor Advisory", "Patch", "Mitigation"} & set(tags):
        return "vendor"
    if "Third Party Advisory" in tags or "US Government Resource" in tags:
        return "official"
    return "analysis"


def fetch(http: HttpClient, since: datetime, until: datetime, page_size: int = 2000,
          sleep=time.sleep) -> list[dict[str, Any]]:
    key = env("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    pause = 0.8 if key else 6.5
    out: list[dict[str, Any]] = []
    start = since
    while start < until:
        end = min(start + MAX_RANGE, until)
        idx = 0
        while True:
            params = {"lastModStartDate": _fmt(start), "lastModEndDate": _fmt(end),
                      "resultsPerPage": page_size, "startIndex": idx}
            r = http.get(NVD_API, params=params, headers=headers)
            if r.status_code != 200:
                raise RuntimeError(f"NVD HTTP {r.status_code}")
            doc = r.json()
            items = doc.get("vulnerabilities", [])
            for it in items:
                try:
                    out.append(parse_cve(it))
                except (KeyError, ValueError) as exc:
                    log.warning("NVD: registro ignorado (%s)", exc)
            idx += len(items)
            total = doc.get("totalResults", 0)
            if not items or idx >= total:
                break
            sleep(pause)
        start = end
        if start < until:
            sleep(pause)
    log.info("NVD: %d CVEs modificadas entre %s e %s", len(out), since.date(), until.date())
    return out


def fetch_ids(http: HttpClient, ids: list[str], sleep=time.sleep) -> list[dict[str, Any]]:
    """Busca CVEs específicas (ex.: entradas recentes do KEV que ainda não temos)."""
    key = env("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    pause = 0.8 if key else 6.5
    out = []
    for i, cid in enumerate(ids):
        if i:
            sleep(pause)
        r = http.get(NVD_API, params={"cveId": cid}, headers=headers)
        if r.status_code != 200:
            log.warning("NVD %s: HTTP %d", cid, r.status_code)
            continue
        for it in r.json().get("vulnerabilities", []):
            if it.get("cve", {}).get("id", "").upper() == cid.upper():
                out.append(parse_cve(it))
    return out
