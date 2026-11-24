"""CISA Known Exploited Vulnerabilities (espelho oficial no GitHub, licença CC0)."""
from __future__ import annotations

import logging
from typing import Any

from ..http import HttpClient

log = logging.getLogger(__name__)

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
KEV_URL_FALLBACK = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for v in doc.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if not cid:
            continue
        out[cid] = {
            "listed": True,
            "dateAdded": v.get("dateAdded"),
            "dueDate": v.get("dueDate"),
            "vendorProject": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "shortDescription": v.get("shortDescription"),
            "requiredAction": v.get("requiredAction"),
            "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
            "notes": v.get("notes"),
        }
    return out


def fetch(http: HttpClient) -> dict[str, dict[str, Any]]:
    for url in (KEV_URL, KEV_URL_FALLBACK):
        try:
            r = http.get(url)
            if r.status_code == 200:
                data = parse(r.json())
                log.info("KEV: %d entradas", len(data))
                return data
            log.warning("KEV: HTTP %d em %s", r.status_code, url)
        except Exception as exc:  # noqa: BLE001
            log.warning("KEV: falha em %s: %s", url, exc)
    return {}
