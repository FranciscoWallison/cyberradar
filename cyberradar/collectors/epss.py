"""FIRST EPSS — probabilidade de tentativa de exploração nos próximos 30 dias."""
from __future__ import annotations

import logging
from typing import Any, Iterable

from ..http import HttpClient

log = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
BATCH = 100  # a API aceita até 100 CVEs por chamada


def parse(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for row in doc.get("data", []):
        try:
            out[row["cve"].upper()] = {
                "score": round(float(row["epss"]), 5),
                "percentile": round(float(row["percentile"]), 5),
                "date": row.get("date"),
            }
        except (KeyError, ValueError, TypeError):
            continue
    return out


def fetch(http: HttpClient, cves: Iterable[str]) -> dict[str, dict[str, Any]]:
    ids = sorted({c.upper() for c in cves if c.upper().startswith("CVE-")})
    out: dict[str, dict[str, Any]] = {}
    for i in range(0, len(ids), BATCH):
        chunk = ids[i:i + BATCH]
        try:
            r = http.get(EPSS_API, params={"cve": ",".join(chunk)})
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS: falha de rede (%s); seguindo sem EPSS", exc)
            break
        if r.status_code != 200:
            log.warning("EPSS: HTTP %d", r.status_code)
            continue
        out.update(parse(r.json()))
    log.info("EPSS: %d CVEs com pontuação", len(out))
    return out
