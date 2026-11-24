"""Score de prioridade determinístico e explicável (0–100). Ver docs 05 §3.4."""
from __future__ import annotations

from typing import Any

from .normalize import primary_cvss, vendors_of


def priority(rec: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    popular = {p.lower() for p in cfg.get("popular", [])}
    kev = 1.0 if rec.get("kev", {}).get("listed") else 0.0
    epss_p = float(rec.get("epss", {}).get("percentile") or 0.0)
    pc = primary_cvss(rec.get("cvss", []))
    cvss = (pc["baseScore"] / 10.0) if pc else 0.0
    ex = rec.get("exploitation") or {}
    exploit = 1.0 if (ex.get("publicExploit") or ex.get("publicTool")) else 0.0
    pop = 1.0 if popular & set(vendors_of(rec)) else 0.0
    parts = {
        "kev": round(cfg.get("w_kev", 40) * kev, 2),
        "epss": round(cfg.get("w_epss_percentile", 25) * epss_p, 2),
        "cvss": round(cfg.get("w_cvss", 20) * cvss, 2),
        "exploit_publico": round(cfg.get("w_public_exploit", 10) * exploit, 2),
        "tecnologia_popular": round(cfg.get("w_popular", 5) * pop, 2),
    }
    return {"score": round(sum(parts.values()), 1), "breakdown": parts, "formulaVersion": str(cfg.get("version", "1"))}
