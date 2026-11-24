"""Junta NVD + GHSA + KEV num registro único e escolhe o CVSS principal."""
from __future__ import annotations

from typing import Any

SEVERITY_FROM_SCORE = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"), (0.0, "NONE")]
VERSION_RANK = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}


def severity_for(score: float) -> str:
    for threshold, name in SEVERITY_FROM_SCORE:
        if score >= threshold:
            return name
    return "NONE"


def primary_cvss(cvss: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Preferência: versão mais nova; entre iguais, a do CNA (Secondary) antes do NVD (Primary),
    pois desde 2026 o NVD passou a reaproveitar o score do CNA (docs 04 §2.1)."""
    if not cvss:
        return None
    def key(c: dict[str, Any]) -> tuple[int, int]:
        return (VERSION_RANK.get(c.get("version", ""), 0), 1 if c.get("type") == "Secondary" else 0)
    best = dict(max(cvss, key=key))
    best["severity"] = best.get("severity") or severity_for(best["baseScore"])
    return best


def merge_ghsa(rec: dict[str, Any], adv: dict[str, Any]) -> dict[str, Any]:
    aliases = set(rec.get("aliases", []))
    if adv.get("ghsa_id"):
        aliases.add(adv["ghsa_id"])
    rec["aliases"] = sorted(aliases)
    rec["packages"] = adv.get("packages", [])
    if adv.get("cvss") and not any(c.get("assigner") == "GitHub (GHSA)" for c in rec.get("cvss", [])):
        rec.setdefault("cvss", []).append(adv["cvss"])
    rec["cwe"] = sorted(set(rec.get("cwe", [])) | set(adv.get("cwe", [])))
    if adv.get("summary") and not rec.get("title"):
        rec["title"] = adv["summary"][:200]
    srcs = rec.setdefault("sources", [])
    if adv.get("url") and all(s["url"] != adv["url"] for s in srcs):
        srcs.append({"url": adv["url"], "name": "GitHub Advisory Database", "kind": "official", "license": "CC-BY-4.0"})
    return rec


def ghsa_only_record(adv: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": adv["ghsa_id"],
        "aliases": [],
        "title": adv.get("summary", "")[:200],
        "published": (adv.get("published") or "")[:19] + "Z",
        "lastModified": (adv.get("updated") or "")[:19] + "Z",
        "description_official": adv.get("description", ""),
        "cvss": [adv["cvss"]] if adv.get("cvss") else [],
        "ghsa_severity": adv.get("severity"),
        "cwe": adv.get("cwe", []),
        "affected": [],
        "packages": adv.get("packages", []),
        "references": [{"url": u, "kind": "analysis", "tags": []} for u in adv.get("references", [])],
        "exploitation": {"publicExploit": False},
        "sources": [{"url": adv["url"], "name": "GitHub Advisory Database", "kind": "official", "license": "CC-BY-4.0"}],
    }


def carry_over(new: dict[str, Any], old: dict[str, Any] | None) -> dict[str, Any]:
    """Preserva campos que o pipeline gera (IA, aliases, pacotes) ao atualizar um registro do NVD."""
    if not old:
        return new
    for key in ("ai", "aliases", "packages", "news", "first_seen", "title"):
        if key in old and key not in new:
            new[key] = old[key]
    ghsa_cvss = [c for c in old.get("cvss", []) if c.get("assigner") == "GitHub (GHSA)"]
    if ghsa_cvss and not any(c.get("assigner") == "GitHub (GHSA)" for c in new.get("cvss", [])):
        new.setdefault("cvss", []).extend(ghsa_cvss)
    for s in old.get("sources", []):
        if all(s["url"] != x["url"] for x in new.get("sources", [])):
            new.setdefault("sources", []).append(s)
    return new


def vendors_of(rec: dict[str, Any]) -> list[str]:
    vs = {a["vendor"].lower() for a in rec.get("affected", []) if a.get("vendor")}
    if rec.get("kev", {}).get("vendorProject"):
        vs.add(rec["kev"]["vendorProject"].lower().replace(" ", ""))
    for p in rec.get("packages", []):
        if p.get("ecosystem"):
            vs.add(p["ecosystem"].lower())
    return sorted(vs)


def products_of(rec: dict[str, Any]) -> list[str]:
    ps = [f'{a["vendor"]}:{a["product"]}' for a in rec.get("affected", []) if a.get("product")]
    ps += [f'{p["ecosystem"]}:{p["name"]}' for p in rec.get("packages", []) if p.get("name")]
    if rec.get("kev", {}).get("product"):
        ps.append(f'{rec["kev"].get("vendorProject", "")}:{rec["kev"]["product"]}')
    seen: dict[str, str] = {}
    for p in ps:  # remove duplicatas que só diferem em caixa/espaço/sublinhado ("VPN Gateway" x "vpn_gateway")
        key = p.split(":", 1)[-1].lower().replace("_", " ").replace("-", " ").strip()
        seen.setdefault(key, p)
    return sorted(seen.values())
