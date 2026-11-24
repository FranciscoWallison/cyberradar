"""Textos em PT-BR gerados SEM IA, a partir dos dados estruturados (fallback e itens não priorizados)."""
from __future__ import annotations

from typing import Any

from ..pipeline.normalize import primary_cvss, products_of

SEV_PT = {"CRITICAL": "crítica", "HIGH": "alta", "MEDIUM": "média", "LOW": "baixa", "NONE": "sem severidade"}


def sev_pt(sev: str | None) -> str:
    return SEV_PT.get((sev or "").upper(), "não informada")


def cve_template(rec: dict[str, Any]) -> dict[str, Any]:
    pc = primary_cvss(rec.get("cvss", []))
    prods = [p.split(":", 1)[1].replace("_", " ") for p in products_of(rec)][:4]
    alvo = ", ".join(prods) if prods else "produto não informado"
    partes = []
    if pc:
        partes.append(f"Vulnerabilidade de severidade {sev_pt(pc['severity'])} (CVSS {pc['baseScore']:.1f} v{pc['version']}, "
                      f"atribuído por {pc.get('assigner') or 'não informado'}) que afeta {alvo}.")
    else:
        partes.append(f"Vulnerabilidade ainda sem pontuação CVSS publicada que afeta {alvo}.")
    kev = rec.get("kev") or {}
    if kev.get("listed"):
        partes.append(f"Consta no catálogo KEV da CISA desde {kev.get('dateAdded')}: há evidência de exploração ativa.")
        if (kev.get("knownRansomwareCampaignUse") or "").lower() == "known":
            partes.append("Há uso conhecido em campanhas de ransomware.")
    ep = rec.get("epss") or {}
    if ep.get("score") is not None:
        partes.append(f"Probabilidade estimada de exploração em 30 dias (EPSS): {ep['score'] * 100:.1f}% "
                      f"(percentil {ep.get('percentile', 0) * 100:.0f}).")
    if rec.get("cwe"):
        partes.append(f"Classe de fraqueza: {', '.join(rec['cwe'][:3])}.")
    recs = [{"kind": "remediation", "text": "Aplique a correção ou a versão indicada no aviso oficial do fabricante."}]
    if kev.get("requiredAction"):
        recs.append({"kind": "mitigation", "text": f"Ação exigida pela CISA (em inglês): {kev['requiredAction']}"})
    recs.append({"kind": "prevention", "text": "Reduza a exposição do serviço afetado à internet e monitore registros de acesso suspeitos."})
    vendor_refs = [r["url"] for r in rec.get("references", []) if r.get("kind") == "vendor"]
    if vendor_refs:
        recs[0]["sourceUrl"] = vendor_refs[0]
    return {"summary_simple": " ".join(partes), "recommendations": recs, "generator": "template"}
