"""Validação da saída da IA contra os dados de origem (anti-alucinação básica)."""
from __future__ import annotations

import re
from typing import Any

from ..collectors import find_cves

URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
KINDS = {"prevention", "mitigation", "remediation"}
CVE_CATEGORIES = {"web", "rede", "nuvem", "sistema-operacional", "navegador", "iot-ot", "supply-chain", "identidade",
                  "email", "virtualizacao", "mobile", "banco-de-dados", "outro"}
NEWS_CATEGORIES = {"vulnerabilidade", "ransomware", "malware", "phishing", "vazamento", "apt-espionagem", "supply-chain",
                   "nuvem", "politica-regulacao", "patch", "pesquisa", "outro"}


class ValidationError(ValueError):
    pass


def _s(v: Any, name: str, max_len: int) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValidationError(f"campo vazio: {name}")
    v = v.strip()
    if len(v) > max_len:
        raise ValidationError(f"campo longo demais: {name}")
    return v


def validate_cve_analysis(out: Any, rec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(out, dict):
        raise ValidationError("saída não é objeto")
    impact = out.get("impact") or {}
    res = {
        "summary_simple": _s(out.get("summary_simple"), "summary_simple", 900),
        "technical_explanation": _s(out.get("technical_explanation"), "technical_explanation", 2500),
        "impact": {k: _s(impact.get(k), f"impact.{k}", 900) for k in ("technical", "financial", "operational")},
        "if_not_fixed": _s(out.get("if_not_fixed"), "if_not_fixed", 900),
        "recommendations": [],
        "category": out.get("category") if out.get("category") in CVE_CATEGORIES else "outro",
    }
    allowed_urls = {r["url"] for r in rec.get("references", [])} | {s["url"] for s in rec.get("sources", [])}
    for r in (out.get("recommendations") or [])[:6]:
        if not isinstance(r, dict) or r.get("kind") not in KINDS:
            continue
        text = _s(r.get("text"), "recommendation.text", 600)
        url = (r.get("sourceUrl") or "").strip()
        if url and url not in allowed_urls:
            url = ""  # URL inventada → descartada
        res["recommendations"].append({"kind": r["kind"], "text": text, **({"sourceUrl": url} if url else {})})
    if not res["recommendations"]:
        raise ValidationError("sem recomendações válidas")

    # 1) Nenhum CVE citado que não seja o próprio/aliases.
    allowed_ids = {rec["id"].upper(), *[a.upper() for a in rec.get("aliases", [])]}
    blob = " ".join([res["summary_simple"], res["technical_explanation"], res["if_not_fixed"],
                     *res["impact"].values(), *[r["text"] for r in res["recommendations"]]])
    extra = [c for c in find_cves(blob) if c not in allowed_ids]
    if extra:
        raise ValidationError(f"CVE não presente nos dados: {extra[:3]}")
    # 2) Nenhuma URL no texto livre fora das referências.
    for u in URL_RE.findall(blob):
        if u.rstrip(".,;") not in allowed_urls:
            raise ValidationError("URL não presente nos dados")
    # 3) Scores numéricos citados devem bater com os dados (ex.: "CVSS 9.8").
    known_scores = {f"{c['baseScore']:.1f}" for c in rec.get("cvss", [])}
    for m in re.finditer(r"CVSS[^0-9]{0,15}(\d{1,2}[.,]\d)", blob, re.I):
        if m.group(1).replace(",", ".") not in known_scores:
            raise ValidationError("CVSS citado não confere")
    return res


def validate_news_batch(out: Any, ids: set[str]) -> dict[str, dict[str, str]]:
    items = out.get("items") if isinstance(out, dict) else out
    if not isinstance(items, list):
        raise ValidationError("formato inválido")
    res: dict[str, dict[str, str]] = {}
    for it in items:
        if not isinstance(it, dict) or it.get("id") not in ids:
            continue
        try:
            title = _s(it.get("title_pt"), "title_pt", 300)
            summ = _s(it.get("summary_pt"), "summary_pt", 600)
        except ValidationError:
            continue
        if URL_RE.search(title + summ):
            continue
        cat = it.get("category") if it.get("category") in NEWS_CATEGORIES else "outro"
        res[it["id"]] = {"title_pt": title, "summary_pt": summ, "category": cat}
    return res
