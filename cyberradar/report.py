"""Boletim semanal em Markdown (content/reports/AAAA-Wnn.md), gerado só com dados estruturados."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from .ai.templates import sev_pt
from .config import Settings
from .pipeline.normalize import primary_cvss, products_of
from .storage import Store, now_utc, parse_dt


def week_slug(dt=None) -> str:
    dt = dt or now_utc()
    y, w, _ = dt.isocalendar()
    return f"{y}-W{w:02d}"


def build_weekly(settings: Settings, records: list[dict[str, Any]], store: Store) -> Path:
    now = now_utc()
    start = now - timedelta(days=7)
    def in_week(v: str | None) -> bool:
        d = parse_dt(v)
        return bool(d and d >= start)
    new = [r for r in records if in_week(r.get("published"))]
    kev_new = [r for r in records if r.get("kev") and in_week((r["kev"].get("dateAdded") or "") + "T00:00:00Z")]
    top = sorted(new, key=lambda r: r["priority"]["score"], reverse=True)[:10]
    crit = [r for r in new if (primary_cvss(r.get("cvss", [])) or {}).get("severity") == "CRITICAL"]
    news = [n for n in store.iter_news() if in_week(n.get("published"))]
    clusters = {}
    for n in news:
        clusters.setdefault(n.get("cluster", n["id"]), []).append(n)
    top_stories = sorted(clusters.values(), key=lambda g: (len(g), max(x["published"] for x in g)), reverse=True)[:8]
    base = settings.public_base

    def line(r: dict[str, Any]) -> str:
        pc = primary_cvss(r.get("cvss", []))
        prods = ", ".join(p.split(":", 1)[1].replace("_", " ") for p in products_of(r)[:2]) or "—"
        sev = f"{sev_pt(pc['severity'])} ({pc['baseScore']:.1f})" if pc else "sem CVSS"
        return f"| [{r['id']}]({base}/cve/{r['id']}/) | {prods} | {sev} | {r['priority']['score']:.0f} | {'✅' if r.get('kev') else ''} |"

    slug = week_slug(now)
    md = [
        "---",
        f"titulo: Boletim semanal {slug}",
        f"data: {now.strftime('%Y-%m-%d')}",
        "tipo: relatorio",
        "---",
        f"# Boletim semanal {slug}",
        "",
        f"Período: {start.strftime('%d/%m/%Y')} a {now.strftime('%d/%m/%Y')} (UTC). Gerado automaticamente a partir de fontes oficiais.",
        "",
        "## Números da semana",
        f"- **{len(new)}** CVEs publicadas e rastreadas; **{len(crit)}** críticas.",
        f"- **{len(kev_new)}** novas entradas no catálogo KEV da CISA (exploração ativa confirmada).",
        f"- **{len(news)}** notícias coletadas em **{len(clusters)}** histórias distintas.",
        "",
        "## Novas no KEV (corrija primeiro)",
    ]
    md += (["| CVE | Produto | Severidade | Prioridade | KEV |", "|---|---|---|---|---|"] + [line(r) for r in kev_new[:15]]) if kev_new else ["Nenhuma nova entrada nesta semana."]
    md += ["", "## Top 10 por prioridade (publicadas na semana)"]
    md += (["| CVE | Produto | Severidade | Prioridade | KEV |", "|---|---|---|---|---|"] + [line(r) for r in top]) if top else ["Sem dados suficientes."]
    md += ["", "## Histórias mais cobertas"]
    for g in top_stories:
        n = sorted(g, key=lambda x: x["published"])[0]
        title = n.get("title_pt") or n["title"]
        fontes = ", ".join(sorted({x["source"] for x in g}))
        md.append(f"- [{title}]({n['url']}) — {fontes}")
    md += ["", "## O que perguntar ao seu time esta semana",
           "1. Algum dos produtos da tabela KEV está em uso aqui? Já foi corrigido?",
           "2. Os serviços afetados estão expostos à internet?",
           "3. Existe monitoramento para tentativas de exploração desses itens?",
           "", "> Priorização = KEV + EPSS + CVSS + exploit público + tecnologia popular. Veja a metodologia em /sobre/."]
    out = settings.content_dir / "reports" / f"{slug}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(md) + "\n", encoding="utf-8")
    return out
