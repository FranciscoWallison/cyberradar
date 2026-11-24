"""Gera o site estático em _site/ (HTML + JSON + feeds). A busca (Pagefind) roda depois."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import markdown
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..ai.templates import cve_template, sev_pt
from ..config import Settings
from ..pipeline.normalize import primary_cvss, products_of, vendors_of
from ..pipeline.run import enriched_records
from ..storage import Store, now_utc, parse_dt, read_json

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
FRONT_RE = re.compile(r"^---\n(.*?)\n---\n", re.S)

KIND_LABEL = {"official": "Oficial", "vendor": "Fabricante", "news": "Imprensa", "analysis": "Análise",
              "exploit": "Exploit", "ai_generated": "IA"}
CATEGORY_PT = {
    "vulnerabilidade": "Vulnerabilidade", "ransomware": "Ransomware", "malware": "Malware", "phishing": "Phishing",
    "vazamento": "Vazamento", "apt-espionagem": "APT / espionagem", "supply-chain": "Cadeia de suprimentos",
    "nuvem": "Nuvem", "politica-regulacao": "Política e regulação", "patch": "Atualizações", "pesquisa": "Pesquisa", "outro": "Outros",
}


def front_matter(text: str) -> tuple[dict[str, Any], str]:
    m = FRONT_RE.match(text)
    if not m:
        return {}, text
    meta: dict[str, Any] = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                meta[k.strip()] = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
            else:
                meta[k.strip()] = v.strip("'\"")
    return meta, text[m.end():]


def md_to_html(text: str) -> str:
    return markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "sane_lists"])


class Builder:
    def __init__(self, settings: Settings):
        self.s = settings
        self.store = Store(settings.data_dir)
        self.out = settings.out_dir
        self.base = settings.base_path
        self.now = now_utc()
        self.env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html", "xml"]),
                               trim_blocks=True, lstrip_blocks=True)
        site = dict(settings.section("site"))
        if os.environ.get("FEEDBACK_URL"):
            site["feedback_url"] = os.environ["FEEDBACK_URL"]
        self.env.globals.update(base=self.base, site=site, now=self.now, sev_pt=sev_pt,
                                kind_label=KIND_LABEL, category_pt=CATEGORY_PT, site_url=settings.public_base)
        self.env.filters["date_br"] = lambda v: (parse_dt(v).strftime("%d/%m/%Y") if parse_dt(v) else "—")
        self.env.filters["datetime_br"] = lambda v: (parse_dt(v).strftime("%d/%m/%Y %H:%M UTC") if parse_dt(v) else "—")
        self.env.filters["pct"] = lambda v: f"{float(v) * 100:.1f}%"
        self.env.filters["prod"] = lambda p: p.split(":", 1)[-1].replace("_", " ")
        self.pages: list[str] = []

    # ------------------------------------------------------------------ util
    def write(self, rel: str, html: str) -> None:
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")
        if rel.endswith(".html"):
            self.pages.append(rel)

    def render(self, rel: str, tpl: str, **ctx: Any) -> None:
        self.write(rel, self.env.get_template(tpl).render(**ctx))

    def write_json(self, rel: str, data: Any) -> None:
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    # ------------------------------------------------------------------ dados
    def load(self) -> None:
        cfg = self.s.section("site")
        window = self.now - timedelta(days=int(cfg.get("window_days", 45)))
        detail_min = float(cfg.get("detail_page_min_priority", 45))
        recs = []
        for r in enriched_records(self.store, self.s):
            mod = parse_dt(r.get("lastModified")) or self.now
            if mod < window and not r.get("kev") and r["priority"]["score"] < detail_min:
                continue
            ai = r.get("ai") or {}
            if ai.get("generator") != "llm":
                r["ai"] = cve_template(r)
            r["_cvss"] = primary_cvss(r.get("cvss", []))
            r["_products"] = products_of(r)
            r["_vendors"] = vendors_of(r)
            r["_detail"] = bool(r.get("kev")) or r["priority"]["score"] >= detail_min
            recs.append(r)
        recs.sort(key=lambda r: r.get("published", ""), reverse=True)
        self.recs = recs
        days = int(self.s.section("collect").get("news_max_age_days", 14))
        limit = self.now - timedelta(days=max(days, 30))
        news = [n for n in self.store.iter_news() if (parse_dt(n.get("published")) or limit) >= limit]
        news.sort(key=lambda n: n.get("published", ""), reverse=True)
        groups: dict[str, list[dict[str, Any]]] = {}
        for n in news:
            groups.setdefault(n.get("cluster", n["id"]), []).append(n)
        self.stories = []
        for members in groups.values():
            members.sort(key=lambda x: (x.get("kind") != "official", x.get("published", "")))
            lead = members[0]
            self.stories.append({"lead": lead, "others": members[1:], "published": max(m["published"] for m in members),
                                 "cves": sorted({c for m in members for c in m.get("cves", [])}),
                                 "category": next((m.get("category") for m in members if m.get("category")), "outro")})
        self.stories.sort(key=lambda s: s["published"], reverse=True)
        self.news_by_cve: dict[str, list[dict[str, Any]]] = {}
        for n in news:
            for c in n.get("cves", []):
                self.news_by_cve.setdefault(c, []).append(n)
        self.state = self.store.load_state()

    # ------------------------------------------------------------------ páginas
    def build(self) -> None:
        if self.out.exists():
            shutil.rmtree(self.out)
        shutil.copytree(HERE / "static", self.out / "static")
        self.load()
        self.page_index()
        self.page_cves()
        self.page_news()
        self.pages_content()
        self.page_learn()
        self.page_static()
        self.feeds()
        self.sitemap()
        (self.out / ".nojekyll").write_text("", encoding="utf-8")
        log.info("site: %d páginas em %s", len(self.pages), self.out)

    def page_index(self) -> None:
        week = self.now - timedelta(days=7)
        recent = [r for r in self.recs if (parse_dt(r.get("published")) or self.now) >= week]
        kev_recent = sorted([r for r in self.recs if r.get("kev")], key=lambda r: r["kev"].get("dateAdded") or "", reverse=True)[:10]
        top_week = sorted(recent, key=lambda r: r["priority"]["score"], reverse=True)[:10]
        top_epss = sorted([r for r in self.recs if r.get("epss")], key=lambda r: r["epss"]["score"], reverse=True)[:10]
        per_day = Counter((r.get("published") or "")[:10] for r in self.recs)
        days = [(self.now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
        series = [{"day": d, "label": d[8:10] + "/" + d[5:7], "n": per_day.get(d, 0)} for d in days]
        vendors = Counter(v for r in recent for v in r["_vendors"]).most_common(8)
        sev = Counter((r["_cvss"] or {}).get("severity", "NONE") for r in recent)
        stats = {"cves_7d": len(recent), "critical_7d": sev.get("CRITICAL", 0),
                 "kev_30d": sum(1 for r in self.recs if r.get("kev") and (parse_dt((r["kev"].get("dateAdded") or "") + "T00:00:00Z") or self.now) >= self.now - timedelta(days=30)),
                 "news_7d": sum(1 for s in self.stories if (parse_dt(s["published"]) or self.now) >= week)}
        self.render("index.html", "index.html", stats=stats, kev_recent=kev_recent, top_week=top_week, top_epss=top_epss,
                    series=series, series_max=max([x["n"] for x in series] + [1]), vendors=vendors,
                    vendors_max=max([n for _, n in vendors] + [1]), sev=sev, stories=self.stories[:8], title="Painel")

    def page_cves(self) -> None:
        index = []
        for r in self.recs:
            pc = r["_cvss"] or {}
            index.append({
                "id": r["id"], "t": (r.get("title") or r.get("description_official", ""))[:160],
                "p": r.get("published", "")[:10], "s": pc.get("severity") or "", "c": pc.get("baseScore"),
                "e": (r.get("epss") or {}).get("score"), "k": 1 if r.get("kev") else 0,
                "x": 1 if (r.get("exploitation", {}).get("publicExploit") or r.get("exploitation", {}).get("publicTool")) else 0,
                "pr": r["priority"]["score"], "v": r["_vendors"][:6], "pd": [p.split(":", 1)[-1] for p in r["_products"][:6]],
                "d": 1 if r["_detail"] else 0, "cat": (r.get("ai") or {}).get("category", ""),
            })
        self.write_json("data/vulns.json", index)
        self.render("cves/index.html", "cves.html", total=len(index), title="Vulnerabilidades")
        for r in self.recs:
            if r["_detail"]:
                self.render(f"cve/{r['id']}/index.html", "cve.html", r=r, news=self.news_by_cve.get(r["id"], [])[:8],
                            title=f"{r['id']}", description=(r["ai"].get("summary_simple") or "")[:200])

    def page_news(self) -> None:
        cats = Counter(s["category"] for s in self.stories)
        self.render("noticias/index.html", "news.html", stories=self.stories[:300], cats=cats.most_common(), title="Notícias")

    def _load_md_dir(self, sub: str) -> list[dict[str, Any]]:
        d = self.s.content_dir / sub
        items = []
        for p in sorted(d.glob("*.md")) if d.exists() else []:
            meta, body = front_matter(p.read_text(encoding="utf-8"))
            items.append({"slug": p.stem, "meta": meta, "html": md_to_html(body)})
        return items

    def pages_content(self) -> None:
        reports = sorted(self._load_md_dir("reports"), key=lambda x: x["slug"], reverse=True)
        self.render("relatorios/index.html", "list.html", items=reports, section="relatorios", title="Boletins semanais",
                    intro="Resumo semanal gerado automaticamente a partir de fontes oficiais (KEV, NVD, EPSS) e notícias.")
        for it in reports:
            self.render(f"relatorios/{it['slug']}/index.html", "article.html", it=it, section="relatorios",
                        title=it["meta"].get("titulo", it["slug"]))
        ency = sorted(self._load_md_dir("encyclopedia"), key=lambda x: x["meta"].get("titulo", x["slug"]).lower())
        cwe_map: dict[str, list[dict[str, Any]]] = {}
        for r in self.recs:
            for c in r.get("cwe", []):
                cwe_map.setdefault(c, []).append(r)
        for it in ency:
            cwes = it["meta"].get("cwe", []) if isinstance(it["meta"].get("cwe"), list) else []
            related = sorted({r["id"]: r for c in cwes for r in cwe_map.get(c, [])}.values(),
                             key=lambda r: r["priority"]["score"], reverse=True)[:8]
            it["related"] = related
        self.render("enciclopedia/index.html", "list.html", items=ency, section="enciclopedia", title="Enciclopédia",
                    intro="Conceitos de segurança explicados do básico ao técnico, ligados a vulnerabilidades reais.")
        for it in ency:
            self.render(f"enciclopedia/{it['slug']}/index.html", "article.html", it=it, section="enciclopedia",
                        title=it["meta"].get("titulo", it["slug"]))

    def page_learn(self) -> None:
        decks = []
        d = self.s.content_dir / "learning"
        for p in sorted(d.glob("*.json")) if d.exists() else []:
            deck = read_json(p, {})
            # só itens revisados e publicados vão para o site (rascunhos da IA ficam de fora)
            deck["items"] = [it for it in deck.get("items", []) if it.get("status", "published") == "published"]
            if deck.get("items"):
                decks.append({"slug": p.stem, "title": deck.get("title", p.stem), "description": deck.get("description", ""),
                              "count": len(deck["items"])})
                self.write_json(f"data/learning/{p.stem}.json", deck)
        self.render("aprender/index.html", "learn.html", decks=decks, title="Aprender")

    def page_static(self) -> None:
        status = self.state.get("sources_status", {})
        runs = self.state.get("runs", [])[-1:] or [{}]
        self.render("fontes/index.html", "sources.html", status=status, last_run=runs[0],
                    feeds=self.s.raw.get("feeds", []), title="Fontes e licenças")
        self.render("sobre/index.html", "about.html", scoring=self.s.section("scoring"), title="Sobre e metodologia")
        self.render("busca/index.html", "search.html", title="Busca")
        self.render("404.html", "404.html", title="Página não encontrada")

    def feeds(self) -> None:
        base = self.s.public_base
        items = []
        for r in sorted([r for r in self.recs if r["_detail"]], key=lambda r: r.get("lastModified", ""), reverse=True)[:50]:
            items.append({"id": f"{base}/cve/{r['id']}/", "url": f"{base}/cve/{r['id']}/", "title": f"{r['id']} — {', '.join(p.split(':', 1)[-1] for p in r['_products'][:2]) or 'vulnerabilidade'}",
                          "summary": r["ai"].get("summary_simple", ""), "date": r.get("lastModified") or r.get("published")})
        feed = {"version": "https://jsonfeed.org/version/1.1", "title": self.s.section("site").get("title"),
                "home_page_url": base + "/", "feed_url": base + "/feed.json", "language": "pt-BR",
                "items": [{"id": i["id"], "url": i["url"], "title": i["title"], "content_text": i["summary"],
                           "date_modified": i["date"]} for i in items]}
        self.write_json("feed.json", feed)
        entries = "".join(
            f"<entry><id>{escape(i['id'])}</id><title>{escape(i['title'])}</title><link href=\"{escape(i['url'])}\"/>"
            f"<updated>{escape(i['date'] or '')}</updated><summary>{escape(i['summary'])}</summary></entry>" for i in items)
        atom = ('<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom" xml:lang="pt-BR">'
                f"<title>{escape(self.s.section('site').get('title', ''))}</title><id>{escape(base)}/</id>"
                f"<link href=\"{escape(base)}/feed.xml\" rel=\"self\"/><updated>{self.now.strftime('%Y-%m-%dT%H:%M:%SZ')}</updated>"
                f"{entries}</feed>")
        (self.out / "feed.xml").write_text(atom, encoding="utf-8")

    def sitemap(self) -> None:
        base = self.s.public_base
        urls = []
        for rel in self.pages:
            if rel == "404.html":
                continue
            path = "/" + rel.removesuffix("index.html")
            urls.append(f"<url><loc>{escape(base + path)}</loc></url>")
        xml = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(urls) + "</urlset>"
        (self.out / "sitemap.xml").write_text(xml, encoding="utf-8")
        (self.out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n", encoding="utf-8")


def build(settings: Settings) -> Path:
    b = Builder(settings)
    b.build()
    return settings.out_dir
