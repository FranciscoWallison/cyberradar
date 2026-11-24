"""Orquestração: coleta → normalização → enriquecimento → IA → poda → estado."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from ..ai.analyze import analyze_cves, translate_news
from ..ai.client import AIClient
from ..collectors import epss as epss_c, exploits as exploits_c, ghsa as ghsa_c, kev as kev_c, nvd as nvd_c, rss as rss_c
from ..config import Settings
from ..http import HttpClient
from ..storage import Store, iso, now_utc, parse_dt
from .dedupe import cluster
from .normalize import carry_over, ghsa_only_record, merge_ghsa
from .score import priority

log = logging.getLogger(__name__)


def enrich(rec: dict[str, Any], kev: dict[str, Any], epss: dict[str, Any], scoring: dict[str, Any],
           exploits: dict[str, Any] | None = None) -> dict[str, Any]:
    r = dict(rec)
    r["exploitation"] = dict(rec.get("exploitation") or {})  # cópia: campos derivados não vão para o arquivo
    ids = [r["id"], *r.get("aliases", [])]
    k = next((kev[i] for i in ids if i in kev), None)
    if k:
        r["kev"] = k
        r["exploitation"]["activeExploitation"] = True
    sig = next(((exploits or {})[i] for i in ids if i in (exploits or {})), None)
    if sig:
        r["signals"] = sig
        if sig.get("nuclei") or any(m.get("type") == "exploit" for m in sig.get("msf", [])):
            r["exploitation"]["publicTool"] = True
    e = next((epss[i] for i in ids if i in epss), None)
    if e:
        r["epss"] = e
    r["priority"] = priority(r, scoring)
    return r


def enriched_records(store: Store, settings: Settings) -> list[dict[str, Any]]:
    kev, epss, exploits = store.load_kev(), store.load_epss(), store.load_exploits()
    scoring = settings.section("scoring")
    return [enrich(r, kev, epss, scoring, exploits) for r in store.iter_vulns()]


def collect(settings: Settings, http: HttpClient, store: Store, state: dict[str, Any]) -> dict[str, Any]:
    cfg = settings.section("collect")
    now = now_utc()
    stats: dict[str, Any] = {"started": iso(now)}

    # 1) KEV (um JSON pequeno; sempre completo)
    kev = kev_c.fetch(http)
    if kev:
        old = set(state.get("kev_seen", []))
        new_kev = sorted(set(kev) - old) if old else []
        state["kev_seen"] = sorted(kev)
        state["kev_new"] = new_kev
        store.save_kev(kev)
        stats["kev_new"] = len(new_kev)
    else:
        kev = store.load_kev()
        state["kev_new"] = []

    # 2) NVD incremental
    cur = parse_dt(state["cursors"].get("nvd")) or (now - timedelta(days=int(cfg.get("nvd_initial_days", 7))))
    since = cur - timedelta(minutes=5)  # pequena sobreposição
    changed: list[str] = []
    try:
        for rec in nvd_c.fetch(http, since, now, int(cfg.get("nvd_page_size", 2000))):
            old = store.get_vuln(rec["id"])
            rec = carry_over(rec, old)
            rec.setdefault("first_seen", (old or {}).get("first_seen") or iso(now))
            if store.put_vuln(rec):
                changed.append(rec["id"])
        state["cursors"]["nvd"] = iso(now)
        _ok(state, "NVD")
    except Exception as exc:  # noqa: BLE001
        log.error("NVD falhou: %s (cursor mantido)", exc)
        _fail(state, "NVD")
    stats["nvd_changed"] = len(changed)

    # 2b) Entradas recentes do KEV que ainda não temos: busca no NVD pelo ID; sem sucesso, registro mínimo.
    recent_kev_limit = (now - timedelta(days=int(cfg.get("kev_seed_days", 30)))).strftime("%Y-%m-%d")
    max_attempts = int(cfg.get("kev_seed_max_attempts", 3))
    missing = []
    for cid, k in sorted(kev.items()):
        if (k.get("dateAdded") or "") < recent_kev_limit:
            continue
        cur_rec = store.get_vuln(cid)
        # sem registro, ou registro mínimo ainda não completado pelo NVD (com limite de tentativas)
        if cur_rec is None or (cur_rec.get("kev_seed") and cur_rec.get("seed_attempts", 0) < max_attempts):
            missing.append(cid)
    fetched: set[str] = set()
    if missing:
        try:
            for rec in nvd_c.fetch_ids(http, missing[: int(cfg.get("kev_seed_max_per_run", 20))]):
                rec["first_seen"] = (store.get_vuln(rec["id"]) or {}).get("first_seen") or iso(now)
                store.put_vuln(rec)
                fetched.add(rec["id"])
        except Exception as exc:  # noqa: BLE001
            log.warning("NVD (busca por ID) falhou: %s", exc)
    attempted = set(missing[: int(cfg.get("kev_seed_max_per_run", 20))])
    for cid in missing:
        if cid in fetched:
            continue
        k = kev[cid]
        prev = store.get_vuln(cid) or {}
        store.put_vuln({
            "id": cid, "title": k.get("name"), "published": (k.get("dateAdded") or "") + "T00:00:00Z",
            "lastModified": (k.get("dateAdded") or "") + "T00:00:00Z",
            "description_official": k.get("shortDescription", ""), "cvss": [], "cwe": [],
            "affected": [{"vendor": (k.get("vendorProject") or "").lower().replace(" ", ""),
                          "product": (k.get("product") or "").lower().replace(" ", "_"), "versions": []}],
            "references": [], "exploitation": {"publicExploit": False},
            "sources": [{"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "name": "CISA KEV",
                         "kind": "official", "license": "CC0"}],
            "first_seen": prev.get("first_seen") or iso(now), "kev_seed": True,
            "seed_attempts": prev.get("seed_attempts", 0) + (1 if cid in attempted else 0),
        })

    # 3) GitHub Advisory Database
    gcur = parse_dt(state["cursors"].get("ghsa")) or (now - timedelta(days=int(cfg.get("nvd_initial_days", 7))))
    try:
        for adv in ghsa_c.fetch(http, gcur, int(cfg.get("ghsa_pages", 2))):
            if adv.get("cve_id"):
                rec = store.get_vuln(adv["cve_id"])
                if rec is None:  # CVE ainda não vista no NVD: cria a partir do GHSA (o NVD completa depois)
                    rec = ghsa_only_record(adv)
                    rec["id"] = adv["cve_id"]
                    rec["first_seen"] = iso(now)
                store.put_vuln(merge_ghsa(rec, adv))
            elif adv.get("ghsa_id"):
                old = store.get_vuln(adv["ghsa_id"])
                store.put_vuln(carry_over(ghsa_only_record(adv), old))
        state["cursors"]["ghsa"] = iso(now)
        _ok(state, "GitHub Advisory")
    except Exception as exc:  # noqa: BLE001
        log.error("GHSA falhou: %s", exc)
        _fail(state, "GitHub Advisory")

    # 4) EPSS — uma vez por dia, só para as CVEs rastreadas
    today = now.strftime("%Y-%m-%d")
    if state["cursors"].get("epss_day") != today:
        ids = {r["id"] for r in store.iter_vulns()} | set(kev)
        got = epss_c.fetch(http, ids)
        if got:
            # mescla com o anterior (falha parcial não apaga dados) e descarta CVEs não rastreadas
            merged = {k: v for k, v in store.load_epss().items() if k in ids}
            merged.update(got)
            store.save_epss(merged)
            state["cursors"]["epss_day"] = today
            _ok(state, "EPSS")
        else:
            _fail(state, "EPSS")

    # 4b) Sinais de exploit/detecção pública — uma vez por dia
    if cfg.get("exploit_signals", True) and state["cursors"].get("exploits_day") != today:
        sig = exploits_c.fetch(http)
        if sig is not None:
            tracked = {r["id"] for r in store.iter_vulns()} | set(kev)
            store.save_exploits({k: v for k, v in sig.items() if k in tracked})  # só o que rastreamos
            state["cursors"]["exploits_day"] = today
            _ok(state, "Nuclei/Metasploit")
        else:
            _fail(state, "Nuclei/Metasploit")

    # 5) Notícias
    feeds = settings.raw.get("feeds", [])
    fresh = rss_c.fetch(http, feeds, state, int(cfg.get("rss_max_items_per_feed", 30)))
    max_age = now - timedelta(days=int(cfg.get("news_max_age_days", 14)))
    fresh = [n for n in fresh if (parse_dt(n["published"]) or now) >= max_age]
    stats["news_new"] = _merge_news(store, fresh)
    return stats


def _merge_news(store: Store, fresh: list[dict[str, Any]]) -> int:
    added = 0
    by_month: dict[str, list[dict[str, Any]]] = {}
    for n in fresh:
        by_month.setdefault(n["published"][:7], []).append(n)
    for month, items in by_month.items():
        cur = {x["id"]: x for x in store.load_news_month(month)}
        for n in items:
            if n["id"] not in cur:
                cur[n["id"]] = n
                added += 1
        store.save_news_month(month, list(cur.values()))
    return added


def recent_news(store: Store, days: int) -> list[dict[str, Any]]:
    limit = now_utc() - timedelta(days=days)
    return [n for n in store.iter_news() if (parse_dt(n.get("published")) or limit) >= limit]


def process_news(settings: Settings, store: Store, ai: AIClient) -> int:
    days = int(settings.section("collect").get("news_max_age_days", 14))
    items = recent_news(store, days)
    cluster(items)
    n = translate_news(items, ai, settings.section("ai"))
    by_month: dict[str, list[dict[str, Any]]] = {}
    for it in items:
        by_month.setdefault(it["published"][:7], []).append(it)
    for month, its in by_month.items():
        cur = {x["id"]: x for x in store.load_news_month(month)}
        for it in its:
            cur[it["id"]] = it
        store.save_news_month(month, list(cur.values()))
    return n


def news_by_cve(store: Store, days: int = 30) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for n in recent_news(store, days):
        for c in n.get("cves", []):
            out.setdefault(c, []).append(n)
    return out


def prune(settings: Settings, store: Store, records: list[dict[str, Any]]) -> int:
    cfg = settings.section("retention")
    limit = now_utc() - timedelta(days=int(cfg.get("prune_after_days", 120)))
    keep_p = float(cfg.get("keep_min_priority", 50))
    removed = 0
    for r in records:
        mod = parse_dt(r.get("lastModified")) or now_utc()
        if mod < limit and not r.get("kev") and r["priority"]["score"] < keep_p:
            store.delete_vuln(r["id"])
            removed += 1
    return removed


def run_all(settings: Settings, http: HttpClient, skip_collect: bool = False) -> dict[str, Any]:
    store = Store(settings.data_dir)
    state = store.load_state()
    stats: dict[str, Any] = {}
    if not skip_collect:
        stats.update(collect(settings, http, store, state))
    ai = AIClient(http, settings.section("ai"), state)
    stats["ai_providers"] = [p.name for p in ai.providers]
    stats["news_translated"] = process_news(settings, store, ai)
    records = enriched_records(store, settings)
    stats["cve_analyzed"] = analyze_cves(store, records, ai, settings.section("ai"), news_by_cve(store))
    stats["pruned"] = prune(settings, store, enriched_records(store, settings))
    stats["finished"] = iso(now_utc())
    state["runs"].append(stats)
    store.save_state(state)
    log.info("execução concluída: %s", stats)
    return stats


def _ok(state: dict[str, Any], name: str) -> None:
    st = state.setdefault("sources_status", {})
    st[name] = {"last_ok": iso(now_utc()), "last_error": None, "failures": 0}


def _fail(state: dict[str, Any], name: str) -> None:
    st = state.setdefault("sources_status", {})
    prev = st.get(name, {})
    st[name] = {"last_ok": prev.get("last_ok"), "last_error": iso(now_utc()), "failures": prev.get("failures", 0) + 1}
