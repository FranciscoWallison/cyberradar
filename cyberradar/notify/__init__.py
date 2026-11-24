"""Alertas: Telegram (canal), Discord (webhook), Bluesky. Cada canal só é usado se o segredo existir."""
from __future__ import annotations

import logging
from typing import Any

from ..ai.templates import sev_pt
from ..config import Settings, env
from ..http import HttpClient
from ..pipeline.normalize import primary_cvss, products_of
from . import bluesky, discord, telegram

log = logging.getLogger(__name__)


def channels() -> list[str]:
    out = []
    if env("TELEGRAM_BOT_TOKEN") and env("TELEGRAM_CHAT_ID"):
        out.append("telegram")
    if env("DISCORD_WEBHOOK_URL"):
        out.append("discord")
    if env("BLUESKY_HANDLE") and env("BLUESKY_APP_PASSWORD"):
        out.append("bluesky")
    return out


def cve_url(settings: Settings, vid: str) -> str:
    return f"{settings.public_base}/cve/{vid}/"


def format_alert(rec: dict[str, Any], settings: Settings) -> dict[str, str]:
    pc = primary_cvss(rec.get("cvss", []))
    prods = ", ".join(p.split(":", 1)[1].replace("_", " ") for p in products_of(rec)[:3]) or "produto não informado"
    head = "🚨 Explorada ativamente (CISA KEV)" if rec.get("kev") else "⚠️ Vulnerabilidade prioritária"
    sev = f"{sev_pt(pc['severity'])} · CVSS {pc['baseScore']:.1f}" if pc else "sem CVSS publicado"
    ep = rec.get("epss") or {}
    eps = f" · EPSS {ep['score'] * 100:.1f}%" if ep.get("score") is not None else ""
    summary = (rec.get("ai") or {}).get("summary_simple") or rec.get("description_official", "")
    summary = summary[:400] + ("…" if len(summary) > 400 else "")
    label = "Resumo gerado por IA" if (rec.get("ai") or {}).get("generator") == "llm" else "Resumo automático"
    url = cve_url(settings, rec["id"])
    text = f"{head}\n{rec['id']} — {prods}\n{sev}{eps} · prioridade {rec['priority']['score']:.0f}/100\n\n{summary}\n({label})\n\n{url}"
    short = f"{head}: {rec['id']} — {prods} ({sev}). {url}"
    return {"text": text, "short": short, "url": url, "title": f"{rec['id']} — {prods}"}


def send(http: HttpClient, msg: dict[str, str]) -> list[str]:
    sent = []
    for ch in channels():
        try:
            if ch == "telegram":
                telegram.send(http, env("TELEGRAM_BOT_TOKEN"), env("TELEGRAM_CHAT_ID"), msg["text"])
            elif ch == "discord":
                discord.send(http, env("DISCORD_WEBHOOK_URL"), msg["text"])
            elif ch == "bluesky":
                bluesky.post(http, env("BLUESKY_HANDLE"), env("BLUESKY_APP_PASSWORD"), msg["short"], msg["url"])
            sent.append(ch)
        except Exception as exc:  # noqa: BLE001
            log.warning("falha ao notificar via %s: %s", ch, exc.__class__.__name__)
    return sent


def select_alerts(records: list[dict[str, Any]], state: dict[str, Any], settings: Settings) -> list[dict[str, Any]]:
    cfg = settings.section("alerts")
    notified = set(state.get("notified", []))
    kev_new = set(state.get("kev_new", []))
    min_p = float(cfg.get("min_priority", 70))
    picks = [r for r in records if r["id"] not in notified and (r["id"] in kev_new or r["priority"]["score"] >= min_p)]
    picks.sort(key=lambda r: (r["id"] in kev_new, r["priority"]["score"]), reverse=True)
    return picks[: int(cfg.get("max_per_run", 8))]


def run(settings: Settings, http: HttpClient, records: list[dict[str, Any]], state: dict[str, Any], dry_run: bool = False) -> int:
    chans = channels()
    if not chans and not dry_run:
        log.info("nenhum canal de alerta configurado; pulando notificações")
        return 0
    picks = select_alerts(records, state, settings)
    if not state.get("notified") and not state.get("alerts_bootstrapped"):
        # Primeira execução: marca o que já existe como "visto" para não disparar dezenas de alertas antigos.
        state["notified"] = [r["id"] for r in records if r["priority"]["score"] >= float(settings.section("alerts").get("min_priority", 70))]
        state["alerts_bootstrapped"] = True
        log.info("primeira execução: %d itens marcados como já notificados", len(state["notified"]))
        return 0
    n = 0
    for r in picks:
        msg = format_alert(r, settings)
        if dry_run:
            print("-" * 60 + "\n" + msg["text"])
        elif not send(http, msg):
            continue
        state.setdefault("notified", []).append(r["id"])
        n += 1
    return n
