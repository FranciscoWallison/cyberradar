"""Orquestra as análises por IA respeitando orçamento, com fallback para template."""
from __future__ import annotations

import logging
from typing import Any

from ..storage import Store, iso, now_utc
from . import prompts
from .client import AIClient, NoProviderAvailable
from .validate import ValidationError, validate_cve_analysis, validate_news_batch

log = logging.getLogger(__name__)


def needs_ai(rec: dict[str, Any], min_priority: float) -> bool:
    if rec.get("priority", {}).get("score", 0) < min_priority:
        return False
    fail = rec.get("ai_attempt") or {}
    if (fail.get("sourceModified") == rec.get("lastModified") and fail.get("promptVersion") == prompts.PROMPT_VERSION
            and fail.get("count", 0) >= 2):
        return False  # já falhou 2x para esta versão do registro; não gastar cota de novo
    ai = rec.get("ai") or {}
    if ai.get("generator") != "llm":
        return True
    return ai.get("promptVersion") != prompts.PROMPT_VERSION or ai.get("sourceModified") != rec.get("lastModified")


def analyze_cves(store: Store, records: list[dict[str, Any]], client: AIClient, cfg: dict[str, Any],
                 news_by_cve: dict[str, list[dict[str, Any]]]) -> int:
    """`records` já enriquecidos (KEV/EPSS/prioridade em memória)."""
    min_p = float(cfg.get("min_priority", 55))
    budget = int(cfg.get("max_cve_per_run", 6))
    candidates = [r for r in records if needs_ai(r, min_p)]
    candidates.sort(key=lambda r: r.get("priority", {}).get("score", 0), reverse=True)
    done = 0
    for rec in candidates:
        if done >= budget or not client.available:
            break
        news = news_by_cve.get(rec["id"], [])
        try:
            out, model = client.chat_json(prompts.CVE_SYSTEM, prompts.cve_user_prompt(rec, news))
            res = validate_cve_analysis(out, rec)
        except NoProviderAvailable as exc:
            log.info("IA indisponível (%s); restante fica com template", exc)
            break
        except (ValidationError, ValueError) as exc:
            log.warning("IA: saída rejeitada para %s (%s); usando template", rec["id"], exc)
            prev = rec.get("ai_attempt") or {}
            same = prev.get("sourceModified") == rec.get("lastModified")
            rec["ai_attempt"] = {"sourceModified": rec.get("lastModified"), "promptVersion": prompts.PROMPT_VERSION,
                                 "count": (prev.get("count", 0) if same else 0) + 1, "error": str(exc)[:200]}
            store.put_vuln(rec)
            done += 1
            continue
        res.update({"generator": "llm", "lang": "pt-BR", "model": model, "promptVersion": prompts.PROMPT_VERSION,
                    "generatedAt": iso(now_utc()), "sourceModified": rec.get("lastModified"), "reviewedByHuman": False})
        rec["ai"] = res
        rec.pop("ai_attempt", None)
        store.put_vuln(rec)
        done += 1
        log.info("IA: %s analisada por %s", rec["id"], model)
    return done


def translate_news(items: list[dict[str, Any]], client: AIClient, cfg: dict[str, Any]) -> int:
    pending = [it for it in items if not it.get("title_pt") and it.get("lang") != "pt"]
    # prioriza itens oficiais e os que citam CVEs; mais recentes primeiro
    pending.sort(key=lambda it: (it.get("kind") == "official", bool(it.get("cves")), it.get("published", "")), reverse=True)
    size = int(cfg.get("news_batch_size", 8))
    batches = int(cfg.get("max_news_batches_per_run", 3))
    done = 0
    for b in range(batches):
        chunk = pending[b * size:(b + 1) * size]
        if not chunk or not client.available:
            break
        try:
            out, model = client.chat_json(prompts.NEWS_SYSTEM, prompts.news_user_prompt(chunk))
            res = validate_news_batch(out, {it["id"] for it in chunk})
        except NoProviderAvailable as exc:
            log.info("IA indisponível para notícias (%s)", exc)
            break
        except (ValidationError, ValueError) as exc:
            log.warning("IA: lote de notícias rejeitado (%s)", exc)
            continue
        for it in chunk:
            if it["id"] in res:
                it.update(res[it["id"]])
                it["ai_model"] = model
                it["ai_prompt"] = prompts.NEWS_PROMPT_VERSION
                done += 1
    for it in items:  # itens já em português dispensam tradução
        if it.get("lang") == "pt" and not it.get("title_pt"):
            it["title_pt"] = it["title"]
            it["summary_pt"] = it.get("excerpt", "")
    return done
