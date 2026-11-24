"""'Caso da semana': transforma a vulnerabilidade mais relevante da semana em material de estudo.

A IA gera um RASCUNHO (status in_review). Nada é publicado até um humano revisar e mudar o status
para `published` — o workflow learning-draft.yml abre um Pull Request para essa revisão.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

import jsonschema

from .ai.client import AIClient, NoProviderAvailable
from .collectors import find_cves
from .config import Settings
from .report import week_slug
from .storage import now_utc, parse_dt

log = logging.getLogger(__name__)

PROMPT_VERSION = "learn-2026-11-a"
SYSTEM = """Você é professor de segurança da informação e cria material ORIGINAL em português do Brasil
para quem estuda para certificações de entrada (Security+, ISC2 CC, SC-900).
Use SOMENTE os fatos do bloco <dados>. Não invente versões, CVSS, produtos ou outras CVEs.
Não inclua código de exploração nem passo a passo de ataque: foque em conceitos, impacto, detecção e defesa.
Não copie questões de provas reais.
Responda APENAS com JSON:
{
 "case_study": "estudo de caso de 1–2 parágrafos explicando o incidente/vulnerabilidade e o que ele ensina",
 "items": [
   {"type": "multiple_choice", "prompt": "...", "options": ["...", "...", "...", "..."], "answer": 0,
    "explanation": "por que a correta está certa e as outras não", "topic": "tema curto", "difficulty": 2},
   {"type": "flashcard", "prompt": "pergunta curta", "answer": "resposta curta", "explanation": "...", "topic": "...", "difficulty": 1}
 ]
}
Gere exatamente 3 itens multiple_choice (4 opções, uma correta) e 3 itens flashcard."""


def pick_case(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    start = now_utc() - timedelta(days=7)

    def recent(r: dict[str, Any]) -> bool:
        kev_added = parse_dt(((r.get("kev") or {}).get("dateAdded") or "") + "T00:00:00Z")
        pub = parse_dt(r.get("published"))
        return bool((kev_added and kev_added >= start) or (pub and pub >= start))

    cands = [r for r in records if recent(r) and r.get("description_official")]
    cands.sort(key=lambda r: ((r.get("ai") or {}).get("generator") == "llm", r["priority"]["score"]), reverse=True)
    return cands[0] if cands else None


def _user_prompt(rec: dict[str, Any]) -> str:
    ai = rec.get("ai") or {}
    data = {
        "id": rec["id"], "description_official": rec.get("description_official", "")[:2500],
        "cwe": rec.get("cwe", []), "cvss": rec.get("cvss", [])[:2], "epss": rec.get("epss"),
        "kev": bool(rec.get("kev")), "ransomware": (rec.get("kev") or {}).get("knownRansomwareCampaignUse"),
        "affected_products": [f'{a.get("vendor")} {a.get("product")}' for a in rec.get("affected", [])[:5]],
        "summary_pt": ai.get("summary_simple"), "recommendations": [x.get("text") for x in ai.get("recommendations", [])],
    }
    return f"<dados>\n{json.dumps(data, ensure_ascii=False)}\n</dados>"


def build_deck(out: Any, rec: dict[str, Any], schema: dict[str, Any], model: str) -> dict[str, Any]:
    if not isinstance(out, dict) or not isinstance(out.get("items"), list):
        raise ValueError("formato inválido")
    slug = week_slug()
    allowed = {rec["id"], *rec.get("aliases", [])}
    case = str(out.get("case_study") or "").strip()
    if not case or len(case) > 3000:
        raise ValueError("estudo de caso ausente")
    items = []
    for i, it in enumerate(out["items"][:8], 1):
        if not isinstance(it, dict) or it.get("type") not in ("multiple_choice", "flashcard"):
            continue
        item = {
            "id": f"caso-{slug}-{i:02d}", "type": it["type"], "prompt": str(it.get("prompt", "")).strip(),
            "explanation": str(it.get("explanation", "")).strip(),
            "difficulty": int(it.get("difficulty") or 2) if str(it.get("difficulty", "2")).isdigit() else 2,
            "objectives": [{"exam": "NUCLEO", "code": str(it.get("topic") or "caso-da-semana")[:60]}],
            "related": {"cve": [rec["id"]]},
            "sources": [s["url"] for s in rec.get("sources", [])[:2]],
            "origin": "ai_draft_human_reviewed", "status": "in_review",
        }
        item["difficulty"] = min(max(item["difficulty"], 1), 5)
        if it["type"] == "multiple_choice":
            opts = [str(o).strip() for o in (it.get("options") or [])]
            ans = it.get("answer")
            if len(opts) != 4 or not isinstance(ans, int) or not 0 <= ans < 4:
                continue
            item["options"], item["answer"] = opts, ans
        else:
            item["answer"] = str(it.get("answer", "")).strip()
            if not item["answer"]:
                continue
        blob = " ".join([item["prompt"], item["explanation"], json.dumps(item.get("options", [])), str(item["answer"])])
        if any(c not in allowed for c in find_cves(blob)):
            continue  # cita CVE que não está nos dados
        try:
            jsonschema.validate(item, schema)
        except jsonschema.ValidationError:
            continue
        if item["prompt"] and item["explanation"]:
            items.append(item)
    if len(items) < 3:
        raise ValueError(f"poucos itens válidos ({len(items)})")
    return {
        "title": f"Caso da semana {slug}: {rec['id']}",
        "description": case,
        "license": "CC BY 4.0 (conteúdo próprio do projeto)",
        "generated": {"by": model, "promptVersion": PROMPT_VERSION, "at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "cve": rec["id"]},
        "note": "RASCUNHO gerado por IA. Revise cada item, corrija o que for preciso e mude status para 'published'.",
        "items": items,
    }


def draft_weekly(settings: Settings, records: list[dict[str, Any]], ai: AIClient) -> Path | None:
    rec = pick_case(records)
    if not rec:
        log.info("nenhuma vulnerabilidade recente para o caso da semana")
        return None
    if not ai.available:
        log.info("sem provedor de IA configurado: caso da semana não gerado")
        return None
    schema = json.loads((settings.root / "schemas" / "learning-item.schema.json").read_text(encoding="utf-8"))
    last_err: Exception | None = None
    for _ in range(2):
        try:
            out, model = ai.chat_json(SYSTEM, _user_prompt(rec))
            deck = build_deck(out, rec, schema, model)
            break
        except NoProviderAvailable as exc:
            log.warning("IA indisponível: %s", exc)
            return None
        except (ValueError, TypeError) as exc:
            last_err = exc
    else:
        log.warning("rascunho rejeitado: %s", last_err)
        return None
    path = settings.content_dir / "learning" / f"caso-da-semana-{week_slug()}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(deck, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return path
