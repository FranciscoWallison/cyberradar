import json

import pytest

from cyberradar.ai import validate
from cyberradar.ai.client import AIClient, extract_json
from cyberradar.pipeline.run import enriched_records, run_all
from cyberradar.storage import Store

REC = {
    "id": "CVE-2026-10001", "aliases": [],
    "cvss": [{"version": "3.1", "baseScore": 9.8, "vector": "", "assigner": "x"}],
    "references": [{"url": "https://examplecorp.com/psirt/ADV-2026-01", "kind": "vendor"}],
    "sources": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-10001", "kind": "official"}],
}
GOOD = {
    "summary_simple": "Falha grave no gateway VPN permite ler arquivos.",
    "technical_explanation": "Path traversal (CWE-22) com CVSS 9.8.",
    "impact": {"technical": "Leitura de arquivos.", "financial": "Custos de resposta a incidente.", "operational": "Possível parada."},
    "if_not_fixed": "Roubo de credenciais.",
    "recommendations": [{"kind": "remediation", "text": "Atualize para a versão corrigida.", "sourceUrl": "https://examplecorp.com/psirt/ADV-2026-01"}],
    "category": "rede",
}


def test_valid_output_passes():
    out = validate.validate_cve_analysis(GOOD, REC)
    assert out["recommendations"][0]["sourceUrl"].startswith("https://examplecorp.com")


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(summary_simple="Relacionada à CVE-2024-0001."),                # CVE inventada
    lambda d: d.update(technical_explanation="Veja https://evil.example/x"),          # URL inventada
    lambda d: d.update(technical_explanation="Tem CVSS 7.2 segundo o fabricante."),    # nota divergente
    lambda d: d.update(recommendations=[]),                                            # sem recomendação
    lambda d: d.update(summary_simple=""),
])
def test_hallucinations_rejected(mutate):
    bad = json.loads(json.dumps(GOOD))
    mutate(bad)
    with pytest.raises(validate.ValidationError):
        validate.validate_cve_analysis(bad, REC)


def test_invented_source_url_is_dropped():
    d = json.loads(json.dumps(GOOD))
    d["recommendations"][0]["sourceUrl"] = "https://made-up.example"
    out = validate.validate_cve_analysis(d, REC)
    assert "sourceUrl" not in out["recommendations"][0]


def test_extract_json_variants():
    assert extract_json('```json\n{"a":1}\n```') == {"a": 1}
    assert extract_json('<think>hmm</think>{"a":2}') == {"a": 2}
    assert extract_json('Claro! {"a":3} espero ajudar') == {"a": 3}


def _chat(content: dict) -> tuple[int, dict]:
    return 200, {"choices": [{"message": {"content": json.dumps(content)}}]}


def test_fallback_chain_and_budget(settings, http, net, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "x")
    monkeypatch.setenv("OPENROUTER_API_KEY", "y")
    net.ai_responses = [(429, {}), _chat({"ok": True})]  # groq limita → openrouter responde
    state = {}
    ai = AIClient(http, settings.section("ai"), state)
    out, model = ai.chat_json("s", "u")
    assert out == {"ok": True} and model.startswith("openrouter/")
    today = next(iter(state["ai_usage"].values()))
    assert today == {"groq": 1, "openrouter": 1}
    # groq desativado no resto da execução
    net.ai_responses = [_chat({"ok": 2})]
    _, model = ai.chat_json("s", "u")
    assert model.startswith("openrouter/")


def test_secrets_not_sent_to_public_only_provider_for_private_data(settings, http, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "z")
    ai = AIClient(http, settings.section("ai"), {})
    with pytest.raises(Exception):
        ai.chat_json("s", "u", private_data=True)


def test_end_to_end_ai_analysis(settings, http, net, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "x")
    news = {"items": [{"id": "ignored", "title_pt": "t", "summary_pt": "s", "category": "outro"}]}
    # 1ª chamada = lote de notícias, 2ª = análise da CVE prioritária
    net.ai_responses = [_chat(news), _chat(GOOD)]
    run_all(settings, http)
    rec = {r["id"]: r for r in enriched_records(Store(settings.data_dir), settings)}["CVE-2026-10001"]
    assert rec["ai"]["generator"] == "llm" and rec["ai"]["model"].startswith("groq/")
    # o prompt enviado contém o aviso anti-injeção e os dados oficiais
    sent = [json.loads(c.content) for c in net.calls if c.url.path.endswith("/chat/completions")]
    assert any("NÃO CONFIÁVEL" in m["messages"][0]["content"] for m in sent)


def test_learning_draft(settings, http, net, monkeypatch):
    from cyberradar.ai.client import AIClient
    from cyberradar.learning import draft_weekly
    run_all(settings, http)
    recs = enriched_records(Store(settings.data_dir), settings)
    monkeypatch.setenv("GROQ_API_KEY", "x")
    mc = {"type": "multiple_choice", "prompt": "Qual CWE descreve path traversal?", "options": ["CWE-22", "CWE-79", "CWE-89", "CWE-20"],
          "answer": 0, "explanation": "CWE-22 é path traversal.", "topic": "appsec", "difficulty": 2}
    bad = dict(mc, prompt="Relacione com CVE-2019-0001")  # CVE fora dos dados → descartado
    fc = {"type": "flashcard", "prompt": "O que é KEV?", "answer": "Catálogo de falhas exploradas.", "explanation": "CISA.", "topic": "gestao"}
    net.ai_responses = [_chat({"case_study": "Uma VPN exposta...", "items": [mc, mc, bad, fc, fc]})]
    path = draft_weekly(settings, recs, AIClient(http, settings.section("ai"), {}))
    deck = json.loads(path.read_text(encoding="utf-8"))
    assert deck["generated"]["cve"] == "CVE-2026-10001" and len(deck["items"]) == 4
    assert all(it["status"] == "in_review" for it in deck["items"])
    # rascunho não aparece no site
    from cyberradar.site.build import build
    out = build(settings)
    assert not (out / f"data/learning/{path.stem}.json").exists()
