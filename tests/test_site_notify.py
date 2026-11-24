import json

from cyberradar import notify
from cyberradar.notify.bluesky import build_record
from cyberradar.pipeline.run import enriched_records, run_all
from cyberradar.report import build_weekly
from cyberradar.site.build import build
from cyberradar.storage import Store


def test_site_build(settings, http):
    run_all(settings, http)
    out = build(settings)
    for rel in ["index.html", "cves/index.html", "cve/CVE-2026-10001/index.html", "noticias/index.html",
                "enciclopedia/index.html", "aprender/index.html", "fontes/index.html", "sobre/index.html",
                "feed.xml", "feed.json", "sitemap.xml", "data/vulns.json", "static/vendor/ts-fsrs-5.2.3.mjs"]:
        assert (out / rel).exists(), rel
    page = (out / "cve/CVE-2026-10001/index.html").read_text(encoding="utf-8")
    assert "This product uses the NVD API" in page
    assert "Automático" in page  # sem IA → selo de texto automático
    # conteúdo externo é escapado (o feed contém tags HTML e texto de injeção)
    news = (out / "noticias/index.html").read_text(encoding="utf-8")
    assert "<b>path traversal</b>" not in news
    idx = json.loads((out / "data/vulns.json").read_text(encoding="utf-8"))
    assert any(r["id"] == "CVE-2026-10001" and r["k"] == 1 for r in idx)
    # CSP sem scripts inline
    assert "onsubmit=" not in (out / "cves/index.html").read_text(encoding="utf-8")


def test_base_path(settings, http, monkeypatch):
    monkeypatch.setenv("SITE_BASE_PATH", "/cyberradar")
    run_all(settings, http)
    out = build(settings)
    assert 'href="/cyberradar/static/css/style.css"' in (out / "index.html").read_text(encoding="utf-8")


def test_alerts_bootstrap_then_send(settings, http, net, monkeypatch):
    run_all(settings, http)
    store = Store(settings.data_dir)
    recs = enriched_records(store, settings)
    state = store.load_state()
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "@canal")
    # 1ª execução só marca como visto (sem enxurrada de alertas antigos)
    assert notify.run(settings, http, recs, state) == 0
    assert "CVE-2026-10001" in state["notified"]
    # novo item prioritário chega → é enviado
    new = dict(recs[0]); new["id"] = "CVE-2026-19999"; new["priority"] = {"score": 95, "breakdown": {}}
    assert notify.run(settings, http, [new], state) == 1
    assert any(c.url.host == "api.telegram.org" for c in net.calls)


def test_bluesky_facet_offsets_are_bytes():
    url = "https://exemplo.github.io/cr/cve/CVE-2026-1/"
    rec = build_record(f"🚨 Ação: {url}", url)
    f = rec["facets"][0]["index"]
    assert rec["text"].encode()[f["byteStart"]:f["byteEnd"]].decode() == url


def test_weekly_report(settings, http):
    run_all(settings, http)
    store = Store(settings.data_dir)
    path = build_weekly(settings, enriched_records(store, settings), store)
    text = path.read_text(encoding="utf-8")
    assert "CVE-2026-10001" in text and "Boletim semanal 2026-W48" in text
