import json

from cyberradar.collectors import find_cves, nvd, rss
from cyberradar.pipeline import dedupe
from cyberradar.pipeline.normalize import primary_cvss
from cyberradar.pipeline.run import enriched_records, run_all
from cyberradar.storage import Store


def test_find_cves_dedup_and_upper():
    assert find_cves("cve-2026-1234 e CVE-2026-1234, CVE-2025-99999") == ["CVE-2026-1234", "CVE-2025-99999"]


def test_nvd_parse_prefers_cna_cvss():
    item = json.loads(open("tests/fixtures/nvd.json").read())["vulnerabilities"][0]
    rec = nvd.parse_cve(item)
    assert rec["cwe"] == ["CWE-22"]
    assert rec["exploitation"]["publicExploit"] is True
    assert rec["affected"][0]["vendor"] == "examplecorp"
    assert rec["affected"][0]["versions"] == [{"versionEndExcluding": "7.2.5"}]
    pc = primary_cvss(rec["cvss"])
    assert pc["baseScore"] == 9.8 and pc["assigner"] == "psirt@examplecorp.com"


def test_rss_parse_strips_html_and_tracking():
    items = rss.parse_feed(open("tests/fixtures/feed.xml", "rb").read(), {"name": "X", "kind": "news"})
    assert len(items) == 3  # item sem link é descartado
    first = items[0]
    assert "<" not in first["excerpt"]
    assert "utm_source" not in first["url"]
    assert first["cves"] == ["CVE-2026-10001"]


def test_dedupe_groups_same_story():
    items = rss.parse_feed(open("tests/fixtures/feed.xml", "rb").read(), {"name": "X", "kind": "news"})
    dedupe.cluster(items)
    clusters = {it["cluster"] for it in items}
    assert len(clusters) == 2  # duas notícias da VPN juntas + phishing separado


def test_full_run_without_any_key(settings, http, net):
    stats = run_all(settings, http)
    assert stats["ai_providers"] == []  # sem chaves → só templates
    store = Store(settings.data_dir)
    recs = {r["id"]: r for r in enriched_records(store, settings)}
    assert {"CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003", "GHSA-mnop-qrst-uvwx"} <= set(recs)
    top = recs["CVE-2026-10001"]
    assert top["kev"]["listed"] and top["priority"]["score"] > 90
    assert "GHSA-abcd-efgh-ijkl" in recs["CVE-2026-10002"]["aliases"]
    # campos voláteis não vão para o arquivo
    raw = json.loads(store.vuln_path("CVE-2026-10001").read_text(encoding="utf-8"))
    assert "epss" not in raw and "priority" not in raw and "kev" not in raw
    # nenhum provedor de IA foi chamado
    assert not any(c.url.path.endswith("/chat/completions") for c in net.calls)
    # segunda execução idempotente: não reescreve arquivos
    before = store.vuln_path("CVE-2026-10001").stat().st_mtime_ns
    run_all(settings, http)
    assert store.vuln_path("CVE-2026-10001").stat().st_mtime_ns == before


def test_recent_kev_entry_gets_seeded(settings, http, net):
    kev = json.loads(open("tests/fixtures/kev.json").read())
    kev["vulnerabilities"].append({"cveID": "CVE-2025-55555", "vendorProject": "Acme", "product": "Edge Router",
                                   "vulnerabilityName": "Acme Edge Router RCE", "dateAdded": "2026-11-20",
                                   "shortDescription": "RCE.", "requiredAction": "Patch.", "dueDate": "2026-12-11",
                                   "knownRansomwareCampaignUse": "Unknown", "notes": ""})
    net.kev_override = kev
    store = Store(settings.data_dir)
    for attempt in range(1, 5):
        run_all(settings, http)
        rec = store.get_vuln("CVE-2025-55555")
        assert rec["kev_seed"] is True and rec["affected"][0]["vendor"] == "acme"
        assert rec["seed_attempts"] == min(attempt, 3)  # para de insistir no NVD após 3 tentativas
    # o filtro por ID impede gravar CVEs que não foram pedidas
    assert store.get_vuln("CVE-2021-44228") is None


def test_ghsa_with_unknown_cve_creates_record(settings, http, net):
    ghsa = json.loads(open("tests/fixtures/ghsa.json").read())
    ghsa[0]["cve_id"] = "CVE-2026-20000"
    import httpx
    orig = net.__call__
    net_calls = []

    def handler(req):
        net_calls.append(req)
        if req.url.host == "api.github.com":
            return httpx.Response(200, json=ghsa)
        return orig(req)
    from cyberradar.http import HttpClient
    h = HttpClient(transport=httpx.MockTransport(handler), sleep=lambda s: None)
    run_all(settings, h)
    rec = Store(settings.data_dir).get_vuln("CVE-2026-20000")
    assert rec and "GHSA-abcd-efgh-ijkl" in rec["aliases"] and rec["packages"][0]["name"] == "examplecms-comments"


def test_exploit_signals(settings, http):
    run_all(settings, http)
    store = Store(settings.data_dir)
    recs = {r["id"]: r for r in enriched_records(store, settings)}
    a, b = recs["CVE-2026-10001"], recs["CVE-2026-10002"]
    assert a["signals"]["msf"][0]["url"].endswith("/modules/exploits/multi/http/example_vpn_traversal.rb")
    assert len(a["signals"]["msf"]) == 1  # payload ignorado
    assert b["signals"]["nuclei"].endswith("CVE-2026-10002.yaml")
    assert b["exploitation"]["publicTool"] and b["priority"]["breakdown"]["exploit_publico"] > 0
    raw = json.loads(store.vuln_path("CVE-2026-10002").read_text(encoding="utf-8"))
    assert "signals" not in raw and "publicTool" not in raw.get("exploitation", {})
