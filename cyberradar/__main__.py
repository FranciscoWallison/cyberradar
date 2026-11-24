"""CLI: python -m cyberradar <comando>

  update        coleta fontes + IA + poda (o que o cron executa)
  process       só IA/notícias, sem coletar (útil para testar provedores)
  notify        envia alertas pendentes (use --dry-run para só imprimir)
  report        gera o boletim semanal em content/reports/
  announce      publica nos canais o link do boletim da semana (após o deploy)
  learning-draft  gera o rascunho do "caso da semana" (IA) em content/learning/ para revisão humana
  validate      valida content/learning/*.json contra schemas/learning-item.schema.json
  build         gera o site em _site/ (e o índice de busca, se o Pagefind estiver instalado)
  serve         serve _site/ em http://localhost:8000 para conferir localmente
  status        mostra provedores de IA e canais configurados (sem revelar segredos)
"""
from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys

from . import config
from .http import HttpClient


def _search_index(out_dir) -> None:
    cmd = [sys.executable, "-m", "pagefind", "--site", str(out_dir)]
    try:
        subprocess.run(cmd, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        exe = shutil.which("pagefind")
        if exe:
            subprocess.run([exe, "--site", str(out_dir)], check=True)
        else:
            logging.warning("Pagefind não encontrado: busca desativada (pip install 'pagefind[extended]')")


def _load_dotenv() -> None:
    """Carrega .env da raiz (só uso local; não sobrescreve variáveis já definidas)."""
    path = config.ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if v and k not in os.environ:
            os.environ[k] = v


def _validate(s) -> int:
    import json

    import jsonschema
    schema = json.loads((s.root / "schemas" / "learning-item.schema.json").read_text(encoding="utf-8"))
    errors = 0
    for p in sorted((s.content_dir / "learning").glob("*.json")):
        deck = json.loads(p.read_text(encoding="utf-8"))
        ids = set()
        for it in deck.get("items", []):
            try:
                jsonschema.validate(it, schema)
            except jsonschema.ValidationError as exc:
                print(f"{p.name}:{it.get('id')}: {exc.message}")
                errors += 1
            if it.get("id") in ids:
                print(f"{p.name}: id duplicado {it['id']}")
                errors += 1
            ids.add(it.get("id"))
            if it.get("type") == "multiple_choice" and not (0 <= int(it.get("answer", -1)) < len(it.get("options", []))):
                print(f"{p.name}:{it.get('id')}: resposta fora das opções")
                errors += 1
        print(f"{p.name}: {len(deck.get('items', []))} itens verificados")
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cyberradar", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["update", "process", "notify", "report", "announce", "learning-draft", "validate", "build", "serve", "status"])
    ap.add_argument("--dry-run", action="store_true", help="notify: só imprime as mensagens")
    ap.add_argument("--no-search", action="store_true", help="build: não gera o índice Pagefind")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # não logar URLs com tokens
    _load_dotenv()
    s = config.load()

    if args.command == "status":
        from .ai.client import AIClient
        from .notify import channels
        ai = AIClient(HttpClient(), s.section("ai"), {})
        print("Provedores de IA ativos:", ", ".join(p.name for p in ai.providers) or "nenhum (usará templates)")
        print("Canais de alerta ativos:", ", ".join(channels()) or "nenhum")
        print("NVD API key:", "sim" if config.env("NVD_API_KEY") else "não (limite menor)")
        print("URL pública:", s.public_base or "(defina SITE_URL)")
        return 0

    if args.command == "validate":
        return _validate(s)

    if args.command == "serve":
        import functools
        import http.server
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(s.out_dir))
        print(f"Servindo {s.out_dir} em http://localhost:8000{s.base_path}/  (Ctrl+C para sair)")
        if s.base_path:
            print("Aviso: SITE_BASE_PATH definido; para testar localmente use SITE_BASE_PATH= (vazio) no build.")
        http.server.ThreadingHTTPServer(("127.0.0.1", 8000), handler).serve_forever()
        return 0

    if args.command == "build":
        from .site.build import build
        out = build(s)
        if not args.no_search:
            _search_index(out)
        print(f"Site gerado em {out}")
        return 0

    http = HttpClient()
    try:
        from .pipeline.run import enriched_records, run_all
        from .storage import Store
        if args.command in ("update", "process"):
            run_all(s, http, skip_collect=args.command == "process")
            return 0
        store = Store(s.data_dir)
        records = enriched_records(store, s)
        if args.command == "notify":
            from . import notify
            state = store.load_state()
            n = notify.run(s, http, records, state, dry_run=args.dry_run)
            if not args.dry_run:
                store.save_state(state)
            print(f"{n} alerta(s) {'listados' if args.dry_run else 'enviados'}")
            return 0
        if args.command == "report":
            from .report import build_weekly
            path = build_weekly(s, records, store)
            print(f"Boletim gerado: {path}")
            return 0
        if args.command == "learning-draft":
            from .ai.client import AIClient
            from .learning import draft_weekly
            state = store.load_state()
            path = draft_weekly(s, records, AIClient(http, s.section("ai"), state))
            store.save_state(state)
            print(f"Rascunho gerado: {path}" if path else "Nenhum rascunho gerado")
            return 0
        if args.command == "announce":
            from . import notify
            from .report import week_slug
            url = f"{s.public_base}/relatorios/{week_slug()}/"
            sent = notify.send(http, {"text": f"📰 Boletim semanal {week_slug()} — o que corrigir primeiro.\n{url}",
                                      "short": f"📰 Boletim semanal {week_slug()}: {url}", "url": url, "title": "Boletim"})
            print("anunciado em:", ", ".join(sent) or "nenhum canal")
            return 0
    finally:
        http.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
