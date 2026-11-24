"""Persistência em arquivos JSON versionados no git.

Layout:
  data/vulns/<ano>/<ID>.json   registro normalizado (sem campos voláteis)
  data/epss.json               {cve: {score, percentile, date}} só para CVEs rastreadas
  data/news/<AAAA-MM>.json     lista de notícias do mês
  data/state.json              cursores, itens notificados, uso de IA
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

VOLATILE = {"epss", "kev", "priority", "signals"}
DERIVED_EXPLOITATION = {"activeExploitation", "publicTool"}
ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3})$")


def now_utc() -> datetime:
    """Hora atual em UTC. CYBERRADAR_NOW (ISO 8601) fixa o relógio — usado nos testes."""
    fixed = os.environ.get("CYBERRADAR_NOW")
    if fixed:
        dt = datetime.fromisoformat(fixed.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def read_json(path: Path, default: Any) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_json(path: Path, data: Any, *, compact: bool = False) -> bool:
    """Grava somente se o conteúdo mudou (evita commits e churn desnecessários)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, sort_keys=True,
                      indent=None if compact else 1, separators=(",", ":") if compact else None)
    text += "\n"
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return True


class Store:
    def __init__(self, data_dir: Path):
        self.dir = data_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    # ---- estado -------------------------------------------------------------
    @property
    def state_path(self) -> Path:
        return self.dir / "state.json"

    def load_state(self) -> dict[str, Any]:
        st = read_json(self.state_path, {})
        st.setdefault("cursors", {})
        st.setdefault("notified", [])
        st.setdefault("ai_usage", {})
        st.setdefault("kev_seen", [])
        st.setdefault("runs", [])
        return st

    def save_state(self, st: dict[str, Any]) -> None:
        st["notified"] = st["notified"][-5000:]
        st["runs"] = st["runs"][-50:]
        write_json(self.state_path, st)

    # ---- vulnerabilidades ---------------------------------------------------
    def vuln_path(self, vid: str) -> Path:
        if not ID_RE.match(vid):
            raise ValueError(f"id inválido: {vid!r}")
        year = vid.split("-")[1] if vid.startswith("CVE-") else "ghsa"
        return self.dir / "vulns" / year / f"{vid}.json"

    def get_vuln(self, vid: str) -> dict[str, Any] | None:
        return read_json(self.vuln_path(vid), None)

    def put_vuln(self, rec: dict[str, Any]) -> bool:
        """Grava só os campos estáveis; EPSS/KEV/prioridade são recalculados em memória
        (evita reescrever milhares de arquivos por dia quando o EPSS muda)."""
        stable = {k: v for k, v in rec.items() if k not in VOLATILE}
        if isinstance(stable.get("exploitation"), dict):
            stable["exploitation"] = {k: v for k, v in stable["exploitation"].items() if k not in DERIVED_EXPLOITATION}
        return write_json(self.vuln_path(rec["id"]), stable)

    def delete_vuln(self, vid: str) -> None:
        p = self.vuln_path(vid)
        if p.exists():
            p.unlink()

    def iter_vulns(self) -> Iterator[dict[str, Any]]:
        base = self.dir / "vulns"
        if not base.exists():
            return
        for p in sorted(base.rglob("*.json")):
            rec = read_json(p, None)
            if rec:
                yield rec

    # ---- EPSS ---------------------------------------------------------------
    def load_epss(self) -> dict[str, Any]:
        return read_json(self.dir / "epss.json", {})

    def save_epss(self, data: dict[str, Any]) -> None:
        write_json(self.dir / "epss.json", data, compact=True)

    # ---- KEV ----------------------------------------------------------------
    def load_kev(self) -> dict[str, Any]:
        return read_json(self.dir / "kev.json", {})

    def save_kev(self, data: dict[str, Any]) -> None:
        write_json(self.dir / "kev.json", data, compact=True)

    # ---- sinais de exploit/detecção (Nuclei, Metasploit) -------------------
    def load_exploits(self) -> dict[str, Any]:
        return read_json(self.dir / "exploits.json", {})

    def save_exploits(self, data: dict[str, Any]) -> None:
        write_json(self.dir / "exploits.json", data, compact=True)

    # ---- notícias -----------------------------------------------------------
    def news_path(self, month: str) -> Path:
        if not re.match(r"^\d{4}-\d{2}$", month):
            raise ValueError(month)
        return self.dir / "news" / f"{month}.json"

    def load_news_month(self, month: str) -> list[dict[str, Any]]:
        return read_json(self.news_path(month), [])

    def save_news_month(self, month: str, items: list[dict[str, Any]]) -> None:
        items = sorted(items, key=lambda x: x.get("published", ""), reverse=True)
        write_json(self.news_path(month), items)

    def iter_news(self) -> Iterator[dict[str, Any]]:
        base = self.dir / "news"
        if not base.exists():
            return
        for p in sorted(base.glob("*.json"), reverse=True):
            yield from read_json(p, [])
