"""Carrega config/settings.toml e aplica sobrescritas por variáveis de ambiente."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    raw: dict[str, Any]
    root: Path = ROOT
    data_dir: Path = field(default_factory=lambda: ROOT / "data")
    content_dir: Path = field(default_factory=lambda: ROOT / "content")
    out_dir: Path = field(default_factory=lambda: ROOT / "_site")

    def section(self, name: str) -> dict[str, Any]:
        return self.raw.get(name, {})

    @property
    def site_url(self) -> str:
        return os.environ.get("SITE_URL") or self.section("site").get("url", "")

    @property
    def base_path(self) -> str:
        bp = os.environ.get("SITE_BASE_PATH")
        if bp is None:
            bp = self.section("site").get("base_path", "")
        bp = bp.strip()
        if bp and not bp.startswith("/"):
            bp = "/" + bp
        return bp.rstrip("/")

    @property
    def public_base(self) -> str:
        return self.site_url.rstrip("/") + self.base_path


def load(path: Path | None = None) -> Settings:
    path = path or Path(os.environ.get("CYBERRADAR_CONFIG", ROOT / "config" / "settings.toml"))
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    s = Settings(raw=raw)
    if os.environ.get("CYBERRADAR_DATA_DIR"):
        s.data_dir = Path(os.environ["CYBERRADAR_DATA_DIR"])
    if os.environ.get("CYBERRADAR_OUT_DIR"):
        s.out_dir = Path(os.environ["CYBERRADAR_OUT_DIR"])
    if os.environ.get("CYBERRADAR_CONTENT_DIR"):
        s.content_dir = Path(os.environ["CYBERRADAR_CONTENT_DIR"])
    return s


def env(name: str) -> str | None:
    """Lê um segredo/variável; string vazia conta como ausente."""
    v = os.environ.get(name, "").strip()
    return v or None
