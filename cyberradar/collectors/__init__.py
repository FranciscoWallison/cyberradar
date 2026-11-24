"""Coletores: cada módulo baixa uma fonte e devolve dados já parseados."""
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def find_cves(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in CVE_RE.findall(text or ""):
        seen[m.upper()] = None
    return list(seen)
