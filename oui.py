from __future__ import annotations

import re
from pathlib import Path

_LINE = re.compile(r"^(?P<oui>[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(?P<vendor>.+?)\s*$")


class OuiDb:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._map: dict[str, str] = {}
        self.loaded = False

    def load(self) -> bool:
        if not self.path.exists():
            return False
        self._map.clear()
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                m = _LINE.match(raw)
                if m:
                    self._map[m.group("oui").upper()] = m.group("vendor")
        self.loaded = bool(self._map)
        return self.loaded

    def lookup(self, mac: str) -> str:
        if not self.loaded:
            self.load()
        if not mac:
            return ""
        h = normalize_mac(mac)
        if len(h) < 6:
            return ""
        key = f"{h[0:2]}-{h[2:4]}-{h[4:6]}"
        return self._map.get(key, "")


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
