"""Needles from patterns/me7-core.yaml (field reference in its header)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

PATTERNS = Path(__file__).resolve().parents[3] / "patterns" / "me7-core.yaml"


@dataclass
class Needle:
    name: str
    regex: re.Pattern[bytes]
    back_up: int = 0
    back_up_max: int | None = None
    ref_offset: int | None = None
    unique: bool = False
    function: bool = False
    entry_after: tuple[bytes, ...] = ()

    def find(self, data: bytes) -> list[int]:
        """Word-aligned hits only (C166 instructions are word aligned)."""
        return [m.start() for m in self.regex.finditer(data) if m.start() % 2 == 0]

    def label(self, data: bytes, hit: int) -> int:
        """Label for a hit; with a back_up range, the closest entry to the hit in the range."""
        if self.back_up_max is not None:
            for label in range(hit - self.back_up, hit - self.back_up_max - 1, -2):
                if self.entry_ok(data, label):
                    return label
        return hit - self.back_up

    def entry_ok(self, data: bytes, label: int) -> bool:
        if not self.entry_after:
            return True
        return any(label >= len(e) and data[label - len(e) : label] == e for e in self.entry_after)


def _byte_regex(value: int, mask: int) -> bytes:
    ok = [v for v in range(256) if v & mask == value & mask]
    if len(ok) == 1:
        return re.escape(bytes(ok))
    return b"." if len(ok) == 256 else b"[" + b"".join(re.escape(bytes([v])) for v in ok) + b"]"


def compile_needle(needle_hex: str, mask_hex: str | None = None) -> re.Pattern[bytes]:
    """Overlapping-match regex for hex with "??" wildcards and an optional per-byte mask."""
    toks = re.findall(r"\S\S", re.sub(r"\s+", "", needle_hex))
    masks = bytes.fromhex(mask_hex) if mask_hex else b"\xff" * len(toks)
    if len(masks) != len(toks):
        raise ValueError(f"mask_hex length {len(masks)} != needle length {len(toks)}")
    pat = b"".join(
        b"." if t == "??" else _byte_regex(int(t, 16), m) for t, m in zip(toks, masks)
    )
    return re.compile(b"(?=" + pat + b")", re.S)


def _back_up(f: dict) -> tuple[int, int | None]:
    v = f.get("back_up", 0)
    if isinstance(v, int):
        return v, None
    lo, hi = v
    if lo > hi or (lo - hi) % 2 or not f.get("entry_after"):
        raise ValueError(f"{f['name']}: back_up range needs min <= max, even span, entry_after")
    return lo, hi


def _needle(f: dict) -> Needle:
    back_up, back_up_max = _back_up(f)
    return Needle(
        name=f["name"],
        regex=compile_needle(f["needle_hex"], f.get("mask_hex")),
        back_up=back_up,
        back_up_max=back_up_max,
        ref_offset=f.get("ref_offset"),
        unique=f.get("unique", False),
        function=f.get("function", False),
        entry_after=tuple(bytes.fromhex(e) for e in f.get("entry_after", [])),
    )


def load_needles(path: Path = PATTERNS) -> list[Needle]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [_needle(f) for f in doc["functions"]]
