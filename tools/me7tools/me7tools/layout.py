"""ME7 memory layout discovery from a raw flash image (no Ghidra needed).

- DPP0-3 from contiguous ``MOV DPP0..DPP3,#imm`` blocks (``E6 0n lo hi`` x4).
- Flash offset of RAM-resident code from ``CALLS seg:off`` targets that land
  right after a ``RETS`` (``DB 00``) at a candidate offset.
"""

from __future__ import annotations

import re
import struct
from collections import Counter
from dataclasses import dataclass

RETS = b"\xdb\x00"
DPP_BLOCK = re.compile(rb"\xE6\x00(..)\xE6\x01(..)\xE6\x02(..)\xE6\x03(..)", re.S)


@dataclass
class SweepResult:
    seg: int
    offset: int
    matched: int
    targets: int
    runner_up: int
    seeds: list[int]

    @property
    def confident(self) -> bool:
        return self.matched >= 10 and self.matched >= 2 * self.runner_up


def find_dpp(data: bytes) -> tuple[tuple[int, ...], list[int]] | None:
    """Return (DPP0-3, file offsets) of the most common full block with DPP0 != 0.

    DPP0 = 0 blocks are the boot-time reset; the runtime value comes later.
    """
    blocks: dict[tuple[int, ...], list[int]] = {}
    for m in DPP_BLOCK.finditer(data):
        if m.start() % 2 == 0:
            vals = tuple(struct.unpack("<H", g)[0] for g in m.groups())
            blocks.setdefault(vals, []).append(m.start())
    if not blocks:
        return None
    return max(blocks.items(), key=lambda kv: (kv[0][0] != 0, len(kv[1])))


def sweep_copy_offset(data: bytes, seg: int = 0x38, size: int = 0x8000) -> SweepResult | None:
    """Find file offset k such that RAM (seg<<16)+t is a copy of file t+k."""
    calls = re.compile(rb"\xDA" + bytes([seg]) + rb"(..)", re.S)
    targets = sorted(
        {t for m in calls.finditer(data) if m.start() % 2 == 0
         if (t := struct.unpack("<H", m.group(1))[0]) < size}
    )
    rets = [m.start() + 2 for m in re.finditer(re.escape(RETS), data) if m.start() % 2 == 0]
    limit = len(data) - size
    counts = Counter(r - t for t in targets for r in rets if 0 <= r - t <= limit)
    if not counts:
        return None
    (k, n), *rest = counts.most_common(2)
    return SweepResult(
        seg=seg,
        offset=k,
        matched=n,
        targets=len(targets),
        runner_up=rest[0][1] if rest else 0,
        seeds=[t for t in targets if data[t + k - 2 : t + k] == RETS],
    )
