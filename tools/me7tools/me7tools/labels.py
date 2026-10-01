"""Build a label TSV for ME7ImportLabelsScript (addr, name, size, comment).

Sources: an ASAP2DAM DAMOS export (.dam, code page 850) for maps (/SPZ) and RAM
measurements (/UMP), and ME7Logger .ecu files for RAM variables. All DAMOS entries are
kept; .ecu files only add names not seen yet. With --dam, maps.tsv and ram.tsv are
written too.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from me7tools.maps import parse_damos


@dataclass
class Label:
    addr: int
    name: str
    size: int
    comment: str
    bit: bool = False


UMP = re.compile(
    r"^/UMP, \{\}, ([^,]+), \{(.*?)\}, \$([0-9A-F]+), \d+, \d+, ([^,]+), \d+, \$([0-9A-F]+)", re.M | re.S)
ECU = re.compile(
    r";?\s*(\w+)\s*,\s*\{[^}]*\}\s*,\s*0x([0-9A-Fa-f]+)\s*,\s*(\d)\s*,\s*0x([0-9A-Fa-f]+)\s*,.*\{([^}]*)\}\s*$")


def parse_dam(text: str) -> tuple[list[dict], list[dict]]:
    """Maps (labeled at their first /SPZ address) and RAM measurements from DAMOS text."""
    d = parse_damos(text)
    maps = [dict(name=m.name, type=str(m.type), addr=m.ref, bytes=abs(m.width), fixed_len=str(m.fkx),
                 conv=d.conv(m.conv).name, unit=d.conv(m.conv).unit, desc=m.desc) for m in d.maps.values()]
    ram = [dict(name=m[1], addr=int(m[3], 16), conv=m[4], mask=int(m[5], 16), desc=" ".join(m[2].split()))
           for m in UMP.finditer(text)]
    return maps, ram


def dam_labels(maps: list[dict], ram: list[dict]) -> list[Label]:
    out = [Label(r["addr"], r["name"], r["bytes"] if r["type"] == "1" else 0,
                 f"{r['desc']} [{r['unit']}] {r['conv']}") for r in maps]
    for r in ram:
        bit = r["mask"] not in (0xFF, 0xFFFF)
        size = 0 if bit else (1 if r["mask"] == 0xFF else 2)
        note = f" mask 0x{r['mask']:X}" if bit else ""
        out.append(Label(r["addr"], r["name"], size, f"{r['desc']}{note} {r['conv']}", bit))
    return out


def ecu_labels(text: str, source: str) -> list[Label]:
    """RAM variables from an ME7Logger .ecu file (commented-out lines included)."""
    out = []
    for line in text.splitlines():
        m = ECU.match(line)
        if not m:
            continue
        mask = int(m[4], 16)
        note = f" mask 0x{mask:X}" if mask else ""
        out.append(Label(int(m[2], 16), m[1], 0 if mask else int(m[3]),
                         f"{m[5].strip()}{note} ({source})", mask != 0))
    return out


def merge(base: list[Label], *fill: list[Label]) -> list[Label]:
    """All of base, plus fill labels whose name (case-insensitive) is not known yet;
    sorted by address with bit flags last."""
    known = {lb.name.lower() for lb in base}
    out = list(base)
    for labels in fill:
        for lb in labels:
            if lb.name.lower() not in known:
                known.add(lb.name.lower())
                out.append(lb)
    return sorted(out, key=lambda lb: (lb.addr, lb.bit))


def write_tsv(path: Path, cols: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join(f"0x{r[c]:06X}" if c == "addr" else str(r[c]) for c in cols) + "\n")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Build labels.tsv from a DAMOS export and/or ME7Logger .ecu files")
    p.add_argument("--dam", type=Path, help="ASAP2DAM .dam export (code page 850)")
    p.add_argument("--ecu", type=Path, nargs="*", default=[], help="ME7Logger .ecu files")
    p.add_argument("-o", "--out", type=Path, required=True, help="output directory")
    a = p.parse_args(argv)
    if not a.dam and not a.ecu:
        p.error("need --dam and/or --ecu")
    a.out.mkdir(parents=True, exist_ok=True)
    base, fill = [], []
    if a.dam:
        maps, ram = parse_dam(a.dam.read_text(encoding="cp850"))
        write_tsv(a.out / "maps.tsv", ["name", "type", "addr", "bytes", "fixed_len", "conv", "unit", "desc"],
                  sorted(maps, key=lambda r: r["name"]))
        write_tsv(a.out / "ram.tsv", ["name", "addr", "conv", "mask", "desc"], sorted(ram, key=lambda r: r["name"]))
        base = dam_labels(maps, ram)
        print(f"{a.dam.name}: {len(maps)} maps, {len(ram)} ram")
    for e in sorted(a.ecu):
        fill.append(ecu_labels(e.read_text(encoding="latin1"), e.name))
    labels = merge(base, *fill)
    write_tsv(a.out / "labels.tsv", ["addr", "name", "size", "comment"], [asdict(lb) for lb in labels])
    print(f"{len(labels)} labels -> {a.out / 'labels.tsv'}")


if __name__ == "__main__":
    main()
