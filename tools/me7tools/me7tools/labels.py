"""Build a label TSV for ME7ImportLabelsScript (addr, name, size, comment).

Sources: an ASAP2DAM DAMOS export (.dam, code page 850) for maps (/SPZ) and RAM
measurements (/UMP), a TunerPro XDF for flash maps and constants, and ME7Logger
.ecu files for RAM variables. All DAMOS or XDF entries are kept; .ecu files only
add names not seen yet. With --dam, maps.tsv and ram.tsv are written too.
"""
from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

from me7tools.maps import parse_damos, parse_xdf, xdf_name, xdf_z


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


def _xml_text(el: ET.Element, path: str) -> str:
    return " ".join((el.findtext(path) or "").split())


def _embedded_bytes(ed: ET.Element, count: int | None = None) -> tuple[int, int]:
    """File offset and byte length of an XDF EMBEDDEDDATA block."""
    width = int(ed.get("mmedelementsizebits", "8")) // 8
    if ed.get("mmedrowcount") or ed.get("mmedcolcount"):
        n = int(ed.get("mmedrowcount", "1")) * int(ed.get("mmedcolcount", "1"))
    else:
        n = count or 1
    return int(ed.get("mmedaddress", "0"), 16), width * n


def _xdf_comment(el: ET.Element, nbytes: int, desc: str = "") -> str:
    unit = _xml_text(el, "units")
    math = el.find("MATH")
    equation = " ".join((math.get("equation") or "").split()) if math is not None else ""
    parts = [p for p in (desc or _xml_text(el, "description"), f"[{unit}]" if unit else "", equation) if p]
    if nbytes > 2:
        parts.append(f"{nbytes} bytes")
    return " ".join(parts)


def xdf_labels(text: str, base: int = 0x800000) -> list[Label]:
    """Flash maps and constants from a TunerPro XDF.

    ``mmedaddress`` is a file offset. Labels use ``base`` (the ME7 flash base) plus
    the XDF header ``baseoffset``. The value block keeps the map name. An axis with
    its own address is ``name_x`` or ``name_y``. A repeated name is dropped, and a
    file offset of 0 is skipped. Size is 1 or 2 for a byte or word, and 0 otherwise,
    matching the label importer.
    """
    origin = base + int(ET.fromstring(text).findtext("XDFHEADER/baseoffset") or "0", 0)
    out: list[Label] = []
    known: set[str] = set()

    def add(name: str, ed: ET.Element, described: ET.Element, count: int | None = None, desc: str = "") -> None:
        key = name.lower()
        if not name or key in known or not ed.get("mmedaddress"):
            return
        off, nbytes = _embedded_bytes(ed, count)
        if off == 0:
            return
        known.add(key)
        out.append(Label(origin + off, name, nbytes if nbytes in (1, 2) else 0,
                         _xdf_comment(described, nbytes, desc)))

    for el in parse_xdf(text):
        name = xdf_name(el)
        desc = _xml_text(el, "description")
        z = xdf_z(el)
        zed = z.find("EMBEDDEDDATA") if z is not None else None
        if zed is not None:
            add(name, zed, z, desc=desc)
        if el.tag != "XDFTABLE":
            continue
        zaddr = zed.get("mmedaddress") if zed is not None else None
        for axis in ("x", "y"):
            node = el.find(f"XDFAXIS[@id='{axis}']")
            ed = node.find("EMBEDDEDDATA") if node is not None else None
            if ed is None or ed.get("mmedaddress") in (None, zaddr):
                continue
            count = int(node.findtext("indexcount") or "1")
            add(f"{name}_{axis}", ed, node, count, desc)
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
        desc = " ".join(m[5].split())
        out.append(Label(int(m[2], 16), m[1], 0 if mask else int(m[3]),
                         f"{desc}{note} ({source})", mask != 0))
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
            cells = []
            for c in cols:
                text = f"0x{r[c]:06X}" if c == "addr" else str(r[c])
                cells.append(" ".join(text.split()))
            f.write("\t".join(cells) + "\n")


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin1")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Build labels.tsv from a DAMOS export, a TunerPro XDF, and/or ME7Logger .ecu files")
    p.add_argument("--dam", type=Path, help="ASAP2DAM .dam export (code page 850)")
    p.add_argument("--xdf", type=Path, help="TunerPro XDF (flash maps and constants)")
    p.add_argument("--ecu", type=Path, nargs="*", default=[], help="ME7Logger .ecu files")
    p.add_argument("-o", "--out", type=Path, required=True, help="output directory")
    a = p.parse_args(argv)
    if bool(a.dam) and bool(a.xdf):
        p.error("give one of --dam or --xdf")
    if not a.dam and not a.xdf and not a.ecu:
        p.error("need --dam, --xdf, and/or --ecu")
    a.out.mkdir(parents=True, exist_ok=True)
    base, fill = [], []
    if a.xdf:
        base = xdf_labels(read_text(a.xdf))
        print(f"{a.xdf.name}: {len(base)} labels")
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
