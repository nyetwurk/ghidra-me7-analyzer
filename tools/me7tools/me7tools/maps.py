"""Decode calibration maps from a flash image (me7map).

Definitions come from an ASAP2DAM DAMOS export (.dam, code page 850: exact Bosch
conversions, every map) or a TunerPro XDF (any image with a definition file; equation
coefficients are often rounded). Output is in physical units, one table per map; with
two images, the second table shows the differences.
"""
from __future__ import annotations

import argparse
import math
import re
import struct
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Axis:
    name: str
    unit: str
    values: list[float]


@dataclass
class Table:
    name: str
    desc: str
    unit: str
    addr: int  # file offset of the first value
    values: list[list[float]]  # rows x cols
    rows: Axis | None = None
    cols: Axis | None = None
    step: float = 1.0  # physical value of one raw count, for formatting
    text: str | None = None


def read_int(img: bytes, off: int, width: int, little: bool = True) -> int:
    """Unsigned or (negative width) signed integer of |width| bytes."""
    n = abs(width)
    return int.from_bytes(img[off:off + n], "little" if little else "big", signed=width < 0)


# DAMOS

REG = re.compile(r"^(\d+), /REG, ([^,]+), \{[^}]*\}, \d+, \d+, \{([^}]*)\}[^\n]*\n/REP, ([^;]+);", re.M)
SPZ = re.compile(
    r"^(\d+), /SPZ, ([^,]+), \{(.*?)\}, (\d+), \$([0-9A-F]+), \$([0-9A-F]+)[^\n]*\n"
    r"/SPW, ([^\n]+)\n/SPX, ([^\n]+)\n/SPY, ([^\n]+)\n/FKX, ([^\n]+)\n/FKY, ([^\n]+)", re.M | re.S)


@dataclass
class Conv:
    name: str
    unit: str
    rep: tuple[float, ...]

    def phys(self, raw: int) -> float:
        """Invert raw = (a*p + b) / (c*p + d)."""
        a, b, c, d = self.rep[:4]
        if a == b == c == d == 0:
            return float(raw)
        den = a - c * raw
        return (d * raw - b) / den if den else math.inf


NO_CONV = Conv("", "", (0, 0, 0, 0))


@dataclass
class DamMap:
    num: int
    name: str
    desc: str
    type: int
    ref: int  # first /SPZ address: the variant pointer table entry for _0_A/_1_A maps, else addr
    addr: int  # data address (the second /SPZ address)
    conv: int
    width: int
    x: tuple[int, int, int] = (0, 0, 0)  # conv, width, ref
    y: tuple[int, int, int] = (0, 0, 0)
    fkx: int = 0
    fky: int = 0
    xlim: tuple[float, float] = (0.0, 0.0)  # min/max, used by equidistant (width -4) axes
    ylim: tuple[float, float] = (0.0, 0.0)


@dataclass
class Damos:
    maps: dict[str, DamMap] = field(default_factory=dict)
    by_num: dict[int, DamMap] = field(default_factory=dict)
    convs: dict[int, Conv] = field(default_factory=dict)

    def conv(self, num: int) -> Conv:
        return self.convs.get(num, NO_CONV)


def parse_damos(text: str) -> Damos:
    d = Damos()
    for m in REG.finditer(text):
        rep = tuple(float(v) for v in m[4].split(","))
        d.convs[int(m[1])] = Conv(m[2], m[3], rep)
    for m in SPZ.finditer(text):
        spw, spx, spy = ([s.strip() for s in m[i].split(",")] for i in (7, 8, 9))
        dm = DamMap(int(m[1]), m[2], " ".join(m[3].split()), int(m[4]), int(m[5], 16), int(m[6], 16),
                    int(spw[0]), int(spw[1]),
                    (int(spx[0]), int(spx[1]), int(spx[4])), (int(spy[0]), int(spy[1]), int(spy[4])),
                    int(m[10].split(",")[0]), int(m[11].split(",")[0]),
                    (float(spx[2]), float(spx[3])), (float(spy[2]), float(spy[3])))
        d.maps[dm.name] = dm
        d.by_num[dm.num] = dm
    return d


def _step(conv: Conv) -> float:
    return abs(conv.phys(1) - conv.phys(0)) or 1.0


def decode_damos(d: Damos, name: str, img: bytes, base: int = 0x800000) -> Table:
    m = d.maps[name]
    conv = d.conv(m.conv)
    off = m.addr - base
    w = m.width

    def vals(o: int, n: int, width: int, c: Conv) -> list[float]:
        if not 0 <= n <= 1024 or o + n * abs(width) > len(img):
            raise ValueError(f"{name}: {n} values at 0x{o:X} do not fit")
        return [c.phys(read_int(img, o + i * abs(width), width)) for i in range(n)]

    def axis(spec: tuple[int, int, int], o: int, n: int) -> tuple[Axis, int]:
        c = d.conv(spec[0])
        if abs(o) % 2 and abs(spec[1]) == 2:
            o += 1
        return Axis(c.name, c.unit, vals(o, n, spec[1], c)), o + n * abs(spec[1])

    def shared(spec: tuple[int, int, int]) -> Axis:
        a = d.by_num[spec[2]]
        c = d.conv(a.x[0])
        o = a.addr - base
        n = read_int(img, o, abs(a.x[1]))
        return Axis(a.name, c.unit, vals(o + abs(a.x[1]), n, a.x[1], c))

    def linear(spec: tuple[int, int, int], n: int, lo: float, hi: float) -> Axis:
        c = d.conv(spec[0])
        return Axis(c.name, c.unit, [lo + (hi - lo) * i / max(n - 1, 1) for i in range(n)])

    t = Table(m.name, m.desc, conv.unit, off, [], step=_step(conv))
    if m.type == 1:
        t.values = [[conv.phys(read_int(img, off, w))]]
    elif m.type == 12:
        t.text = img[off:off + abs(w)].decode("latin1")
    elif m.type == 13:
        n, r = m.fkx, max(m.fky, 1)
        t.values = [vals(off + i * n * abs(w), n, w, conv) for i in range(r)]
    elif m.type == 6:
        n = read_int(img, off, abs(m.x[1]))
        c = d.conv(m.x[0])
        t.unit, t.step = c.unit, _step(c)
        t.addr = off + abs(m.x[1])
        t.values = [vals(t.addr, n, m.x[1], c)]
    elif m.type == 2:
        n = read_int(img, off, abs(m.x[1]))
        t.cols, o = axis(m.x, off + abs(m.x[1]), n)
        if abs(o) % 2 and abs(w) == 2:
            o += 1
        t.values = [vals(o, n, w, conv)]
        t.addr = o
    elif m.type == 7:
        t.cols = shared(m.x)
        t.values = [vals(off, len(t.cols.values), w, conv)]
    elif m.type == 3:
        cw = 2 if abs(m.x[1]) == 2 and abs(m.y[1]) == 2 else 1
        nx, ny = read_int(img, off, cw), read_int(img, off + cw, cw)
        t.rows, o = axis(m.x, off + 2 * cw, nx)
        t.cols, o = axis(m.y, o, ny)
        if o % 2 and abs(w) == 2:
            o += 1
        t.addr = o
        t.values = [vals(o + r * ny * abs(w), ny, w, conv) for r in range(nx)]
    elif m.type == 8:
        t.rows, t.cols = shared(m.x), shared(m.y)
        ny = len(t.cols.values)
        t.values = [vals(off + r * ny * abs(w), ny, w, conv) for r in range(len(t.rows.values))]
    elif m.type in (4, 5):
        if m.type == 4:
            t.cols = linear(m.x, m.fkx, *m.xlim)
            t.values = [vals(off, m.fkx, w, conv)]
        else:
            t.rows = linear(m.x, m.fkx, *m.xlim)
            t.cols = linear(m.y, m.fky, *m.ylim)
            t.values = [vals(off + r * m.fky * abs(w), m.fky, w, conv) for r in range(m.fkx)]
    else:
        raise ValueError(f"{name}: DAMOS type {m.type} not supported")
    return t


def load_damos(path: Path) -> Damos:
    return parse_damos(path.read_text(encoding="cp850"))


# XDF

def _xdf_eval(eq: str, x: float) -> float:
    try:
        return float(eval(eq, {"__builtins__": {}}, {"X": x}))
    except ZeroDivisionError:
        return math.inf


def _xdf_read(img: bytes, ed: ET.Element, n: int) -> list[int]:
    off = int(ed.get("mmedaddress", "0"), 16)
    bits = int(ed.get("mmedelementsizebits", "8"))
    flags = int(ed.get("mmedtypeflags", "0"), 16)
    width = bits // 8 * (-1 if flags & 1 else 1)
    stride = int(ed.get("mmedmajorstridebits", "0")) // 8 or abs(width)
    return [read_int(img, off + i * stride, width, bool(flags & 2)) for i in range(n)]


def _xdf_axis(img: bytes, ax: ET.Element) -> Axis | None:
    n = int(ax.findtext("indexcount", "1"))
    eq = ax.find("MATH").get("equation", "X") if ax.find("MATH") is not None else "X"
    ed = ax.find("EMBEDDEDDATA")
    if ed is not None and ed.get("mmedaddress"):
        raw = _xdf_read(img, ed, n)
        vals = [_xdf_eval(eq, r) for r in raw]
    else:
        labels = {int(lb.get("index", "0")): lb.get("value", "") for lb in ax.findall("LABEL")}
        vals = [float(labels[i]) if labels.get(i, "").replace(".", "", 1).lstrip("-").isdigit() else i
                for i in range(n)]
    return Axis("", ax.findtext("units", ""), vals) if n > 1 else None


def parse_xdf(text: str) -> list[ET.Element]:
    root = ET.fromstring(text)
    return root.findall("XDFTABLE") + root.findall("XDFCONSTANT")


def decode_xdf(el: ET.Element, img: bytes) -> Table:
    title = el.findtext("title", "")
    desc = el.findtext("description", "")
    z = el.find("XDFAXIS[@id='z']") if el.tag == "XDFTABLE" else el
    ed = z.find("EMBEDDEDDATA")
    eq = z.find("MATH").get("equation", "X") if z.find("MATH") is not None else "X"
    rows = int(ed.get("mmedrowcount", "1"))
    cols = int(ed.get("mmedcolcount", "1"))
    raw = _xdf_read(img, ed, rows * cols)
    t = Table(title, desc, z.findtext("units", ""), int(ed.get("mmedaddress", "0"), 16),
              [[_xdf_eval(eq, raw[r * cols + c]) for c in range(cols)] for r in range(rows)],
              step=abs(_xdf_eval(eq, 1) - _xdf_eval(eq, 0)) or 1.0)
    if el.tag == "XDFTABLE":
        t.cols = _xdf_axis(img, el.find("XDFAXIS[@id='x']"))
        t.rows = _xdf_axis(img, el.find("XDFAXIS[@id='y']"))
    return t


def xdf_name(el: ET.Element) -> str:
    return el.findtext("title", "").split(" ")[0]


# Output

def _decimals(step: float) -> int:
    return min(max(math.ceil(-math.log10(step)), 0), 3) if 0 < step < math.inf else 2


def format_table(t: Table, raw_diff: bool = False) -> str:
    if t.text is not None:
        return f"{t.name} @0x{t.addr:X}: {t.text!r}"
    d = _decimals(t.step)
    fmt = lambda v: f"{v:.{d}f}"  # noqa: E731
    head = f"{t.name} @0x{t.addr:X} [{t.unit}] {t.desc}".rstrip()
    lines = [head]
    if t.rows is None and t.cols is None and len(t.values) == 1 and len(t.values[0]) == 1:
        return f"{head}: {fmt(t.values[0][0])}"
    cells = [[fmt(v) for v in row] for row in t.values]
    rlab = [_fmt_axis(v) for v in t.rows.values] if t.rows else [""] * len(cells)
    clab = [_fmt_axis(v) for v in t.cols.values] if t.cols else []
    wid = max([len(c) for row in cells for c in row] + [len(c) for c in clab] + [1])
    rw = max([len(r) for r in rlab] + [1])
    if t.rows or t.cols:
        lines.append(f"  rows: {_axis_desc(t.rows)}  cols: {_axis_desc(t.cols)}")
    if clab:
        lines.append(" " * rw + " | " + " ".join(c.rjust(wid) for c in clab))
    for lab, row in zip(rlab, cells):
        lines.append(lab.rjust(rw) + " | " + " ".join(c.rjust(wid) for c in row))
    return "\n".join(lines)


def _fmt_axis(v: float) -> str:
    return f"{v:.0f}" if abs(v) >= 100 or v == int(v) else f"{v:.2f}".rstrip("0").rstrip(".")


def _axis_desc(a: Axis | None) -> str:
    return "-" if a is None else f"{a.name or 'axis'} [{a.unit}]".replace(" []", "")


def diff_table(a: Table, b: Table) -> Table:
    if len(a.values) != len(b.values) or any(len(x) != len(y) for x, y in zip(a.values, b.values)):
        raise ValueError(f"{a.name}: shapes differ")
    return Table(b.name, "(second image minus first)", b.unit, b.addr,
                 [[y - x for x, y in zip(ra, rb)] for ra, rb in zip(a.values, b.values)],
                 b.rows, b.cols, b.step)


# XDF check against DAMOS

def _close(x: float, y: float, step: float) -> bool:
    if math.isinf(x) or math.isinf(y):
        return x == y
    return abs(x - y) <= max(step / 2, 2e-3 * max(abs(x), abs(y)), 1e-9)


def _worst(xs: list[list[float]], ys: list[list[float]], step: float) -> tuple[int, int, float, float] | None:
    """First cell (row, col, xdf, damos) outside tolerance, or None."""
    for r, (rx, ry) in enumerate(zip(xs, ys)):
        for c, (x, y) in enumerate(zip(rx, ry)):
            if not _close(x, y, step):
                return r, c, x, y
    return None


def _shape(v: list[list[float]]) -> tuple[int, int]:
    return len(v), len(v[0]) if v else 0


def _transpose(v: list[list[float]]) -> list[list[float]]:
    return [list(r) for r in zip(*v)]


def _axis_vals(a: Axis | None) -> list[float] | None:
    return a.values if a is not None and len(a.values) > 1 else None


def check_table(x: Table, d: Table) -> list[str]:
    """Differences between an XDF table and the DAMOS decode of the same map."""
    out = []
    if x.addr != d.addr:
        out.append(f"address XDF 0x{x.addr:X} DAMOS 0x{d.addr:X}")
    xv, dv, xr, xc = x.values, d.values, x.rows, x.cols
    if _shape(xv) != _shape(dv) and _shape(xv) == _shape(dv)[::-1] and _shape(xv) != (1, 1):
        out.append(f"transposed (XDF {_shape(xv)[0]}x{_shape(xv)[1]})")
        xv, xr, xc = _transpose(xv), xc, xr
    if _shape(xv) != _shape(dv):
        if not (len(xv) == 1 and len(dv) == 1 or _shape(xv)[1] == 1 and _shape(dv)[0] == 1):
            out.append(f"shape XDF {_shape(x.values)[0]}x{_shape(x.values)[1]} DAMOS {_shape(dv)[0]}x{_shape(dv)[1]}")
            return out
        if _shape(xv)[1] == 1:
            xv, xr, xc = _transpose(xv), xc, xr
        if len(xv[0]) != len(dv[0]):
            out.append(f"size XDF {len(xv[0])} DAMOS {len(dv[0])}")
            return out
    w = _worst(xv, dv, d.step)
    if w:
        r, c, a, b = w
        k = _ratio(xv, dv, d.step)
        out.append(f"scaled x{k:g}" if k else
                   f"values differ at [{r},{c}]: XDF {a:g} DAMOS {b:g} [{x.unit or '-'} vs {d.unit or '-'}]")
    for label, xa, da in (("rows", xr, d.rows), ("cols", xc, d.cols)):
        av, bv = _axis_vals(xa), _axis_vals(da)
        if bv is None:
            continue
        if av is None:
            out.append(f"{label} axis missing in XDF")
        elif len(av) != len(bv):
            out.append(f"{label} axis XDF {len(av)} points DAMOS {len(bv)}")
        elif (w := _worst([av], [bv], abs(bv[-1] - bv[0]) / 1e4)):
            k = _ratio([av], [bv], abs(bv[-1] - bv[0]) / 1e4)
            out.append(f"{label} axis scaled x{k:g}" if k else
                       f"{label} axis differs at [{w[1]}]: XDF {w[2]:g} DAMOS {w[3]:g}")
    return out


SCALES = (2.0, 0.5)  # 5.12 bar boost sensor ("5120") XDFs double pressures and halve per-pressure gains


def _ratio(xs: list[list[float]], ys: list[list[float]], step: float) -> float | None:
    """A SCALES factor k with xdf == k * damos in every cell, or None."""
    for k in SCALES:
        if not _worst(xs, [[k * y for y in r] for r in ys], step * k):
            return k
    return None


def check_xdf(d: Damos, els: list[ET.Element], img: bytes, base: int = 0x800000) -> list[str]:
    """One line per XDF entry that differs from DAMOS or cannot be matched."""
    out = []
    for el in els:
        title = el.findtext("title", "")
        name = xdf_name(el)
        try:
            x = decode_xdf(el, img)
        except (ValueError, KeyError, AttributeError) as e:
            out.append(f"{title}: XDF decode failed: {e}")
            continue
        norm = re.sub("_+", "_", name)
        cands = [d.maps[name]] if name in d.maps else \
            [m for n, m in d.maps.items() if re.sub("_+", "_", n) == norm] or \
            [m for n, m in d.maps.items() if n.startswith(name + "_")] or \
            [d.maps[b] for b in [re.sub(r"_\d+_+A$", "", name)] if b != name and b in d.maps]
        if not cands:
            out.append(f"{title}: not in DAMOS")
            continue
        results = []
        for m in cands:
            if m.type == 12:
                results = []
                break
            try:
                results.append((m.name, check_table(x, decode_damos(d, m.name, img, base))))
            except ValueError as e:
                results.append((m.name, [f"DAMOS decode failed: {e}"]))
        if not results:
            continue
        best = min(results, key=lambda r: len(r[1]))
        if best[1]:
            label = title if best[0] == name else f"{title} ({best[0]})"
            out.extend(f"{label}: {p}" for p in best[1])
    return out


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="me7map", description=__doc__.splitlines()[0])
    p.add_argument("--dam", type=Path, help="DAMOS .dam export")
    p.add_argument("--xdf", type=Path, help="TunerPro XDF")
    p.add_argument("--check", action="store_true",
                   help="compare every XDF entry with DAMOS (needs --dam, --xdf and --bin)")
    p.add_argument("--bin", type=Path, action="append", default=[],
                   help="flash image (repeat once to compare two images)")
    p.add_argument("--base", type=lambda s: int(s, 0), default=0x800000,
                   help="address of file offset 0 for DAMOS (default 0x800000)")
    p.add_argument("-s", "--search", help="list maps whose name or description matches REGEX")
    p.add_argument("names", nargs="*", help="map names (DAMOS name, or first word of the XDF title)")
    a = p.parse_args(argv)

    if a.check:
        if not (a.dam and a.xdf and a.bin):
            p.error("--check needs --dam, --xdf and --bin")
        els = parse_xdf(a.xdf.read_text(encoding="latin1"))
        problems = check_xdf(load_damos(a.dam), els, a.bin[0].read_bytes(), a.base)
        scaled = [p for p in problems if "scaled x" in p]
        other = [p for p in problems if "scaled x" not in p]
        print("\n".join(other))
        if scaled:
            print("\n# scaled by a constant factor (e.g. 5120 boost sensor XDFs)\n" + "\n".join(scaled))
        bad = len({p.split(": ", 1)[0] for p in other})
        print(f"{len(els)} XDF entries, {bad} with differences, "
              f"{len({p.split(': ', 1)[0] for p in scaled})} scaled", file=sys.stderr)
        sys.exit(1 if other else 0)
    if bool(a.dam) == bool(a.xdf):
        p.error("give one of --dam or --xdf")
    if a.dam:
        d = load_damos(a.dam)
        entries = [(m.name, m.desc) for m in d.maps.values()]
    else:
        els = parse_xdf(a.xdf.read_text(encoding="latin1"))
        entries = [(el.findtext("title", ""), el.findtext("description", "")) for el in els]
    if a.search:
        rx = re.compile(a.search, re.I)
        for n, desc in entries:
            if rx.search(n) or rx.search(desc):
                print(f"{n}\t{desc}")
        if not a.names:
            return
    if not a.bin:
        p.error("--bin is required to decode maps")
    imgs = [b.read_bytes() for b in a.bin[:2]]
    status = 0
    for name in a.names:
        if a.dam:
            if name not in d.maps:
                print(f"{name}: not in DAMOS", file=sys.stderr)
                status = 1
                continue
            tables = [[decode_damos(d, name, img, a.base) for img in imgs]]
        else:
            hits = [el for el in els if xdf_name(el).upper() == name.upper()] or \
                [el for el in els if xdf_name(el).upper().startswith(name.upper() + "_")]
            if not hits:
                print(f"{name}: not in XDF", file=sys.stderr)
                status = 1
                continue
            tables = [[decode_xdf(el, img) for img in imgs] for el in hits]
        for ts in tables:
            print(format_table(ts[0]))
            if len(ts) == 2:
                print(format_table(diff_table(ts[0], ts[1])))
            print()
    sys.exit(status)


if __name__ == "__main__":
    main()
