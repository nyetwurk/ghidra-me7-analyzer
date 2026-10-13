"""Find a moved copy of a call by masking its immediates."""

from __future__ import annotations

import argparse
from pathlib import Path


def word_op(b0: int, b1: int) -> bool:
    """The word after E6 Fx, F2 Fx, C2 Fx, F3 F8, F7 F8, F6 F4, and 42 F4."""
    if b0 in (0xE6, 0xF2, 0xC2) and b1 & 0xF0 == 0xF0:
        return True
    return (b0, b1) in {(0xF3, 0xF8), (0xF7, 0xF8), (0xF6, 0xF4), (0x42, 0xF4)}


def mask_immediates(window: bytes) -> tuple[bytes, bytes]:
    mask = bytearray(b"\xff" * len(window))
    i = 0
    while i + 3 < len(window):
        if word_op(window[i], window[i + 1]):
            mask[i + 2] = mask[i + 3] = 0
            i += 4
        else:
            i += 1
    return window, bytes(mask)


def parse_pat(text: str) -> tuple[bytes, bytes]:
    hex_ = text.replace(" ", "").replace("?", "X").upper()
    if not hex_ or len(hex_) % 2:
        raise ValueError("pattern length")
    pat = bytearray()
    mask = bytearray()
    for i in range(0, len(hex_), 2):
        pair = hex_[i : i + 2]
        byte = 0
        bits = 0
        for shift, nibble in ((4, pair[0]), (0, pair[1])):
            if nibble == "X":
                continue
            if nibble not in "0123456789ABCDEF":
                raise ValueError(f"pattern byte {pair}")
            byte |= int(nibble, 16) << shift
            bits |= 0xF << shift
        pat.append(byte)
        mask.append(bits)
    return bytes(pat), bytes(mask)


def pattern_text(pat: bytes, mask: bytes) -> str:
    out = []
    for b, m in zip(pat, mask):
        hi = "X" if m & 0xF0 == 0 else f"{b >> 4:X}"
        lo = "X" if m & 0x0F == 0 else f"{b & 0x0F:X}"
        out.append(hi + lo)
    return "".join(out)


def find(img: bytes, pat: bytes, mask: bytes, limit: int) -> list[int]:
    n = len(pat)
    hits = []
    for off in range(0, len(img) - n + 1, 2):
        if all((img[off + j] & mask[j]) == (pat[j] & mask[j]) for j in range(n)):
            hits.append(off)
            if len(hits) >= limit:
                break
    return hits


def bins_of(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(p for p in path.glob("*.bin") if p.is_file())
    return [path]


def search(pat: bytes, mask: bytes, targets: list[Path], limit: int) -> None:
    print(pattern_text(pat, mask))
    for path in targets:
        img = path.read_bytes()
        hits = find(img, pat, mask, limit)
        addrs = " ".join(f"0x{0x800000 + h:X}" for h in hits)
        more = "+" if len(hits) >= limit else ""
        print(f"{path.stem} {len(hits)}{more} {addrs}".rstrip())
        if len(hits) == 1:
            h = hits[0]
            print(f"  {img[h:h + len(pat)].hex()}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Find a call after its immediates change")
    p.add_argument("--pat", help="hex pattern; XX is one wildcard byte")
    p.add_argument("--window", nargs=3, metavar=("BIN", "ADDR", "LEN"), help="donor image, CPU address, length")
    p.add_argument("--limit", type=int, default=4)
    p.add_argument("target", nargs="+", type=Path, help="bin or a directory of bins")
    args = p.parse_args(argv)
    if (args.pat is None) == (args.window is None):
        p.error("pass --pat or --window")
    if args.pat is not None:
        pat, mask = parse_pat(args.pat)
    else:
        donor, addr_s, len_s = args.window
        addr = int(addr_s, 16)
        length = int(len_s, 0)
        off = addr - 0x800000
        img = Path(donor).read_bytes()
        if off < 0 or off + length > len(img):
            p.error("window is outside the donor")
        pat, mask = mask_immediates(img[off : off + length])
    targets = [b for path in args.target for b in bins_of(path)]
    search(pat, mask, targets, args.limit)


if __name__ == "__main__":
    main()
