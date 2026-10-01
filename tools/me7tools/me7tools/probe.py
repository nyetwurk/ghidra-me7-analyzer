from __future__ import annotations

import argparse
from pathlib import Path

from me7tools.layout import find_dpp, sweep_copy_offset
from me7tools.patterns import load_needles


def probe(data: bytes) -> None:
    dpp = find_dpp(data)
    if dpp:
        vals = " ".join(f"DPP{i}=0x{v:04X}" for i, v in enumerate(dpp[0]))
        print(f"dpp: {vals} (file+{' '.join(f'0x{o:X}' for o in dpp[1])})")
    else:
        print("dpp: no full DPP0-3 init block found")

    sweep = sweep_copy_offset(data)
    if sweep:
        print(
            f"ram code 0x{sweep.seg:02X}xxxx = file xxxx+0x{sweep.offset:X}: "
            f"{sweep.matched}/{sweep.targets} CALLS targets after RETS, runner-up "
            f"{sweep.runner_up}{'' if sweep.confident else ' (low confidence)'}"
        )
    else:
        print("ram code: no CALLS 0x38 targets")

    for n in load_needles():
        hits = n.find(data)
        if not hits:
            print(f"  miss  {n.name}")
        elif n.unique and len(hits) > 1:
            print(f"  ambig {n.name}: {' '.join(f'0x{h:X}' for h in hits)}, expected 1")
        else:
            for h in hits:
                label = n.label(data, h)
                if not n.entry_ok(data, label):
                    print(f"  noent {n.name} @ 0x{label:X}: not after RETS/padding")
                    continue
                delta = "" if n.ref_offset is None else f" delta {label - n.ref_offset:+d}"
                print(f"  hit   {n.name} @ file+0x{label:X}{delta}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Probe an ME7 flash image")
    p.add_argument("bin", type=Path, help="raw flash dump")
    probe(p.parse_args(argv).bin.read_bytes())


if __name__ == "__main__":
    main()
