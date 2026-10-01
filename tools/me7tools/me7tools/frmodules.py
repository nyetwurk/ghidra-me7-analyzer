"""Map variables and parameters to their FR module from the ABK (Abkuerzungen) tables.

Writes a TSV (name, module, kind) for ME7NameFunctionsScript. A parameter lists every
ABK section that names it (comma-separated); a variable gets the weighted majority of
its Quelle column, AUS/LOK counting double. Input is `pdftotext -layout` output of a
Bosch Funktionsrahmen.
"""
from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path

SECTION = re.compile(r"^\s*(ABK|FB|APP) ([A-Z][A-Z0-9_]*) [0-9.]+ ")
VAR = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s+([A-Z][A-Z0-9_]*)\s+(AUS|EIN|LOK)\s")
PAR = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s+.*?\b(KF|KL|FW|KLA|FKL|FKF|SYS|KWT|STX|STY)\b")


def parse_fr(text: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Parameter -> modules, variable (lower case) -> module."""
    params: dict[str, list[str]] = defaultdict(list)
    votes: dict[str, Counter] = defaultdict(Counter)
    module, part = None, None
    for line in text.splitlines():
        m = SECTION.match(line)
        if m:
            module, part = (m[2], None) if m[1] == "ABK" else (None, None)
            continue
        if module is None:
            continue
        s = line.strip()
        if s.startswith("Parameter "):
            part = "par"
        elif s.startswith("Variable "):
            part = "var"
        elif part == "var" and (m := VAR.match(line)):
            votes[m[1].lower()][m[2]] += 1 if m[3] == "EIN" else 2
        elif part == "par" and (m := PAR.match(line)) and module not in params[m[1]]:
            params[m[1]].append(module)
    return dict(params), {v: c.most_common(1)[0][0] for v, c in votes.items()}


def write_modules(path: Path, params: dict[str, list[str]], variables: dict[str, str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write("name\tmodule\tkind\n")
        for name in sorted(params):
            f.write(f"{name}\t{','.join(params[name])}\tparam\n")
        for name in sorted(variables):
            f.write(f"{name}\t{variables[name]}\tvar\n")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Build modules.tsv from Funktionsrahmen ABK tables")
    p.add_argument("fr", type=Path, help="FR text (pdftotext -layout)")
    p.add_argument("-o", "--out", type=Path, required=True, help="output TSV")
    a = p.parse_args(argv)
    params, variables = parse_fr(a.fr.read_text(encoding="utf-8", errors="replace"))
    write_modules(a.out, params, variables)
    print(f"{len(params)} params, {len(variables)} vars -> {a.out}")


if __name__ == "__main__":
    main()
