"""Drive analyzeHeadless for the ME7 project next to this checkout."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

DEFAULT_IMAGES = (
    "8D0907551M-0002",
    "8E0909518AK-0004",
    "06A906032NL",
    "4B0906018DQ",
    "4B0906018CH",
)

_INIT_KEEP = re.compile(
    r"ME7Setup|ME7ImportLabels|ME7NameFunctions|flash:|dpp:|kernel_ram:|"
    r"ERROR|Import succeeded|REPORT: Analysis succeeded"
)
_SCRIPT_STOP = re.compile(r"REPORT: Discarding changes|Script .* completed")


def die(message: str) -> NoReturn:
    raise SystemExit(f"me7ghidra: {message}")


def repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "ghidra-extension" / "ghidra_scripts").is_dir():
            return parent
    die("run from a ghidra-me7-analyzer checkout")


def is_ghidra(path: Path) -> bool:
    support = path / "support"
    return (support / "analyzeHeadless").is_file() or (support / "analyzeHeadless.bat").is_file()


def ghidra_candidates() -> list[Path]:
    roots = [Path("/usr/local"), Path("/opt"), Path.home()]
    found = [root / "ghidra" for root in roots]
    for root in roots:
        if root.is_dir():
            found.extend(sorted(root.glob("ghidra_*"), reverse=True))
    return found


def find_ghidra() -> Path:
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        path = Path(env)
        if is_ghidra(path):
            return path.resolve()
        die(f"GHIDRA_INSTALL_DIR has no support/analyzeHeadless: {path}")
    for candidate in ghidra_candidates():
        if is_ghidra(candidate):
            return candidate.resolve()
    die("Ghidra not found. Set GHIDRA_INSTALL_DIR to the install root.")


def headless_argv(install: Path, args: list[str]) -> list[str]:
    bat = install / "support" / "analyzeHeadless.bat"
    shell = install / "support" / "analyzeHeadless"
    if os.name == "nt" and bat.is_file():
        return ["cmd", "/c", str(bat), *args]
    if shell.is_file():
        return [str(shell), *args]
    if bat.is_file():
        return [str(bat), *args]
    die(f"no analyzeHeadless in {install}")


def project_dir(root: Path) -> Path:
    env = os.environ.get("ME7_PROJECT")
    if env:
        path = Path(env)
        if not path.is_dir():
            die(f"ME7_PROJECT is not a directory: {path}")
        return path.resolve()
    default = (root.parent / "ghidra-projects" / "ME7").resolve()
    if not default.is_dir():
        die("Ghidra project not found. Set ME7_PROJECT to the directory that contains headless/ and data/.")
    return default


def bins_dir(root: Path) -> Path:
    env = os.environ.get("ME7_BINS") or os.environ.get("ME7SUM_BINS")
    if env:
        path = Path(env)
        if not path.is_dir():
            die(f"ME7_BINS is not a directory: {path}")
        return path.resolve()
    default = (root.parent / "ME7Sum" / "bins").resolve()
    if not default.is_dir():
        die("firmware bins not found. Set ME7_BINS to the directory of ECU .bin files.")
    return default


def ecu_data_dir(data: Path, name: str) -> Path:
    exact = data / name
    if exact.is_dir():
        return exact
    part = re.sub(r"-\d+$", "", name)
    shared = data / part
    if part != name and shared.is_dir():
        return shared
    return exact


def program_name(name: str) -> str:
    return name if name.endswith(".bin") else name + ".bin"


def post_scripts(ecu: Path) -> list[str]:
    post: list[str] = []
    labels = ecu / "labels.tsv"
    if labels.is_file():
        post += ["-postScript", "ME7ImportLabelsScript.java", str(labels)]
    modules = ecu / "modules.tsv"
    if modules.is_file():
        post += ["-postScript", "ME7NameFunctionsScript.java", str(modules)]
    return post


def import_args(bin_path: Path, scripts: Path, post: list[str]) -> list[str]:
    return [
        "-import", str(bin_path), "-overwrite",
        "-loader", "BinaryLoader", "-loader-baseAddr", "0x800000",
        "-processor", "C166:LE:16:default", "-cspec", "tasking",
        "-scriptPath", str(scripts),
        "-preScript", "ME7SetupScript.java",
        *post,
    ]


def filter_init_line(line: str) -> str | None:
    if not _INIT_KEEP.search(line):
        return None
    line = re.sub(r"^\s*INFO\s+", "  ", line)
    return re.sub(r"\s+\((?:HeadlessAnalyzer|GhidraScript)\)\s*$", "", line)


def filter_script_output(lines: list[str], script: str) -> list[str]:
    keep = False
    out: list[str] = []
    marker = script + ">"
    for line in lines:
        if marker in line:
            keep = True
        if _SCRIPT_STOP.search(line):
            break
        if keep or "ERROR" in line:
            line = re.sub(r".*" + re.escape(script) + r"> ", "", line)
            line = re.sub(r" \(GhidraScript\)\s*$", "", line)
            out.append(line)
    return out


def filter_export_line(line: str) -> str | None:
    if not re.search(r"exported|ERROR", line):
        return None
    return re.sub(r"^.*ME7ExportGzf\.java> ", "", line)


def _run(argv: list[str]) -> tuple[int, list[str]]:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    text = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, text.splitlines()


def cmd_init(root: Path, images: list[str]) -> int:
    install = find_ghidra()
    project = project_dir(root)
    bins = bins_dir(root)
    scripts = root / "ghidra-extension" / "ghidra_scripts"
    data = project / "data"
    failed = 0
    for name in images or DEFAULT_IMAGES:
        bin_path = bins / f"{name}.bin"
        if not bin_path.is_file():
            print(f"me7ghidra: missing {bin_path}", file=sys.stderr)
            failed = 1
            continue
        log = project / "headless" / f"{name}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        print(f"importing {name} (log: {log})")
        argv = headless_argv(install, [
            str(project / "headless"), "ME7",
            *import_args(bin_path, scripts, post_scripts(ecu_data_dir(data, name))),
        ])
        code, lines = _run(argv)
        log.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")
        for line in lines:
            kept = filter_init_line(line)
            if kept is not None:
                print(kept)
        if code != 0:
            failed = code
    return failed


def cmd_run(root: Path, program: str, script: str, script_args: list[str]) -> int:
    install = find_ghidra()
    project = project_dir(root)
    scripts = root / "ghidra-extension" / "ghidra_scripts"
    code, lines = _run(headless_argv(install, [
        str(project / "headless"), "ME7",
        "-process", program_name(program), "-noanalysis", "-readOnly",
        "-scriptPath", str(scripts),
        "-postScript", script, *script_args,
    ]))
    for line in filter_script_output(lines, script):
        print(line)
    return code


def cmd_sync(root: Path) -> int:
    install = find_ghidra()
    project = project_dir(root)
    scripts = root / "ghidra-extension" / "ghidra_scripts"
    gzf = project / "headless" / "gzf"
    gzf.mkdir(parents=True, exist_ok=True)
    code, lines = _run(headless_argv(install, [
        str(project / "headless"), "ME7",
        "-process", "-noanalysis", "-readOnly",
        "-scriptPath", str(scripts),
        "-postScript", "ME7ExportGzf.java", str(gzf),
    ]))
    for line in lines:
        kept = filter_export_line(line)
        if kept is not None:
            print(kept)
    if code == 0:
        print(f"import into live/ from the GUI: File > Import {gzf}/*.gzf")
    return code


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Drive Ghidra headless for the ME7 project")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="import and analyze images into the headless project")
    init.add_argument("images", nargs="*", help="image names without .bin; default is the handoff set")

    run = sub.add_parser("run", help="run one script read-only against a headless program")
    run.add_argument("program", help="program name; .bin is appended when missing")
    run.add_argument("script", help="Ghidra script file name, for example ME7Decomp.java")
    run.add_argument("script_args", nargs=argparse.REMAINDER, help="arguments passed to the script")

    sub.add_parser("sync", help="export headless programs as GZFs for File > Import in the GUI")

    args = parser.parse_args(argv)
    root = repo_root()
    if args.cmd == "init":
        code = cmd_init(root, args.images)
    elif args.cmd == "run":
        code = cmd_run(root, args.program, args.script, args.script_args)
    else:
        code = cmd_sync(root)
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
