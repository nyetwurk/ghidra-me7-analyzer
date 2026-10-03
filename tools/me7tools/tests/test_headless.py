import os
from pathlib import Path

import pytest

from me7tools.headless import (
    bins_dir,
    ecu_data_dir,
    filter_export_line,
    filter_init_line,
    filter_script_output,
    find_ghidra,
    headless_argv,
    import_args,
    post_scripts,
    program_name,
    project_dir,
    repo_root,
)


def test_repo_root_has_scripts():
    assert (repo_root() / "ghidra-extension" / "ghidra_scripts" / "ME7SetupScript.java").is_file()


def test_ecu_data_dir_shares_part_and_prefers_exact(tmp_path):
    (tmp_path / "4B0906018DQ").mkdir()
    (tmp_path / "4B0906018DQ-0060").mkdir()
    assert ecu_data_dir(tmp_path, "4B0906018DQ-0060") == tmp_path / "4B0906018DQ-0060"
    assert ecu_data_dir(tmp_path, "4B0906018DQ-0099") == tmp_path / "4B0906018DQ"
    assert ecu_data_dir(tmp_path, "NOPE") == tmp_path / "NOPE"


def test_post_scripts_and_import_args(tmp_path):
    ecu = tmp_path / "ecu"
    ecu.mkdir()
    (ecu / "labels.tsv").write_text("addr\tname\n", encoding="utf-8")
    scripts = tmp_path / "ghidra_scripts"
    args = import_args(tmp_path / "image.bin", scripts, post_scripts(ecu))
    assert args[:4] == ["-import", str(tmp_path / "image.bin"), "-overwrite", "-loader"]
    assert "ME7SetupScript.java" in args
    assert args[-3:] == ["-postScript", "ME7ImportLabelsScript.java", str(ecu / "labels.tsv")]
    assert program_name("06A906032NL") == "06A906032NL.bin"
    assert program_name("already.bin") == "already.bin"


def test_find_ghidra_uses_install_dir(tmp_path, monkeypatch):
    install = tmp_path / "ghidra"
    (install / "support").mkdir(parents=True)
    (install / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))
    assert find_ghidra() == install.resolve()


def test_find_ghidra_rejects_bad_install_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    with pytest.raises(SystemExit, match="analyzeHeadless"):
        find_ghidra()


def test_project_and_bins_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ME7_PROJECT", str(tmp_path))
    monkeypatch.setenv("ME7_BINS", str(tmp_path))
    assert project_dir(tmp_path) == tmp_path.resolve()
    assert bins_dir(tmp_path) == tmp_path.resolve()
    monkeypatch.delenv("ME7_BINS")
    monkeypatch.setenv("ME7SUM_BINS", str(tmp_path))
    assert bins_dir(tmp_path) == tmp_path.resolve()


def test_headless_argv_picks_platform_launcher(tmp_path):
    install = tmp_path / "ghidra"
    (install / "support").mkdir(parents=True)
    (install / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    (install / "support" / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    argv = headless_argv(install, ["proj", "ME7"])
    if os.name == "nt":
        assert argv[:3] == ["cmd", "/c", str(install / "support" / "analyzeHeadless.bat")]
    else:
        assert argv[0] == str(install / "support" / "analyzeHeadless")
    assert argv[-2:] == ["proj", "ME7"]


def test_filters():
    assert filter_init_line("INFO noise") is None
    assert filter_init_line("    INFO  flash: mirror (GhidraScript)") == "  flash: mirror"
    assert filter_init_line("INFO  pcode error in instruction") is None
    script = "ME7Decomp.java"
    lines = [
        "INFO  something",
        "ERROR  boom (HeadlessAnalyzer)",
        f"INFO  {script}> hello (GhidraScript)",
        f"INFO  {script}> world",
        "INFO  REPORT: Discarding changes to program",
        f"INFO  {script}> after",
    ]
    assert filter_script_output(lines, script) == [
        "ERROR  boom (HeadlessAnalyzer)",
        "hello",
        "world",
    ]
    assert filter_export_line("INFO ME7ExportGzf.java> exported /tmp/a.gzf") == "exported /tmp/a.gzf"
    assert filter_export_line("INFO nothing") is None
