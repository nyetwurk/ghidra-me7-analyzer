import hashlib
import os
import struct
from pathlib import Path

import pytest

from me7tools import frmodules, labels, maps
from me7tools.layout import find_dpp, sweep_copy_offset
from me7tools.patterns import compile_needle, load_needles
from me7tools.probe import probe

# docs/me7-memory-map.md reference images: MD5, kernel delta vs NL.
REFERENCE_IMAGES = {
    "06A906032NL.bin": ("5c9047c68349946005fa09adcc40b28e", 0),
    "4B0906018CH.bin": ("85412cd972e93d4c44b4d02383150a3c", 0),
    "4B0906018DQ.bin": ("72a1e7d46162c91b2f28866ed9376bb3", -2),
    "4Z7907551S.bin": ("f298f584b27898d95d959b233619c8ba", -10),
}
IMAGES = sorted(REFERENCE_IMAGES)

# Label file offsets. CRC needles agree with me7sum on all 94 ME7Sum bins.
NON_KERNEL_HITS = {
    "06A906032NL.bin": {"CrcTableRef_B": 0x4C456, "app_flash_fault_test": 0x7FCD0},
    "4B0906018CH.bin": {"CrcTableRef": 0x8CE12, "CrcPreBlockRef": 0x8D45A, "XORChkSumGenerate": 0x8CDEE},
    "4B0906018DQ.bin": {"CrcTableRef_B": 0x63B4A, "app_flash_fault_test": 0x7FC86},
    "4Z7907551S.bin": {"CrcTableRef_B": 0x4DE18, "app_flash_fault_test": 0x6C0AE},
}

# NL RAM addresses of CALLS-reached kernel handlers (33 C5, 0x27).
NL_KERNEL_RAM = [0x3846B6, 0x385176]


def load_image(image: str) -> bytes:
    bins = Path(os.environ.get("ME7SUM_BINS", Path(__file__).resolve().parents[4] / "ME7Sum" / "bins"))
    path = bins / image
    if not path.is_file():
        pytest.skip("set ME7SUM_BINS to a nyetwurk/ME7Sum bins/ checkout")
    data = path.read_bytes()
    if hashlib.md5(data).hexdigest() != REFERENCE_IMAGES[image][0]:
        pytest.skip(f"{image} MD5 differs from docs/me7-memory-map.md")
    return data


def test_compile_needle():
    assert [m.start() for m in compile_needle("AA ?? BB").finditer(b"\xaa\x01\xbb\xaa\xaa\x02\xbb")] == [0, 4]
    assert [m.start() for m in compile_needle("aa80", "fffc").finditer(b"\xaa\x83\x00\xaa\x84\xaa\x80")] == [0, 5]


def test_back_up_range(tmp_path):
    yml = tmp_path / "p.yaml"
    yml.write_text('functions:\n  - name: f\n    needle_hex: "AA BB"\n'
                   '    back_up: [0x4, 0xC]\n    entry_after: ["DB 00"]\n')
    n = load_needles(yml)[0]
    data = bytearray(0x20)
    data[0x10:0x12] = b"\xaa\xbb"
    data[0x04:0x06] = data[0x08:0x0A] = b"\xdb\x00"
    assert [n.label(bytes(data), h) for h in n.find(bytes(data))] == [0x0A]
    data[0x08:0x0A] = b"\x00\x00"
    assert n.label(bytes(data), 0x10) == 0x06
    data[0x04:0x06] = b"\x00\x00"
    assert not n.entry_ok(bytes(data), n.label(bytes(data), 0x10))
    yml.write_text(yml.read_text().replace('    entry_after: ["DB 00"]\n', ""))
    with pytest.raises(ValueError):
        load_needles(yml)


def test_find_dpp_prefers_runtime_block():
    boot = bytes.fromhex("e6000000" "e6010502" "e602e000" "e6030300")
    run = bytes.fromhex("e6000402" "e6010502" "e602e000" "e6030300")
    assert find_dpp(boot + b"\x00\x00" + run) == ((0x0204, 0x0205, 0x00E0, 0x0003), [18])


def test_sweep_synthetic():
    k = 0x100
    data = bytearray(0x9000)
    for t in (0x10, 0x40, 0x80):
        data[t + k - 2 : t + k] = b"\xdb\x00"
        data[0x8800 + t : 0x8800 + t + 4] = bytes([0xDA, 0x38, t, 0])
    res = sweep_copy_offset(bytes(data))
    assert res is not None
    assert (res.offset, res.matched, res.targets) == (k, 3, 3)


def test_probe_runs(capsys):
    probe(b"\x00" * 0x100)
    assert "miss  XORChkSumGenerate" in capsys.readouterr().out


DAM = """\
1, /REG, q_test, {}, 6, 0, {%}, 1, 5, 0, 1
/REP, 1, 0, 0, 1, 0, 0;

10, /SPZ, KSCALAR, {test scalar}, 1, $810000, $810000
/SPW, 1, 2, 0, 1
/SPX, 0, 0, 0, 0, 0
/SPY, 0, 0, 0, 0, 0
/FKX, 0, 0, 0
/FKY, 0, 0, 0
/ABL, 0;

11, /SPZ, KLCURVE, {test
curve}, 7, $810004, $810010
/SPW, 1, 1, 0, 1
/SPX, 0, 0, 0, 0, 0
/SPY, 0, 0, 0, 0, 0
/FKX, 8, 0, 0
/FKY, 0, 0, 0
/ABL, 0;

/UMP, {}, var_w, {test word}, $380100, 513, 1, q_test, 3, $FFFF, K;
/UMP, {}, B_flag, {test flag}, $380100, 513, 1, q_test, 3, $10, K;
"""

ECU = "rl_w\t\t, {}\t, 0x00F990,\t2,\t0x0000, {%}\t, 0, 0,\t0.0234375,\t0, {load}\n"

FR = """\
  ABK MODA 1.0 Abkuerzungen
  Parameter Source-X Source-Y Art Bezeichnung
  KFTEST NMOT_W RL_W KF test map
  Variable Quelle Art Bezeichnung
  OUT_W MODA AUS output
  IN_W MODB EIN input
  FB MODA 1.0 Funktionsbeschreibung
  OUT_W MODB AUS not in an ABK table
  ABK MODB 2.0 Abkuerzungen
  Parameter Source-X Source-Y Art Bezeichnung
  KFTEST NMOT_W RL_W KF test map
  Variable Quelle Art Bezeichnung
  OUT_W MODA EIN input
  IN_W MODB AUS output
"""


def test_dam_labels():
    maps, ram = labels.parse_dam(DAM)
    assert [(m["name"], m["bytes"], m["fixed_len"], m["conv"], m["desc"]) for m in maps] == [
        ("KSCALAR", 2, "0", "q_test", "test scalar"), ("KLCURVE", 1, "8", "q_test", "test curve")]
    assert [(r["name"], r["addr"], r["mask"]) for r in ram] == [("var_w", 0x380100, 0xFFFF), ("B_flag", 0x380100, 0x10)]
    got = labels.merge(labels.dam_labels(maps, ram), labels.ecu_labels(ECU, "t.ecu"))
    assert [(lb.addr, lb.name, lb.size) for lb in got] == [
        (0x00F990, "rl_w", 2), (0x380100, "var_w", 2), (0x380100, "B_flag", 0),
        (0x810000, "KSCALAR", 2), (0x810004, "KLCURVE", 0)]
    assert got[2].comment == "test flag mask 0x10 q_test"
    assert got[0].comment == "load (t.ecu)"


XDF = """\
<XDFFORMAT><XDFHEADER><baseoffset>0</baseoffset></XDFHEADER>
<XDFCONSTANT><title>WESSOT</title><description>inlet close</description>
<EMBEDDEDDATA mmedaddress="0x10004" mmedelementsizebits="8" />
<units>deg</units><MATH equation="2.8125 * X"><VAR id="X" /></MATH></XDFCONSTANT>
<XDFCONSTANT><title>WESSOT</title><description>duplicate</description>
<EMBEDDEDDATA mmedaddress="0x10004" mmedelementsizebits="8" /></XDFCONSTANT>
<XDFTABLE><title>KFTEST</title><description>a map</description>
<XDFAXIS id="x"><EMBEDDEDDATA mmedaddress="0x20000" mmedelementsizebits="16" />
<indexcount>4</indexcount><units>rpm</units></XDFAXIS>
<XDFAXIS id="y"><EMBEDDEDDATA mmedaddress="0x0" mmedelementsizebits="8" /><indexcount>2</indexcount></XDFAXIS>
<XDFAXIS id="z"><EMBEDDEDDATA mmedaddress="0x20100" mmedelementsizebits="8" mmedrowcount="2" mmedcolcount="4" />
<units>%</units><MATH equation="0.5 * X"><VAR id="X" /></MATH></XDFAXIS>
</XDFTABLE></XDFFORMAT>
"""


def test_xdf_labels():
    got = {lb.name: lb for lb in labels.xdf_labels(XDF)}
    assert set(got) == {"WESSOT", "KFTEST", "KFTEST_x"}
    assert (got["WESSOT"].addr, got["WESSOT"].size) == (0x810004, 1)
    assert "inlet close" in got["WESSOT"].comment and "2.8125 * X" in got["WESSOT"].comment
    assert (got["KFTEST"].addr, got["KFTEST"].size) == (0x820100, 0)
    assert "a map" in got["KFTEST"].comment and "8 bytes" in got["KFTEST"].comment
    assert (got["KFTEST_x"].addr, got["KFTEST_x"].size) == (0x820000, 0)
    assert "8 bytes" in got["KFTEST_x"].comment
    assert "KFTEST_y" not in got


def test_ecu_comment_collapses_whitespace():
    text = "Z_dk, {}, 0x383976, 0, 0x2, {Zyklusflag:\tDK}\n"
    lb = labels.ecu_labels(text, "t.ecu")[0]
    assert lb.comment == "Zyklusflag: DK mask 0x2 (t.ecu)"


def test_ecu_does_not_override_dam():
    maps, ram = labels.parse_dam(DAM)
    ecu = labels.ecu_labels(ECU.replace("rl_w", "VAR_W"), "t.ecu")
    assert [lb.name for lb in labels.merge(labels.dam_labels(maps, ram), ecu)].count("VAR_W") == 0


def test_fr_modules():
    params, variables = frmodules.parse_fr(FR)
    assert params == {"KFTEST": ["MODA", "MODB"]}
    assert variables == {"out_w": "MODA", "in_w": "MODB"}


MAPDAM = """\
1, /REG, rel_uw_b100, {}, 6, 0, {%}, 1, 5, 0, 99.99
/REP, 65536, 0, 0, 100, 0, 0;

2, /REG, temp_ub_q0p75_o48, {}, 6, 0, {Grad C}, 3, 5, -48, 143.25
/REP, 1, 48, 0, 0.75, 0, 0;

3, /REG, nmot_uw_q0p25, {}, 6, 0, {U/min}, 2, 5, 0, 16383.75
/REP, 1, 0, 0, 0.25, 0, 0;

10, /SPZ, SNM02, {rpm axis}, 6, $810000, $810000
/SPW, 0, 0, 0, 0
/SPX, 3, 2, 0, 16383.75, 99
/SPY, 0, 0, 0, 0, 0
/FKX, 2, 0, 0
/FKY, 0, 0, 0
/ABL, 2;

11, /SPZ, STA03, {temp axis}, 6, $810006, $810006
/SPW, 0, 0, 0, 0
/SPX, 2, 1, -48, 143.3, 99
/SPY, 0, 0, 0, 0, 0
/FKX, 3, 0, 0
/FKY, 0, 0, 0
/ABL, 2;

12, /SPZ, KFSHARED, {shared axes}, 8, $810010, $810010
/SPW, 1, 2, 0, 99.99
/SPX, 3, 2, 0, 16383.75, 10
/SPY, 2, 1, -48, 143.3, 11
/FKX, 0, 0, 0
/FKY, 0, 0, 0
/ABL, 2;

13, /SPZ, KFMIXED, {own axes}, 3, $810020, $810020
/SPW, 2, 1, -48, 143.3
/SPX, 2, 1, -48, 143.3, 7
/SPY, 3, 2, 0, 16383.75, 8
/FKX, 2, 0, 0
/FKY, 2, 0, 0
/ABL, 2;
"""


def map_image() -> bytes:
    img = bytearray(0x40)
    img[0x00:0x06] = struct.pack("<3H", 2, 4000, 8000)  # SNM02: 1000, 2000 rpm
    img[0x06:0x0A] = bytes([3, 64, 104, 144])  # STA03: 0, 30, 60 C
    img[0x10:0x1C] = struct.pack("<6H", *(int(p * 655.36) for p in (10, 20, 30, 40, 50, 60)))
    img[0x20:0x2C] = bytes([2, 2, 64, 104]) + struct.pack("<2H", 4000, 8000) + bytes([64, 104, 144, 184])
    return bytes(img)


def test_damos_maps():
    d = maps.parse_damos(MAPDAM)
    img = map_image()
    t = maps.decode_damos(d, "KFSHARED", img, base=0x810000)
    assert t.rows.values == [1000, 2000] and t.cols.values == [0, 30, 60]
    assert [[round(v) for v in r] for r in t.values] == [[10, 20, 30], [40, 50, 60]]
    t = maps.decode_damos(d, "KFMIXED", img, base=0x810000)
    assert t.rows.values == [0, 30] and t.cols.values == [1000, 2000]
    assert t.values == [[0, 30], [60, 90]] and t.addr == 0x28
    assert "1000" in maps.format_table(t)


def test_conv_reciprocal():
    zk = maps.Conv("zk100msxs_uw_b6553", "s", (0, 65536, 10, 0, 0, 0))
    assert zk.phys(13107) == pytest.approx(0.5, rel=1e-4)
    assert maps.Conv("B_TRUE", "", (0, 0, 0, 0, 0, 0)).phys(7) == 7


def test_xdf_table():
    xdf = """<XDFFORMAT><XDFTABLE><title>KFSHARED (test)</title>
      <XDFAXIS id="x"><EMBEDDEDDATA mmedtypeflags="0x00" mmedaddress="0x07" mmedelementsizebits="8" />
        <indexcount>3</indexcount><MATH equation="0.75 * X+ -48"><VAR id="X" /></MATH></XDFAXIS>
      <XDFAXIS id="y"><EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x02" mmedelementsizebits="16" />
        <indexcount>2</indexcount><MATH equation="0.25 * X"><VAR id="X" /></MATH></XDFAXIS>
      <XDFAXIS id="z"><EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x10" mmedelementsizebits="16"
        mmedrowcount="2" mmedcolcount="3" /><MATH equation="0.001526 * X"><VAR id="X" /></MATH></XDFAXIS>
    </XDFTABLE></XDFFORMAT>"""
    (el,) = maps.parse_xdf(xdf)
    assert maps.xdf_name(el) == "KFSHARED"
    t = maps.decode_xdf(el, map_image())
    assert t.rows.values == [1000, 2000] and t.cols.values == [0, 30, 60]
    assert [[round(v) for v in r] for r in t.values] == [[10, 20, 30], [40, 50, 60]]


def test_check_xdf():
    def entry(name: str, addr: int, eq: str) -> str:
        return f"""<XDFTABLE><title>{name}</title>
          <XDFAXIS id="x"><EMBEDDEDDATA mmedtypeflags="0x00" mmedaddress="0x07" mmedelementsizebits="8" />
            <indexcount>3</indexcount><MATH equation="0.75 * X+ -48"><VAR id="X" /></MATH></XDFAXIS>
          <XDFAXIS id="y"><EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x02" mmedelementsizebits="16" />
            <indexcount>2</indexcount><MATH equation="0.25 * X"><VAR id="X" /></MATH></XDFAXIS>
          <XDFAXIS id="z"><EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x{addr:X}" mmedelementsizebits="16"
            mmedrowcount="2" mmedcolcount="3" /><MATH equation="{eq}"><VAR id="X" /></MATH></XDFAXIS>
        </XDFTABLE>"""
    xdf = "<XDFFORMAT>" + entry("KFSHARED", 0x10, "0.001526 * X") + entry("KFSHARED", 0x10, "0.003052 * X") \
        + entry("KFSHARED", 0x12, "0.001526 * X") + entry("NOPE", 0x10, "X") + "</XDFFORMAT>"
    d = maps.parse_damos(MAPDAM)
    problems = maps.check_xdf(d, maps.parse_xdf(xdf), map_image(), base=0x810000)
    assert problems[0] == "KFSHARED: scaled x2"
    assert problems[1] == "KFSHARED: address XDF 0x12 DAMOS 0x10"
    assert problems[2].startswith("KFSHARED: values differ at [0,0]")
    assert problems[3] == "NOPE: not in DAMOS" and len(problems) == 4


@pytest.mark.parametrize("image", IMAGES)
def test_layout(image: str):
    data = load_image(image)
    assert find_dpp(data)[0] == (0x0204, 0x0205, 0x00E0, 0x0003)
    sweep = sweep_copy_offset(data)
    assert sweep is not None and sweep.confident and sweep.offset == 0x5DE6
    for ram in NL_KERNEL_RAM:
        assert (ram + REFERENCE_IMAGES[image][1]) & 0xFFFF in sweep.seeds


@pytest.mark.parametrize("image", IMAGES)
def test_needles(image: str):
    data = load_image(image)
    delta = REFERENCE_IMAGES[image][1]
    for n in load_needles():
        labels = [n.label(data, h) for h in n.find(data)]
        if n.name.startswith("k_"):
            assert labels == [n.ref_offset + delta], n.name
        else:
            want = NON_KERNEL_HITS[image].get(n.name)
            assert labels == ([want] if want else []), n.name
        assert all(n.entry_ok(data, label) for label in labels), n.name
