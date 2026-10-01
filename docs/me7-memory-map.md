# ME7 memory map and reference images

Verified facts this toolkit relies on. Fault-path background (`P0602` / `P1681`) is in `docs/P1681-P0602.md` in [NefMoto/NefMotoOpenSource](https://github.com/NefMoto/NefMotoOpenSource).

## Reference images

From [nyetwurk/ME7Sum](https://github.com/nyetwurk/ME7Sum) `bins/`. Check MD5s before trusting addresses.

| Image | MD5 | Kernel delta vs `NL` |
| --- | --- | --- |
| `06A906032NL.bin` | `5c9047c68349946005fa09adcc40b28e` | 0 |
| `4B0906018CH.bin` | `85412cd972e93d4c44b4d02383150a3c` | 0 |
| `4B0906018DQ.bin` | `72a1e7d46162c91b2f28866ed9376bb3` | -2 |
| `4Z7907551S.bin` | `f298f584b27898d95d959b233619c8ba` | -10 |

## Ghidra

Import settings are in `README.md`. If the decompiler fails with an empty `decompile failed:` message, the native `decompile` binary is not runnable. On macOS clear quarantine on the Ghidra tree (`xattr -dr com.apple.quarantine "$GHIDRA_INSTALL_DIR"`) and re-import.

## Memory model

- Flash is at `0x800000`; file offset `F` is CPU address `0x800000 + F`.
- Segment `0x00` code (`CALLS 0x00:xxxx`) hits a mirror of the first 32 KB of flash at `0x000000`. Map only 32 KB: `0xE000` and up is C167 internal RAM and SFRs.
- DPP: physical = `(DPP << 14) | (off & 0x3FFF)`. Runtime values are DPP0 `0x0204`, DPP1 `0x0205`, DPP2 `0x00E0`, DPP3 `0x0003` on all 94 ME7Sum images, taken as the most common full `MOV DPP0..DPP3,#imm` block with DPP0 != 0. The reset path block (`0x8064A6` on `NL`) sets DPP0 to `0x0000`; `0x0204` comes from later blocks (`0x80DC08`, `0x8A42F2` on `NL`).
- External RAM is at `0x38xxxx`. The application mirrors 95040 EEPROM pages there.
- The flash programming kernel runs from external RAM: RAM `0x38XXXX` is a copy of file offset `XXXX + 0x5DE6`. Found by the `CALLS 0x38` sweep (35 targets land right after a `RETS` on all four reference images; runner-up 10-12). The copy loop has not been found, so the offset is inferred.
- `ZEROS` is `0xFF1C`, `ONES` is `0xFF1E`. `CALLS` pushes to the system stack, not the user stack `R0`.

## Kernel handlers

Flash-copy addresses on `NL`/`CH`; add the kernel delta for other images. Located by signature (`patterns/me7-core.yaml`), never by fixed address.

| Function | Flash | RAM |
| --- | --- | --- |
| KWP `0x31` StartRoutine (`C4` tool code, `C5` start) | `0x80A2D4` | `0x3844EE` |
| KWP `33 C5` results (match streak in this build) | `0x80A49C` | `0x3846B6` |
| KWP `0x35` RequestUpload (sets upload latch) | `0x80A77E` | `0x384998` |
| KWP `0x27` SecurityAccess (sets flag) | `0x80AF5C` | `0x385176` |
| KWP `0x37` TransferExit | `0x80A9FA` | `0x384C14` |
| Upload exit (clears latch) | `0x80BB28` | `0x385D42` |

- `0x31` is reached by dispatch, not `CALLS`; `33 C5` and `0x27` are `CALLS 0x38` targets on all four images.
- Across all 94 ME7Sum images no kernel signature hits more than once, and every label follows a `RETS` or erased padding. `0x27`, `33 C5`, and `0x31` hit on all 94, `0x35` on 87.
- Kernel builds by delta (`0x27`, `33 C5`, `0x35`, `0x31`):
    - `NL` layout (38 images): one delta per image, 0, -2, or -10.
    - 39 images, including `8D0907551M`: -1388, -1200, -1312, -1216. Their `33 C5` handler has no match-streak check, and `0x27` skips a `MOV`/`JMPR` before the arm step.
    - 7 `4D1907558` images: +404, +90, +120, -2. 3 images (`4D0907558S`, `4D0907559D`, `8D0907551D-0001`): -1396, -1208, -1320, -1216.
    - `0x35` misses on 5 images (`4B0906018`, `4B0907551D`/`E`, `8D0907551C`/`E`; -1934, -1194, -, -1216) and 2 (`006410010A0`, `4E0910559E`; -1704, -1624, -, -1734).
- Application fault test (bit 7 of page 30 byte 8): `NL` `0x87FCD0`, `DQ` `0x87FC86`, `S` `0x86C0AE`; no match on `CH`. Hits on 10 of 94 images.

## Checksum code

`CrcTableRef`, `CrcTableRef_B`, and `CrcPreBlockRef` are ME7Sum's `FindCRCTab` / `FindMainCRCPreBlk` needles with its masks. They agree with `me7sum` on all 94 images (CRC table on 94, pre block on 21). `XORChkSumGenerate` (the IDA CRC seed with a leading wildcard byte so the hit is word aligned) hits once, right after a `RETS`, on 65 of 94; on `CH` it is at `0x88CDEE`. ROMSYS is at file offset `0x8000`.
