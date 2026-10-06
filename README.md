# ME7 Ghidra Toolkit

Static analysis tooling for Bosch **ME7.1 / ME7.1.1 / ME7.5** flash images on
**Infineon C166/C167**. Signatures target firmware structure (DPP layout,
kernel handlers, checksum code), not a part number or hardware box. Verified
addresses and reference images are in `docs/me7-memory-map.md`.

- `patterns/me7-core.yaml`: shared needles (field reference in the file header).
- `ghidra-extension/`: `ME7 Pattern Namer` analyzer and the `ME7SetupScript`
  memory map pre-script.
- `tools/me7tools/`:
  - `me7probe` does the same layout discovery and needle matching without Ghidra.
  - `me7labels` and `me7modules` build the label and module TSVs for the Ghidra
    scripts below.
  - `me7map` decodes maps from DAMOS or XDF definitions.
  - `me7ghidra` imports into, runs scripts on, and exports the headless project.

## Setup

Needs JDK 21+, Python 3.11+, Ghidra 12.x, and
[keyhana/c166-ghidra-module](https://github.com/keyhana/c166-ghidra-module)
installed in Ghidra.

```bash
echo "GHIDRA_INSTALL_DIR=/path/to/ghidra" >> ~/.gradle/gradle.properties  # once per machine
make  # me7tools venv + pytest, then ghidra-extension/dist/ME7Ghidra-<version>-ghidra_<ghidra>.zip
```

Install the zip with File > Install Extensions. `make help` lists the targets.
`make GHIDRA_INSTALL_DIR=download GHIDRA_VERSION=12.1.4 extension` builds
against a downloaded Ghidra in `build/ghidra/`, as CI does.

The tests use the reference images from
[nyetwurk/ME7Sum](https://github.com/nyetwurk/ME7Sum) `bins/`, cloned beside
this tree (`../ME7Sum`) or pointed to by `ME7SUM_BINS`. They skip otherwise.

## Releases

- The version comes from git tags only (`git describe`): `vX.Y.Z` gives
  `X.Y.Z`, later commits add `-N-gHASH`, and uncommitted changes add `-dirty`.
  Do not edit version strings by hand. `make version` prints the current one.
- Tag `vX.Y.Z` for a release and `vX.Y.Z-rcN` for a prerelease. Bump Z for
  fixes and needle corrections, Y for new needles, scripts, or analyzer
  features, and X for incompatible changes to `me7-core.yaml` fields or symbol
  names.
- Ghidra only installs an extension built for its own version, so each release
  has one zip per Ghidra version in the `.github/workflows/build.yml` matrix.
  The ME7 version is in the zip name, the extension description, the jar
  manifest, and the analyzer's log line.
- Release notes come from [git-cliff](https://git-cliff.org/) (`cliff.toml`),
  grouped by commit prefix:
  - `feat:` / `add:`
  - `fix:`
  - `needle:` / `pattern:` (signatures)
  - `docs:`
  - `refactor:`
  - `chore:` / `ci:` / `build:` / `test:`
  - `make changelog` previews unreleased notes.
- `build.yml` runs `make test extension` on every push and PR and uploads the
  zips. `release.yml` runs it on `v*` tags and publishes a GitHub release.

## Import an image

`ME7SetupScript.java` does four things:

- Finds DPP0-3 from the init code.
- Maps the 32 KB flash mirror at `0x0`.
- Maps `kernel_ram` at `0x380000` at the flash offset found by the `CALLS 0x38`
  sweep.
- Seeds the vector table, kernel functions, and flash `CALLS` targets that
  follow a `RET`/`RETS`.

The analyzer then labels the needle hits during auto-analysis.

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJECT_DIR" ME7 \
    -import image.bin -loader BinaryLoader -loader-baseAddr 0x800000 \
    -processor C166:LE:16:default -cspec tasking \
    -scriptPath ghidra-extension/ghidra_scripts -preScript ME7SetupScript.java
```

`me7ghidra init` runs that import for the default images into
`../ghidra-projects/ME7/headless`, then applies `data/<part>/labels.tsv` and
`modules.tsv` from that project.

`me7ghidra run <image> <script> ...` runs one script read-only:

- `me7ghidra run 06A906032NL ME7Decomp.java 0x8A3636` decompiles that address.
- `me7ghidra run 8D0907551T ME7Calls.java 0x804902` lists every `CALLS` to those
  targets: the function
  entry, the byte distance, and the moves in front of the call. A segment-0
  target in the first 64K matches the flash argument at `0x800000` plus that
  word. `entry:0x82E47C` defines that function first.
- `ME7CallsIn.java 0x879C9A` lists the calls inside that function, creating it
  when needed.
- `ME7Func.java 0x879C9A` prints the function as address, bytes, and
  instruction.
- `ME7Bytes.java 0x807856 16` prints flash bytes when the address is not a
  function.
- `ME7Pat.java "5E BC ?? ??"` searches flash for that pattern.
- `ME7Cmp.java /path/to/other.bin 0x807856 16` compares that window with the
  same file offset in a second image and prints `??` where a byte differs.
- `ME7Imm.java 0x1be4` lists instructions whose operand is that immediate.
- `ME7Xref.java 0x807856` lists references to that address.

`me7ghidra sync` exports the headless programs as GZFs to `headless/gzf/` for
File > Import in the GUI. It never opens the live project.

Environment:

- `GHIDRA_INSTALL_DIR` if Ghidra is not under `/usr/local`, `/opt`, or `$HOME`.
- `ME7_BINS` (or `ME7SUM_BINS`) if the images are not in `../ME7Sum/bins`.
- `ME7_PROJECT` if the Ghidra project is not `../ghidra-projects/ME7`.

`me7probe image.bin` prints the same layout and needle hits.

## Maps

`me7map` decodes calibration maps into physical units, with their axes:

```bash
me7map --dam image.dam --bin image.bin KFMIOP LDRXN   # exact Bosch conversions, all maps
me7map --xdf image.xdf --bin image.bin KFMIOP         # any image with a TunerPro XDF
me7map --xdf image.xdf -s 'boost|LDR'                 # search names and descriptions
me7map --dam image.dam --bin stock.bin --bin tuned.bin KFMIRL   # second table: differences
me7map --check --dam image.dam --xdf image.xdf --bin image.bin  # XDF entries that disagree with DAMOS
```

With `--dam`, map layout follows the DAMOS record type:

- Shared axes (`Stützstellenverteilung`) start with a point count.
- Maps with their own axes store the counts. The counts are words only if both
  axes are words.
- Variant maps (`_0_A`, `_1_A`) are read at their data address, not the pointer
  table.

XDF definitions often round their equation coefficients (for example
`0.001526` for 100/65536), so their values can differ in the last digits. An
XDF name matches its first word, and `LDRXN` also finds `LDRXN_1_A`.

`--check` decodes every XDF entry both ways and prints one line per difference:

- data address
- shape, including transposed tables
- values
- axes

Values count as equal within half a raw count or 0.2%. Entries off by exactly
2 or 0.5 everywhere are listed separately. XDFs for a 5.12 bar boost sensor
("5120") scale pressures that way on purpose. The exit status is 1 if anything
else differs.

## Labels and function names

`ME7ImportLabelsScript.java` (Tools > ME7 > Import Labels, or
`-postScript ME7ImportLabelsScript.java labels.tsv`) applies labels from a TSV:

- `addr`
- `name`
- `size`, optional. 1 or 2 types the address as byte or word.
- `comment`, optional.

The first name at an address becomes primary. It then adds references from map
pointer immediates (`MOV Rn,#imm`, paged by a following `MOV Rm,#page` or by
DPP) to the imported labels in flash, since ME7 passes maps to its lookup
routines that way.

`ME7NameFunctionsScript.java` (Tools > ME7 > Name Functions, or
`-postScript ME7NameFunctionsScript.java [modules.tsv] [dry]`) names
default-named functions from the labels they use:

- A function that writes labeled RAM is named after the variable read by the
  most functions. Bit flags come last.
- A function that reads labeled flash maps is named after those maps.
- An optional TSV with columns `name` and `module` (comma-separated modules
  allowed) prefixes the name with the module that most of the outputs belong
  to, giving names like `BGSRM_rl`.
- Without that TSV, writers become `set_var` and readers `uses_MAP`.
- Functions called only from a named function become `caller_subN`.
- Functions whose named callees belong to one module become `MODULE_caller`.

The plate comment records the outputs and maps used. Reruns rename only
functions carrying that comment, so names set by hand are kept. `dry` prints
the proposed names and the functions left unnamed without changing the program.

Build the TSVs with `me7tools`:

```bash
me7labels [--dam image.dam | --xdf image.xdf] [--ecu *.ecu ...] -o DIR   # labels.tsv; maps.tsv and ram.tsv with --dam
me7modules fr.txt -o DIR/modules.tsv                   # from pdftotext -layout of a Funktionsrahmen
```

`me7labels` reads:

- An ASAP2DAM DAMOS export, code page 850. Maps come from `/SPZ`. RAM
  measurements come from `/UMP`. Bit flags are typed size 0 with their mask in
  the comment.
- A TunerPro XDF. The address is the file offset plus `0x800000`. An axis with
  its own address is `name_x` / `name_y`.
- ME7Logger `.ecu` files, which only add names the definition lacks.

`me7modules` reads the FR's ABK tables. A parameter gets every module that
lists it. A variable gets the majority of its `Quelle` column.

DAMOS and FR documents are usually confidential, so write their TSVs outside
the repo (for example next to the Ghidra projects). `.ecu`-only output from
[nyetwurk/ME7L](https://github.com/nyetwurk/ME7L) is public.

## Live session with an agent

Keep Ghidra projects outside this repo, and the GUI project separate from
headless projects. Ghidra locks a project while it is open.

Add `ghidra-extension/ghidra_scripts` in Script Manager, open the program, and
run `ME7BridgeScript` (Tools > ME7 > Start Agent Bridge). It serves read-only
views of the open program and your current location on `127.0.0.1`, and writes
the port and token to `me7-bridge.json` in the project directory:

```bash
curl -H "X-Token: $TOKEN" "http://127.0.0.1:$PORT/listing?addr=0x80a2d4&count=20"
```

- `GET /` lists the endpoints.
- Run the script again to restart the bridge.
- Headless, it serves until `GET /stop`.

## References

- [nyetwurk/me7-logger](https://github.com/nyetwurk/me7-logger): runs these
  scripts on the headless project to locate measurements and tuner maps.
- [nyetwurk/ME7Sum](https://github.com/nyetwurk/ME7Sum): checksum needles
  (ROMSYS, CRC, multipoint, RSA).
- [nyetwurk/ME7L](https://github.com/nyetwurk/ME7L): RAM variable maps
  (`me7_std.map`, `me7_alias.map`).
- [nyetwurk/ecuxplot](https://github.com/nyetwurk/ecuxplot) `data/`: WinOLS map
  packs with generated XDF and CSV definitions for several ME7 images.
- [NefMoto/NefMotoOpenSource](https://github.com/NefMoto/NefMotoOpenSource):
  KWP2000, flash layouts, fault-path notes.
- [nihilus/IDAProBoschME7](https://github.com/nihilus/IDAProBoschME7): IDA
  segment and DPP defaults, CRC seed needle.
- [s4wiki Tuning](https://s4wiki.com/wiki/Tuning).

ST10-based ME7.1.1 needs separate work.
