# Native Loader 0.1 — experimental RAM backend

This is a real calculator add-in: it selects a catalog item, reads its `.bin`
and `.lpf` through Bfile, verifies SHA-256, copies the resident executor to P2,
maps the image at its original virtual addresses, and enters the original CRT.
The host verifier does not populate target memory or change target registers.
It is **not yet a complete four-program or hardware-validated loader**.

The first corpus is KhiCAS, Wolfenstein, Fruit Ninja, and Minesweeper 1.0.13.
See [VALIDATION.md](VALIDATION.md) for observed results and remaining blockers.
Third-party G1As and their renamed BINs are not distributed in this repository.

## Files and operation

- `Loader.g1a`: the native selector/executor, built from this project.
- `Loader.idx`: fixed-size catalog produced by the converter.
- `<id>.bin`: an exact copy of the original G1A, including its header.
- `<id>.lpf`: 384-byte big-endian loading profile, bound to that BIN's SHA-256.
- `profiles.json`: readable analysis and instruction evidence, for the PC.
- `Loader.txt`: 2048-byte result file, replaced on each load attempt. Back it up
  before another attempt. An unrelated same-name file is preserved and blocks loading.

Copy the G1A, index, BINs and LPFs to the same storage root. UP/DOWN selects;
EXE loads after key release; EXIT leaves rejection/completion screens. Target
keys retain their original meanings. After OS replacement, reopen Loader for
another load. A target that never returns or uses a direct reset needs an adapter.
The current bundle is a development artifact; the four samples have not been
validated on hardware through this loader.

## Build and reproduce

Open this directory as an Fx Studio project, build Debug and then Release with
target `loader`. Use the matched `.fxstudio/build/Release/artifacts/addin.g1a`
as `Loader.g1a`. The build emits a resident relocation audit and verifies the
ELF/G1A payload pair. The resident section cannot refer back to ordinary ROM;
the linker also forbids persistent Loader `.data`/`.bss` in the guest's static RAM.

Create a JSON manifest array, with `id` (1–7 lowercase ASCII letters/digits/_),
`title` (up to 15 ASCII bytes), `source`, and `expectedSha256` for each reviewed
original. An optional `forbiddenPhysicalRam` array holds P1 `[begin,end)` ranges.
KhiCAS uses `[[2282033152,2282213376]]` (`88051000..8807D000`).
Paths in the manifest are resolved relative to the working directory.

From the SDK repository root:

```powershell
python probes/native-loader/tools/prepare.py --manifest C:/samples/manifest.json --output C:/samples/bundle
Copy-Item probes/native-loader/.fxstudio/build/Release/artifacts/addin.g1a C:/samples/bundle/Loader.g1a
python probes/native-loader/tools/test_prepare.py
python probes/native-loader/tools/verify.py --manifest C:/samples/manifest.json --bundle C:/samples/bundle --emulator probes/emulator/build/FxEmulator.exe --output C:/samples/new-verification
```

The corpus verifier expects identifiers `khicas`, `wolf`, `fruit`, `mines` in
that order and a fresh output directory. `--section edges` uses authored code
to test return/callback and rejection paths; `--section samples` compares the
original and Loader paths. Results contain statuses, syscall summaries,
screenshots and native logs. Observed failure is recorded, never counted as a
compatibility pass merely because the verifier completed.

## What the profile does

The original image remains at `00300000`, with entry `00300200`; code, resources,
literal pools and fixed virtual RAM references keep their original relationship.
There is no blanket address delta, byte deletion, or inferred relocation table.
Only recognized syscall gateway literal pools are replaced in the RAM copy,
so `SetQuitHandler` is captured while other calls go to the real OS gateway.
The original BIN on storage remains byte-for-byte unchanged.

The target's latest quit handler runs while target mappings are still active;
then original mappings are restored and allocations released. Original CRT,
constructors, target memory initialization and runtime are retained. A return
to Loader and an OS callback/replacement are separate tested paths.

Profile layout: magic at 0; version/size/entry/flags/patch count/range count at
8..31; SHA-256 at 32..63; eight P1 ranges at 64..127; up to 64 gateway offsets
at 128..383. Version 1 requires flags=1 (writable RAM image). Matching machine
instructions are evidence for those pools, not proof of all possible uses or
full compatibility. Direct boot-ROM jumps are reported as unadapted transfers.

## Hard limits

The backend pins 4 KiB RAM pages, borrows UTLB slots below the OS URB, and leaves
at least eight slots for OS refill. Images larger than 160 KiB are rejected.
It needs a contiguous allocation for the rounded image plus 8191 alignment
bytes, roughly 3 KiB context, and roughly 3 KiB resident code. Existing hardware
probes did not demonstrate the 80–140 KiB allocations needed by these games.

KhiCAS is 2,094,444 bytes (512 pages) and is rejected before handoff. It needs
a real file/flash mapping backend, a verified pager, or a different loading
strategy. Neither expanding an emulator heap nor preloading the sample proves
that backend. The present emulator also cannot execute arbitrary guest TLB
fault handlers or the full Casio OS.

Targets can change MMU/cache, use private physical RAM or jump directly to ROM.
The exit guard detects changed pinned mappings when control returns; it is not
a crash recovery mechanism. Full operand-cache behavior, all OS services and
long-duration stability remain outside this validation.
