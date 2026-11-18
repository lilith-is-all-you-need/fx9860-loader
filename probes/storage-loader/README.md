# Generic Flash Loader (experimental)

Version 0.2 adds independent `FXAPPS/<name+hash>/` folders, a two-row icon browser,
explicit Full/Fast verification modes, per-program logs and startup counters.
See [English usage and binary protocol](FOLDERS.en.md) or
[中文使用说明](FOLDERS.zh-CN.md). The older flat catalog below remains a fallback.
`FOLDER-VALIDATION.json` records the directory release; `VALIDATION.json` is the
earlier 0.1 baseline and must not be interpreted as a test of a different binary.

`FlashLd.g1a` runs structurally accepted G1As at their original virtual addresses.
The loader has no program-name or SHA-256 whitelist and does not delete the CRT.
The PC tool copies the complete G1A unchanged to BIN. A SHA-bound FPF profile
identifies instruction-validated syscall gates; their pages alone are copied to
RAM and patched. All other pages are read from the actual external file mapping.

The OS window remains 512 × 4096 bytes (2 MiB). Larger files require the separate
source-integrated extended backend. The existing exact KhiCAS adapter remains
available because its private memory arena needs adaptation.

## Prepare and build

Use the FxStudio offline SDK to open this directory and build Debug and Release,
target `flashloader`. The relocation audit rejects resident references outside
the copied section. Put Release `addin.g1a` in `loader-artifacts/FlashLd.g1a` and
add its SHA-256 to that directory's `manifest.json`.

```
python tooling/loader_suite.py input.g1a --output new-result
python tooling/loader_suite.py input.g1a --profile flash --output new-result
python -m unittest discover -s tests -v
```

For a single menu with up to eight inputs:

```
python probes/storage-loader/tools/prepare.py --manifest samples.json --output new-calculator
```

Each JSON item has `id` (1–7 lowercase letters, digits or underscores), `title`
(up to 15 ASCII bytes), and `source` (relative to the manifest). Optional
`expectedSha256` binds the input; it is an integrity check, not a program whitelist.
Copy the generated files plus **FlashLd.g1a** to the calculator storage root.
Keep that launcher filename. UP/DOWN selects a program; EXE launches it.
Return **FlashLd.txt** after testing. The log is preallocated to 4096 bytes.

## Memory and OS behavior

The dynamic allocation contains context, original OS page table, per-file page
addresses/hashes, copied resident code, alignment and only the necessary gate
shadow pages. Shadow allocation preserves virtual/physical address bit 12 for
the SH7305 cache. The calculator measures the actual required allocation and
reports failure before starting the guest. A small file alone is insufficient.

The runner validates the OS fingerprint, queries physical file pages, checks
SHA-256 in the default Full mode (Fast trusts a prior matching cache as described
in the linked manual), and refreshes/rechecks moved pages after file calls and
OS key waits. It also restores the launcher's own file pages. A TLB exception
through syscall 0003 uses the already maintained table; it performs no file I/O.
OS timers and quit callbacks have resident wrappers, with busy-state guards.
Normal target return and OS application replacement clean up and free the runner.

## Limits

This is an automatic **test candidate** generator, not an all-G1A compatibility
certificate. Unknown gateway forms, recognized direct reset transfers, excess
patches and oversized images are rejected explicitly. Unrecognized computed
addresses, raw OS calls, custom MMU/VBR, private RAM layouts and RAM-resident
callbacks still need validation. Timer/quit callbacks currently require target
image addresses. Full copy-back cache and OS timing are not modeled by the emulator.

EXIT/MENU behavior depends on the target program. The loader cannot force a
program that polls its own keyboard to interpret those keys. Same-icon resume
has not been verified on hardware; for a fresh session enter RUN-MAT, then reopen
FlashLd. Do not infer long-term stability from a startup screen.

`tools/verify.py` records startup, interaction, menu and cleanup independently;
failures remain failures in the report. `tools/verify_edges.py` executes malformed
files and an authored normal-return/quit-callback fixture. Both use real loader
files; the harness never writes target memory or registers. Firmware and original
third-party G1As remain external. See `VALIDATION.json` for current evidence.

The [beta.3 hardware record](BETA3-VALIDATION.json) identifies the exact launcher
and Minesweeper build tested on the fx-9860GIII. A normal guest return now
closes FlashLd after cleanup. Startup or validation errors keep the diagnostic
screen open until EXIT. Folder thumbnails are generated on the PC, so an
existing folder needs a regenerated `ICON.BIN` to pick up the extraction fix.
