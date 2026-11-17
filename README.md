# fx9860-loader

Offline G1A preparation and generic Flash/RAM loaders. Standard-library Python;
no LLM service or network is required for analysis or conversion.

## Folder packages (0.2)

The current desktop engine creates stable **name + short SHA** program folders.
It exports dependencies by default; including the shared launcher is optional.
The separate export action needs no source file:

```powershell
python tooling/profile_job.py generate --input program.g1a --output-root results
python tooling/profile_job.py generate --input program.g1a --output-root with-loader --include-loader --artifacts loader-artifacts
python tooling/profile_job.py export-loader --output launchers --artifacts loader-artifacts
```

Copy `calculator` contents to storage root, preserving `FXAPPS/<ID>/`.
`FlashLd.g1a` scans folders and displays English icon cards. Full verification is
the default; explicit Fast uses a cache created by a prior successful Full pass.
Fast still queries physical pages but can miss same-size content changes between
launches. See [folder protocol](probes/storage-loader/FOLDERS.en.md),
[中文协议](probes/storage-loader/FOLDERS.zh-CN.md) and
[tested cases](probes/storage-loader/FOLDER-VALIDATION.json).

`program-ready` means dependencies ready for a shared launcher; `candidate` also
contains that launcher. Both need hardware testing. Version-2 artifact manifests
prevent accidentally attaching old, flat-layout launchers. Unknown oversized
binaries receive `needs-adapter`, even after successful Ghidra analysis.
Source-integrated payloads use dynamic `EXT.PRF` and the sibling `ExtLoad.g1a`.

[CallerSession](sdk/caller-session/README.en.md) provides cooperative state
transactions and MENU policies. A general resident caller-return backend is still
missing; the current Flash backend is rejected by capability checks, rather than
pretending to preserve arbitrary caller stacks/heaps. Nested calls are refused.

Ghidra now exports original bytes, VBR/exception ownership sites, delay slots and
recovered control flow. `hook-review.json` checks byte provenance and records
runtime obligations. It does not generate executable arbitrary-binary hooks.
The historical flat-layout CLI below remains available for old probe packages.

The standalone **[FX Profile Studio WinUI 3 desktop app](desktop/ProfileStudio/README.zh-CN.md)**
adds batch import, bounded offline generation, per-page plans and optional real
Ghidra headless analysis. Ghidra evidence never upgrades an unsupported oversized
binary into a runnable bundle. Dependencies and source build instructions are
documented with the desktop app.

```
python tooling/loader_suite.py input.g1a --output new-result
python tooling/loader_suite.py --batch jobs.json --artifacts C:/LoaderSuite/loader-artifacts
python -m unittest discover -s tests -v
python probes/native-loader/tools/test_prepare.py
```

The converter preserves every original byte, emits page hashes and instruction
evidence, and uses the generic Flash backend for ordinary G1As within 2 MiB.
This backend has no program-name or SHA whitelist. Structurally unsupported
inputs produce a report; accepted inputs remain test candidates. Exit codes:
0 = candidate bundle, 2 = analysis/profile only, 1 = error.

Build `probes/storage-loader` with the FxStudio offline SDK (target `flashloader`).
See its [instructions and limits](probes/storage-loader/README.md) and
[validation](probes/storage-loader/VALIDATION.json). Legacy RAM remains available
in `probes/native-loader` (target `loader`).
Put `Loader.g1a` and the sibling project's `KLoad.g1a` in `loader-artifacts/`
with `manifest.json` hashes; ordinary bundles also require `FlashLd.g1a` there.
The calculator reads the generated index and profiles and uses EXE to launch.

RAM images are limited to 160 KiB *and* available contiguous heap, which may be
much smaller on hardware. The mapped KhiCAS adapter is exact-version only.
Real-device Fruit/Minesweeper image allocations failed; their RAM profiles are
blocked only for RAM. The generic Flash backend uses a smaller resident
allocation and still needs hardware acceptance. See [historical findings](HARDWARE-20261117.md).
For >2 MiB, [fx9860-large-loader](https://github.com/lilith-is-all-you-need/fx9860-large-loader)
owns the experimental guest-refill backend. Arbitrary oversized G1As are not
automatically made compatible by changing their filename.

Optional review JSON requires schemaVersion=1, exact sha256, backend=ram,
memoryReviewed=true, callbacksReviewed=true and forbiddenPhysicalRam ranges.
It is data, never executed as a script. This is an expert review record, not
a self-issued hardware compatibility certificate.

Batch JSON is an array of source/output/optional profile/reviewProfile objects;
paths resolve relative to the batch file. Existing outputs are never overwritten.
Original commercial/user G1As are not distributed. Code is MIT.

Shared mapped profile encoder is a synchronized snapshot from the large-loader
component. Integration checksums are recorded in source-manifest.json.
