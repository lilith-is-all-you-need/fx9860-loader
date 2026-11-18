# Folder Loader 0.2

Copy `FlashLd.g1a` to storage root without renaming it. Each compatible program
has a separate directory under `FXAPPS`, with an ASCII directory ID of 1–8
letters, digits or underscores. The computer generator chooses name + short hash.

| File | Purpose |
| --- | --- |
| `IMAGE.BIN` | Unmodified complete G1A image, including its header |
| `APP.FPF` | Existing 384-byte version 1 Flash mapping profile |
| `APP.MET` | 64-byte program metadata described below |
| `ICON.BIN` | Optional 30×17 monochrome icon from G1A offset `0x4C`. Each row uses four bytes, MSB first, with two zero padding bits (68 bytes total). |
| `RUN.LOG` | Dedicated preallocated 4096-byte log, beginning `FXFLASH1` |
| `VERIFY.CCH` | Optional preallocated 4096-byte verification cache; initially all zero |

Up/down selects a program, EXE starts it, EXIT leaves the browser. F1 selects
Full verification (the default at every Loader start). F2 opens the Fast warning;
EXE explicitly accepts it. The browser displays two icons at a time and supports
32 compatible folders. An overflow indication is displayed if more are found.
Invalid/missing metadata is skipped. When there are no valid folders the old
`Loader.idx` layout is still supported. Images marked as oversized are visible,
but this backend clearly refuses them and directs users to the EXT loader.

Full reads the complete file, verifies SHA-256, and records per-page FNV hashes.
Fast requires a cache from a completed full content check with the same complete
profile and image SHA/size; missing, corrupt or stale caches fall back to Full.
Fast always queries real physical page addresses. Initial content reads are
skipped even if pages moved between launches: the cache contains no historical
physical addresses. Only address changes detected later within the current run
are rechecked against the saved per-page hashes.
**Fast can miss any BIN change that preserves file size, at any location.** Use Full after
replacing or editing an image. The cache checksum is corruption detection, not an
authentication mechanism. Relocation checks and Loader self-file verification
remain active in both modes.

The log starts with `FXFLASH1`, `BUILD=0.2`, `LOG_FORMAT=2` and `RUN_ID_MODE`.
Read only up to the first `\nRUN_END\n`. Bytes after this terminator may belong to
an older run. Appending overwrites the previous terminator; this removes the
four redundant 1024-byte clearing writes. `TICKS_VERIFY_RELEASE` separates image
checking from waiting for EXE release; `TICKS_MAP_READY` reports initial map work
and total time from selection to the final verified mapping. These are raw OS
RTC ticks, not host wall time. The final timing records are saved during cleanup.
READY_ENTRY is persisted before the final refresh; it is not proof of successful
target operation. Physical validation still follows every relevant file write.

All integers below are unsigned big-endian, and all sizes are exact:

* `APP.MET`: `8s magic=FXAPPM01`, four u32 fields (`version=1`, `kind=1` ordinary
  or `2` oversized, `image_bytes`, `flags=0`), printable ASCII NUL-terminated
  `title[32]`, zero `reserved[8]`. For ordinary folders `image_bytes` must match
  `APP.FPF`; disagreement is rejected before backend allocation.
* `VERIFY.CCH`: `8s magic=FXFSC001`, four u32 fields (`version=1`, `image_bytes`,
  `page_count`, `profile_fnv1a`), `sha256[32]`, u32 `page_hashes_fnv1a`, u32
  `reserved=0`, then `page_count` u32 FNV-1a hashes of actual file bytes per 4096-byte
  page (the last page is not padded). The remaining bytes are ignored. FNV-1a
  uses seed 2166136261 and multiplier 16777619 with wrapping u32 arithmetic.
  `profile_fnv1a` covers all 384 profile bytes; the hash-array checksum covers its
  serialized big-endian bytes. Hashes are written before committing the header.

This remains an experimental GIII Flash mapping backend, not an arbitrary A→B→A
library. It preserves its own minimal shell, mapping context and one OS RAM word.
It does not save an arbitrary caller's stack, heap, static data, file handles or
device state. Integrating a caller requires a real pause/snapshot and cold-start
restore backend, with explicit MENU policies. Nested calls are not supported.
Emulator checks are not real-calculator acceptance or an all-G1A guarantee.
