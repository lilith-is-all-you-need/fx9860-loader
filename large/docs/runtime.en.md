# Dynamic oversized runtime

`ExtLoad.g1a` reads `/FXAPPS/<ID>/EXT.PRF` and `IMAGE.BIN`. One executable handles
different source-integrated images without rebuilding. IDs contain 1–8 ASCII
letters, digits or underscores; Profile Studio derives them from name + hash.
The list uses optional `APP.MET` titles, displays 16 entries at most, and closes
all search handles before loading. Root `EXT.PRF` + `KHICAS.BIN` is a legacy fallback.

## Bounds and profile

The big-endian profile is exactly 128 bytes:

| Offset | Field | Requirement |
|---:|---|---|
| 0 | magic, 8 bytes | `FXEXT002` |
| 8 | version | 2 |
| 12 | image bytes | Includes the 512-byte header |
| 16, 20 | base, entry | `0x00300000`, `0x00300200` |
| 24 | valid page count | `ceil(image_bytes / 4096)` |
| 28 | page capacity | At least valid count, at most 768 |
| 32, 36 | runtime ABI, flags | 1, 1 (source-integrated immutable image) |
| 40 | minimum free storage | Default 8192 bytes, checked on device |
| 44 | guest heap preflight bytes | 0 means target allocator owns the check |
| 48 | image SHA-256 | 32 bytes, full file checked each launch |
| 80 | binary hook count | Must be zero in this version |
| 84 | reserved, 11 words | All zero |

The default capacity rounds up to 16 entries. A 699-page image uses 704 entries;
setting capacity to 768 reserves only more table RAM, not extra valid image pages.
Unused entries remain zero and refill rejects addresses beyond the image size.
Only available UTLB slots below 55 are used, in rotation; this is not 704 hardware
TLB entries. The 768-entry bound is a software policy, not proof of 3 MiB usable
Flash. The offline budget is conservatively 3,000,000 bytes including profile,
metadata and requested reserve. Filesystem overhead, other programs and the
launcher also consume real storage. The on-device free-space check handles both
32-bit and SH4 64-bit output of syscall `0x042E` with a two-word buffer, following
[the original author's SH4 compatibility finding](https://www.casiopeia.net/forum/viewtopic.php?f=11&t=1754).

Resident heap allocation, optional guest heap preflight and storage checks have
distinct errors. A preflight allocation cannot guarantee later fragmented heap
availability; the target must still check every allocation. The final physical
page remains mapped in 4 KiB units. Refusing an out-of-range fault does **not**
provide byte-granular isolation after that page is resident.

## Source library and ownership

Add this repository with CMake `add_subdirectory(...)`, then link
`FxStudio::LargeRuntime`. Include `<fxlarge/runtime.h>` in C or C++. The 28-byte
`FxLargeApi` retains the old Giac MapApi v1 ABI. The resident loader supplies it
as the third entry argument. `fxlarge_bind()` must run before any syscall or
hardware detection, and again after the target initializes `.data` and `.bss`.
Its two function-pointer slots must stay in permanently mapped URAM.

Source runtime integration must cover all these paths:

1. TLB miss entry in permanent RAM saves PR, GBR, MACH/MACL and the required
   register bank, calls `fxlarge_refill_slot`, then restores and executes `rte`.
   A refusal goes to the runtime's original general exception handler.
2. All target OS calls use `fxlarge_syscall_slot` through the documented assembly
   gateway. This is an assembly register convention, not an ordinary C call.
3. VBR world transitions use `fxlarge_atomic_mask()` so the loader world remains
   masked, and `fxlarge_resume_interrupts()` runs only after the target has its
   own complete VBR/drivers installed.
4. Exit stops the target's timers, destroys its runtime and restores the saved
   shim VBR before returning. `fxlarge_unbind()` checks that ownership condition;
   it cannot reconstruct an arbitrary half-initialized runtime.

The Giac-specific `payload-adapter/` remains an example of these real replacements,
including C++ construction and cleanup. Linking the library alone does not patch
an unmodified gint build. The first runtime rejects external Bfile operations,
asynchronous OS callbacks and direct reset/poweroff so its physical Flash pages
cannot move behind its immutable table. MENU/OFF requests are handled after
target teardown. It does not preserve arbitrary caller stacks or nested callers.

An integrated raw image is wrapped with `tooling.ext_profile.wrap_raw()`: 16 bytes
`FXLARGE-PAYLOAD1`, then five BE words `(1, 0x00300200, raw_bytes, 1, 1)` and zeros
through byte 511. This declares an ABI; it is **not** analysis or hardware proof.
The old Giac binary is recognized by its reviewed hash by the PC converter; the
launcher has no compile-time program hash or fixed 699-page array.

## Binary hooks and Ghidra

Replacing VBR handlers or entry dispatch is feasible only with an explicit ABI
and resident code that remains executable during a miss. A complete binary
adapter also needs all world transitions, failure unwinding and old-handler
chaining. Ghidra references/decompilation alone do not prove those properties.
`tooling/hook_review.py` accepts an analyst's Ghidra evidence, verifies exact
image SHA, instruction bytes, offsets, delay-slot acknowledgement and exception
ownership fields. It returns `runnable: false`; no arbitrary binary patch records
are executed by EXT v2. Unknown binaries are refused instead of guessing.

## Build, verification and errors

FxStudio mirrors a selected project into an offline build workspace. Samples
therefore carry a small `vendor/fxlarge` snapshot. Run
`python tooling/sync_sample_library.py` after library changes;
`python -m unittest discover -s tests -v` checks format boundaries, bad hooks,
malformed profiles, capacity/storage separation and snapshot equality. Open
`probes/extended-cas` in FxStudio and build Debug, then Release. Its relocation
check rejects references that would leave copied resident code.

| Error | Meaning |
|---:|---|
| 10–14 | Missing image / size / physical-page query / close / hash |
| 20–23 | Resident RAM / relocation-table validation |
| 31 | Insufficient reusable TLB slots |
| 40 | Target reported failed initialization stage |
| 51–54 | Invalid profile / page policy / storage package budget / binary hooks |
| 55 | Device free-space query failed or reserve unavailable |
| 56–57 | Guest heap preflight failed / runtime header mismatch |
| 101+ | OS fingerprint rejected; no guessed internal addresses |

Historical RC1/RC2 records are retained. Dynamic folder boot and new capacity
behavior require new hardware results; old hardware success does not certify this
new launcher. Crash/fault debugging remains available, but some incomplete target
worlds still fail-stop and require RESET. No recovery of that state is promised.

Original KhiCAS continues using the separate reviewed arena adapter `KLoad.g1a`.
It now selects folders containing `IMAGE.BIN`, `KHICAS.KPF` and a preallocated
4096-byte `KLOAD.TXT` beginning `FXKLOAD1`. Keep `KLoad.g1a` at storage root.
Its old root layout remains a fallback. No generic mapping is substituted for
the exact-version KhiCAS arena patches; MENU preservation is still unproven.
