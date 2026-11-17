# Dynamic source-integrated loader

**Current build:** `ExtLoad.g1a`, external `EXT.PRF`, directory selection and
runtime-sized page tables. No compile-time exact image hash or 699-page array.
See the [current English manual](../../docs/runtime.en.md) or
[中文手册](../../docs/runtime.zh-CN.md). The historical RC2 details below describe
the predecessor, not current artifact hashes or allocation sizes.

Imported from the user's completed `mapped-cas-20261116` integration.
This is distinct from the original 512-page KhiCAS adapter and synthetic
698-page probe. `VALIDATION.json` records simulation, not hardware acceptance.

Approved payload: **2,859,236 bytes / 699 pages**, SHA-256
`176a10ffa918f24f0b98ef89156dc04b02df09190dae0fbe0e3d59780e9455f8`.
RC2 `KhiMap.g1a`: 10,024 bytes, SHA-256
`a5032870f6f3da6a76ab6848ae36e2e0da23053e805794aa8958e0f511aa1d1d`.
Resident allocation is 6,912 bytes; CAS separately allocates 32,768 bytes.
The combined 39,680 bytes were tested in a 40,960-byte simulated heap.

## Build and prepare

Open this folder in the FxStudio offline SDK, target `khimap`; build Debug then
Release. An external profile binds the exact prepared payload.
The build checks that all resident references remain within resident code.
`tools/prepare_image.py RAW_PAYLOAD OUTPUT` creates the private 512-byte header
and external profile; the loader no longer needs rebuilding. This command
accepts an already integrated raw payload, not an arbitrary G1A.

`payload-adapter/` contains the startup, TLB, syscall and atomic replacements
and 28-byte resident API. They integrate with the matching Giac/gint build;
they are not a standalone math library. The full Giac archive, runtime libraries
and UI inputs remain external. The Giac project uses its preserved Linux GCC
14.1.0: its frozen LTO objects cannot be consumed by the Windows GCC build despite
the same version number. The small loader itself builds with the Windows SDK.

The unified PC tool recognizes the reviewed `KHICAS.BIN`, verifies the paired
launcher hash and emits a calculator folder plus runtime-profile.json.
It does not rewrite unrelated 2.86 MB G1As into this ABI.

## Operation and limits

Copy `KhiMap.g1a` and `KHICAS.BIN` to storage root. Startup queries all pages and
checks the full file SHA-256. Its own TLB refill extends past `0x00500000` while
leaving the OS's 512-entry table intact. Virtual layout and entry are retained.
MENU/OFF clean up CAS, C++ objects, gint and both allocations before OS handoff.

The runtime rejects payload file operations, timer/quit callback registration and direct
reset/poweroff, keeping file addresses stable during execution. It does not
implement arbitrary Flash movement and callbacks for other programs. Uncached
Flash mappings avoid an unverified cache-alias assumption and may be slower.
Some partial-initialization failures can require RESET. This version displays
stage/error codes; it does not write a result file during CAS execution.

Loader code follows FxStudio's MIT license. The gint-derived adapter retains
its upstream free-use notice in `payload-adapter/UPSTREAM-NOTICE.txt`.
No Giac archive, original binary or proprietary firmware is published here.

RC2 changes only the launcher: after MENU, selecting this icon shows an ended-session
page; EXE reloads CAS. Prior calculations are not retained. `VALIDATION.json` is
the historical RC1 record. See `VALIDATION-REENTRY-20261117.json` and the root
`HARDWARE-20261117.md` for current evidence and remaining hardware limitations.
