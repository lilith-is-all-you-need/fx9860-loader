# Hardware feedback imported 2026-11-17

Two returned Loader.txt files reject allocation **before target execution**:

| Exact target | Image bytes | Requested contiguous image block | Result |
| --- | ---: | ---: | --- |
| Fruit Ninja | 66,236 | 77,823 | NULL |
| Minesweeper 1.0.13 | 126,448 | 135,167 | NULL |

Both had already allocated a 3,036-byte context. The resident runner and the
target's heap would need additional memory. These observations do not measure
the largest free block or establish a universal safe file-size threshold.

The 160 KiB limit is an implementation ceiling, not available hardware RAM.
Earlier sample runs used an explicitly enlarged 192 KiB emulator heap. They
established some execution paths but could not establish device feasibility.
These exact RAM profiles are now blocked, including when a static review is
provided. Analysis retains the unmodified image and reports the required block;
it does not generate a misleading installable calculator folder.

Flash mapping with small shadow pages is a possible next adapter for these
games. The present change does not implement or certify that adapter.

Original KhiCAS and source-integrated Giac first launches were reported working.
Direct MENU -> same Loader icon was reported stuck, probably displaying Loading.
This is separate from MENU -> another app -> fresh Loader launch. Evidence and
returned-log hashes are in `profiles/hardware-results-20261117.json`.
