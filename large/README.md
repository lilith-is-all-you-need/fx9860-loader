# fx9860-large-loader

External Flash execution backends for fx-9860GIII, including the experimental
path beyond the OS's 512-page / 2 MiB mapping window.

The current `ExtLoad.g1a` reads a dynamic `EXT.PRF` and `IMAGE.BIN` from each
`/FXAPPS/<ID>` directory. Image pages, table capacity, full hash and storage/RAM
budgets are checked per launch; a single executable replaces the fixed 699-page
launcher. `FxStudio::LargeRuntime` exposes the C/C++ source integration contract.
Read the [English manual](docs/runtime.en.md) or [中文手册](docs/runtime.zh-CN.md).
Binary hook evidence is byte-bound and reviewable, but arbitrary binary hooks
remain unsupported; Ghidra completion does not imply runtime compatibility.
The [2026-11-18 validation](VALIDATION-DYNAMIC-20261118.json) records directory
boot/calculation, a separately compiled source guest across the 512-page boundary,
spare-entry checks and empty-directory EXIT. These are emulator results.

Hardware first launches were reported working for KhiCAS and integrated Giac,
but same-icon MENU return failed. The Giac RC2 launcher adds an explicit reload
page; original KhiCAS resume remains unresolved on hardware. See
[the findings and retest procedure](HARDWARE-20261117.md).

* `probes/mapped-loader`: exact-version original KhiCAS adapter; 512-page OS
  mapping, four shadow pages, resident syscall/callback maintenance. Full
  calculator candidate exists; complete hardware acceptance is pending.
* `probes/extended-loader`: independent 698-page guest-refill execution probe.
  Synthetic code/data passed simulation; full CAS integration and hardware
  acceptance are separate. This is not a universal oversized-G1A converter.
* `probes/extended-cas`: dynamic source-integrated loader; the prior 699-page
  Giac RC2 remains a regression fixture. Previous calculation/plot/cleanup
  simulation records apply to that old launcher. The current dynamic version
  requires fresh hardware acceptance. Source adapters are included; the math
  archive is external.

Open either directory in the FxStudio offline SDK and build Debug, then Release.
The source retains authored relocation checks. Use the unified PC tool in
[fx9860-loader](https://github.com/lilith-is-all-you-need/fx9860-loader)
to classify inputs, generate profiles and prepare exact-version bundles.

See the [mapped instructions](probes/mapped-loader/README.zh-CN.md) and
[extended runtime contract](probes/extended-loader/README.md). Tests requiring an
emulator use the separately built [fx9860-emulator](https://github.com/lilith-is-all-you-need/fx9860-emulator).
Firmware, original KhiCAS/Giac binaries and private traces are not included.

`probes/native-loader/tools/prepare.py` is a small synchronized scanner snapshot
from fx9860-loader, retained so offline mapped profile generation is standalone.
Code is MIT; third-party program licenses remain their owners'.
