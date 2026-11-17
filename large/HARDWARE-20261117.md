# MENU return and hardware feedback

The user reports first-launch success for the original KhiCAS mapping adapter
and the integrated 699-page Giac payload. Direct MENU -> the same Loader icon
appeared stuck, probably showing Loading. Exact screen text was not confirmed;
no KLoad/Giac runtime log was returned. Full lifecycle acceptance remains open.

## Integrated Giac: RC2 launcher, unchanged payload

RC1 left the OS display buffer at `Checking KHICAS.BIN / Starting CAS...`.
The payload uses its own gint display buffer. Its MENU operation finishes CAS,
gint and both heap allocations; the loader then enters the OS menu inside
GetKeyWait. Resuming that wait need not return a key to the loader.

In the explicit emulator OS-VRAM redraw stress scenario, RC1 reproduces this
stale screen. An additional EXE starts a second successful run. This supports
the explanation but does not prove every detail of the physical OS path.

RC2 draws `CAS session closed / EXE: reload CAS / MENU: another app` before the
menu handoff. Only EXE starts a new instance; arbitrary keys cannot restart it.
The one-shot menu timer is removed only by its callback, avoiding a second
deinstallation on resume. The existing 2,859,236-byte BIN is unchanged.
Simulation verifies two launches, menu resume without accidental allocation,
explicit reload, matching frees and reused heap addresses. Hardware retest is
still required. This is a fresh CAS session, not preservation of calculations.

## Original KhiCAS: hardware resume unresolved

The same emulator scenario preserves the target screen and accepts further
calculations. It did not reproduce the reported hardware loading screen.
Do not classify that report as a solved Giac bug or infer memory corruption.
The loader now presents a start page explaining the limitation. After a stuck
same-icon return, try EXE once. For a fresh launch, choose RUN-MAT (or another
application) before reopening KLoad, allowing the registered cleanup to run.
Return KLoad.txt after testing and report whether the extra EXE changed the screen.

`probes/extended-cas/tools/verify_lifecycle.py --help` documents the external
binary/emulator/firmware inputs for reproduction. It does not inject guest
memory. Screen review supplements its flow/heap assertions. OS-VRAM stress is
an opt-in scenario, not complete Casio OS emulation.
