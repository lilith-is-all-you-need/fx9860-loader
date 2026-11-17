# Extended Flash mapping: 698-page execution backend

This is the independently buildable mapping probe imported from the user's
`map698-20261116` experiment. It is an experimental backend, **not an automatic
adapter for arbitrary oversized G1As or a completed CAS integration**.

The payload generator produces 2,857,444 bytes of authored SH code and data.
The resident runtime queries all 698 physical pages through the fingerprinted OS
file API, verifies bytes, and services guest TLB misses using its own page table.
The OS table remains exactly 512 entries. Three modes compare stock OS refill
(`O`), explicit target refill (`M`) and guest-vector automatic refill (`A`).

Build this folder in FxStudio (target `map698`, Debug then Release). Run
`python tools/bundle.py NEW_DIRECTORY`, copy the built G1A as `Map698.g1a` there,
and set `Map698.cfg` to `A` for automatic refill. `Map698.txt` is overwritten per
run. Keep the evidence from each run separately. The synthetic probe reserves
32 KiB and has very little heap margin; it is a stress case, not a CAS budget.

Reproduce on the independently published emulator checkout:

```powershell
python tools/run_probe.py --sdk C:/src/fx9860-emulator --firmware C:/private/3071.bin --exe C:/src/fx9860-emulator/probes/emulator/build/FxEmulator.exe --build C:/test/map698 --mode A --label first-auto --stress --timeout 300
```

The private firmware is never bundled. Probe success requires the `PASS` marker,
2,094 verified page calls, 698 cross-page calls and normal EXIT. The harness uses
normal target execution; it does not inject page mappings or success results.
The original experiment passed these conditions; see the integration validation
record for the current emulator build.

## Runtime integration contract

* Retain image offsets and virtual addresses; use a small installed G1A to enter
  the external file. No guessed whole-image relocation and no header removal.
* Own a resident page table outside payload BSS, heap and stack. Do not put device
  physical addresses in an offline profile. Query them on the calculator.
* Install a coherent guest exception vector and coordinate with gint's own VBR,
  interrupt mask, register banks, OS world switching and syscall gateway.
* Refresh file addresses after operations that may move Flash contents. A TLB
  fault handler must not recursively invoke Bfile to discover a missing page.
* Validate partial-page bounds and instruction-cache aliases. Preserve original
  MMU/OS state before handoff; keep mappings valid until target callbacks finish.
* Treat complete CAS startup, cancellation/OOM, MENU, poweroff and physical-device
  acceptance as separate gates. The Giac project is implementing that integration
  independently; its in-progress output is not certified by this probe.

The imported OS profile headers retain the probe revision and are checked in
the component manifest. Native source is MIT, like the FxStudio loader code.
