# fx9860-loader

Offline G1A preparation and calculator RAM Loader. Standard-library Python;
no LLM service or network is required for analysis or conversion.

```
python tooling/loader_suite.py input.g1a --output new-result
python tooling/loader_suite.py --batch jobs.json --artifacts C:/LoaderSuite/loader-artifacts
python tests/test_loader_suite.py
python probes/native-loader/tools/test_prepare.py
```

The converter preserves every original byte, emits page hashes and instruction
evidence, chooses RAM / mapped / extended by size and validates a SHA-bound
review profile. Known exact versions can produce test bundles; unknown or
blocked versions produce a report rather than a false success. Exit codes:
0 = candidate bundle, 2 = analysis/profile only, 1 = error.

Build `probes/native-loader` with the FxStudio offline SDK (target `loader`).
Put `Loader.g1a` and the sibling project's `KLoad.g1a` in `loader-artifacts/`
with `manifest.json`: `{"files":{"Loader.g1a":"sha256", "KLoad.g1a":"sha256"}}`.
The calculator reads the generated index and profiles and uses EXE to launch.

RAM images are limited to 160 KiB *and* available contiguous heap, which may be
much smaller on hardware. The mapped KhiCAS adapter is exact-version only.
Real-device Fruit/Minesweeper image allocations failed; their RAM profiles are
now blocked. See [the hardware findings](HARDWARE-20261117.md).
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
