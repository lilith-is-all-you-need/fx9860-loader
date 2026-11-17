# FX Universal Loader

Prepare and launch add-ins on the Casio fx-9860GIII. The Windows app, calculator
launchers and profile tools share one release. FxProfile appears as **FX Profile
Studio** in the Windows UI.

**[Download v0.2.0-beta.1 / 下载测试版](https://github.com/lilith-is-all-you-need/fx_universal_loader/releases/tag/v0.2.0-beta.1)** · [中文使用说明](desktop/ProfileStudio/README.zh-CN.md) · [English guide](desktop/ProfileStudio/README.en.md)

| Download | Use |
| --- | --- |
| `FxProfile-win-x64.zip` | Extract the whole archive and open `ProfileStudio.exe`. It includes all three calculator launchers. Ordinary preparation works offline. For optional deep analysis select an installed Ghidra and JDK. |
| `fx_universal_loader-calculator.zip` | Install a launcher when you already have a prepared program folder. Keep the original G1A filename. |
| `SHA256SUMS` | Verify the downloaded archives. |

在 FxProfile 中选择 G1A 或 BIN，第一次安装时勾选“同时导出 Loader”。将输出目录中
`calculator` 的内容复制到计算器存储根目录，保留 `FXAPPS/<ID>/` 层级。
再次添加程序默认只需复制新程序目录。已有程序目录且缺启动器时，也可单独导出 Loader。

| Calculator file | Programs | Source |
| --- | --- | --- |
| `FlashLd.g1a` | Ordinary G1As up to 2 MiB using the Flash backend. Use Full verification for the first run. | [Folder protocol](probes/storage-loader/FOLDERS.en.md) |
| `ExtLoad.g1a` | Programs built against the large runtime ABI, including the adapted Giac build. Table capacity and storage reserve come from the profile. | [Large runtime](large/docs/runtime.en.md) |
| `KLoad.g1a` | The reviewed original KhiCAS image, which requires its own memory-pool adapter. FxProfile identifies it by SHA-256. | [KhiCAS adapter](large/probes/mapped-loader/README.zh-CN.md) |

This beta has emulator coverage for directory launch and arithmetic in both CAS
paths. Hardware acceptance for these launcher builds, including direct MENU
re-entry, is pending. Unknown oversized binaries can receive an analysis report
and may still require a runtime adapter. See the [Flash checks](probes/storage-loader/FOLDER-VALIDATION.json)
and [large-runtime checks](large/VALIDATION-DYNAMIC-20261118.json).

## Development

The [desktop project](desktop/ProfileStudio) and [offline preparation engine](tooling/profile_job.py)
prepare immutable images. [CallerSession](sdk/caller-session/README.en.md) provides cooperative
state management. General caller return/resume still requires calculator backend support.
[LargeRuntime](large) is the source library for extended paging. The emulator is
maintained in [fx9860-emulator](https://github.com/lilith-is-all-you-need/fx9860-emulator).
[FxStudio](https://github.com/lilith-is-all-you-need/fx-9860giii-sdk) consumes a pinned source snapshot.

```powershell
python tooling/profile_job.py generate --input program.g1a --output-root results
python -m unittest discover -s tests -v
python -m unittest discover -s large/tests -v
```

The original Loader history continues at the repository root. Large Loader
history was imported under `large/`. Legacy probes and flat-format preparation
remain available for reproducing older hardware results. Third-party add-ins and
Casio firmware are supplied by their owners. See [LICENSE](LICENSE).
