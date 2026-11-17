# Runtime and optional analysis dependencies

Application code: MIT, https://github.com/lilith-is-all-you-need/fx9860-loader .
Original user G1A/BIN files and Casio firmware are not included.

* Microsoft .NET 10 runtime: MIT and third-party notices in the published runtime.
  https://github.com/dotnet/runtime
* Microsoft Windows App SDK 2.6.5 / WinUI 3: Microsoft distribution terms and
  open-source notices supplied with the SDK/runtime.
  https://github.com/microsoft/WindowsAppSDK/tree/v2.6.5
* Embedded CPython 3.13: Python Software Foundation license and component terms;
  see runtime/python/LICENSE.txt. https://www.python.org/downloads/windows/
* Optional Ghidra 12.2, official release archive dated 2026-10-16: Apache-2.0 and
  third-party component licenses. Full LICENSE and licenses/ remain in the dependency.
  https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build
  Archive: ghidra_12.2_PUBLIC_20261016.zip
  SHA-256: 2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
* Optional Eclipse Temurin JDK 25.0.3+9 x64: GPLv2 with Classpath Exception and
  component terms. Complete legal/ directory is retained.
  https://adoptium.net/temurin/releases/?version=25

The application does not silently download, execute downloaded scripts, or
modify system Java settings. It invokes the selected local JDK using separate
arguments and the project's fixed analysis/export scripts.
