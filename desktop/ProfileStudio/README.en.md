# FX Profile Studio 0.2 for Windows x64

An offline WinUI 3 application that prepares G1A/BIN profiles, program folders and analysis reports. No LLM is required.
Select Chinese or English in the top-right menu. Settings are stored in LocalAppData/FxProfileStudio for the current user.

## Use

1. Extract the complete application directory and run ProfileStudio.exe. Keep its supporting files together.
2. Add or drop G1A/BIN files and choose an output root.
3. By default, only program dependencies are exported. Enable “Include matching Loader” to include the launcher.
4. Click “Analyze & generate”. Each PC output folder uses the original name plus a short SHA-256; the report records the full hash.
5. “Dependencies ready” means you use the corresponding existing Loader. “Ready to test” includes a matching Loader.
   Follow the report and copy calculator contents into calculator storage, preserving FXAPPS subfolders.
6. To replace a missing Loader, choose an output location and click “Export Loader”. No input file is needed.
   The result is written to FX-Loader beneath that location. “Export folder” opens it.
   If the destination already exists, select a different output root; existing files are not overwritten.

Ordinary program files live in calculator/FXAPPS/<8-character ID>/. Keep IMAGE.BIN, APP.MET, icon,
runtime profile and log files together. Different program subfolders can coexist under FXAPPS.
Follow analysis.json for the required launcher and any program-specific adaptation.
Do not combine identically named files from different program subfolders.

The same input and settings reuse an unchanged result directory. Different settings or modified results produce a conflict,
preserving existing files and logs. Choose another output root when changing options.

## Status and limits

| Status | Meaning |
| --- | --- |
| Dependencies ready | Program dependencies are ready for testing with their matching Loader |
| Ready to test | Program dependencies and a matching Loader were exported together |
| Adapter required | Analysis is available, but the program cannot run from the report alone |
| Analysis incomplete | Analysis failed, timed out or lacked dependencies; review diagnostics |
| Failed | Invalid input, output conflict or another error; see task details |

Readiness is not proof of device compatibility or stability. Test launch, exit, MENU return and re-entry.
Unknown oversized programs still need a runtime adapter contract. Ghidra does not automatically resolve exception dispatch,
VBR, MMU ownership or memory coexistence. Extended profile capacity follows the input and runtime limits;
699 pages is not a universal fixed capacity. Physical Flash page addresses are queried on the calculator.

Basic analysis does not require Ghidra. Deep analysis requires Ghidra and a full JDK, bundled or supplied separately.
Each file has a default ten-minute analysis limit. Tasks run sequentially and can be cancelled; completed results remain.
Original bytes and layout are retained. Input files are not uploaded.

## Output

- calculator/: program folders; includes the corresponding Loader when requested.
- original.bin: original input copy.
- analysis.json and job-result.json: loading method, status, blockers and full input hash.
- paging-plan.json: page offsets, virtual addresses, valid byte counts and hashes. Analysis only, not an executable profile.
- checksums.json: delivered file hashes.
- ghidra/: optional evidence and a project for further review. Opening the raw project may require a path without apostrophes.
- 阅读说明.txt: copying instructions and limitations for this result.

## Build and verify

Requires .NET 10 SDK, Windows SDK and Windows App SDK 2.6.5. The unpackaged WinUI application includes its runtime.

~~~powershell
dotnet publish desktop/ProfileStudio/ProfileStudio.csproj -c Release -r win-x64 --self-contained true -o C:/build/ProfileStudio
python tooling/package_profile_studio.py --publish C:/build/ProfileStudio --python C:/PythonEmbedded --artifacts C:/LoaderArtifacts --output C:/ProfileStudio
~~~

Optional --ghidra and --jdk arguments bundle full dependency directories. The package destination must not exist.
Loader artifacts require manifest.json and the corresponding G1A files. “Export Loader” validates and exports all bundled launchers.
Packaging includes bundle_v2.py, ext_profile.py, Ghidra scripts, both manuals and dependency notices.
Requires Windows 10 build 19041 or later, x64. Actual validation used Windows 11; see VALIDATION.json for its scope.

Developer argument --verify request.json opens the real WinUI window and uses the same task methods as the buttons.
Request fields: inputs, output, language (zh-CN/en), includeLoader, deep, ghidra, java, select,
cancelAfterMs, width, height and screenshot. mode is generate (default), export-loader or preview.
Version 2 ui-verification.json contains items, status codes, actual output paths, reuse results and errors.
Development overrides --settings-dir, --python, --engine and --artifacts are also available.
