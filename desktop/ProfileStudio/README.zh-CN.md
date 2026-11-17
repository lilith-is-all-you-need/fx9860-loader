# FX Profile Studio 0.2（Windows x64）

离线 WinUI 3 桌面工具，为 G1A/BIN 生成配套 profile、程序目录和分析报告。无需 LLM。
界面右上角可切换中文与 English；语言和生成选项保存在当前用户的 LocalAppData/FxProfileStudio。

## 使用

1. 完整解压工具目录，运行 ProfileStudio.exe。不要只移动 EXE。
2. 添加或拖入 G1A/BIN，选择结果根目录。
3. 默认只生成程序依赖。需要一并取得对应启动器时，勾选“同时导出配套 Loader”。
4. 点击“分析并生成”。电脑端目录使用“原文件名 + 短 SHA-256”，完整摘要写入报告。
5. 结果为“依赖已准备”时，使用已有的对应 Loader；结果为“可实机测试”时，包内包含 Loader。
   按报告把 calculator 内的内容复制到计算器存储根目录，保留 FXAPPS 的子目录层级。
6. Loader 丢失时，无需添加输入文件，选择保存位置后点击“单独导出 Loader”。
   结果存放在该位置下的 FX-Loader 目录，可点击“导出目录”打开。
   已有同名导出目录时会提示选择新的保存位置，避免覆盖文件。

普通程序位于 calculator/FXAPPS/<8字符标识>/。目录中包含 IMAGE.BIN、APP.MET、图标、
运行 profile 及日志等配套文件；不同程序的子目录可合并到同一个 FXAPPS 下。
加载器与特定适配的要求以每项 analysis.json 为准。
不要把不同程序目录中的同名 IMAGE.BIN/profile 抽出来混放。

相同输入、相同配置且结果未被修改时会复用同一目录。选项不同或结果被修改时，
程序会明确提示冲突，不会悄悄替换已有目录或日志。需要改配置时选择新的结果根目录。

## 状态与边界

| 状态 | 含义 |
| --- | --- |
| 依赖已准备 | 程序依赖可交给对应 Loader 测试；默认不重复附带 Loader |
| 可实机测试 | 程序依赖和配套 Loader 已一起输出 |
| 需要运行时适配 | 已有分析材料，但不能仅凭报告运行 |
| 深度分析未完成 | 分析失败、超时或依赖不完整；检查诊断 |
| 失败 | 输入无效、输出冲突或其他错误；查看任务详情 |

这些状态不代表实机兼容性或稳定性保证。必须验证启动、退出、MENU 返回和重入。
未知超限程序仍需运行时适配合约；开启 Ghidra 不会自动解决异常分发、VBR、MMU 或内存共存。
超限 profile 容量按输入和运行时约束计算，不以 699 页作为通用固定尺寸。
物理 Flash 页地址由计算器查询，电脑生成的分页报告不包含物理地址。

基础分析不依赖 Ghidra。深度分析需要 Ghidra 和完整 JDK，可使用随包依赖或自行指定。
每个文件默认最多分析 10 分钟，任务依次执行。可取消当前任务；已完成结果保留。
原始程序字节和布局保留，不删除启动代码或资源，也不会上传输入文件。

## 输出

- calculator/：程序目录；勾选时还包含相应 Loader。
- original.bin：原始输入副本。
- analysis.json、job-result.json：加载方式、状态、阻塞项和完整输入摘要。
- paging-plan.json：页偏移、虚拟地址、有效字节数和页摘要。它是分析报告，不是可执行 profile。
- checksums.json：交付文件的摘要。
- ghidra/：可选分析证据和可继续复查的项目。Ghidra 原始项目打开时可能要求路径不含单引号。
- 阅读说明.txt：本次结果的复制说明和边界。

## 构建与复现

需要 .NET 10 SDK、Windows SDK、Windows App SDK 2.6.5。采用解包式、自带运行时的 WinUI 桌面程序。

~~~powershell
dotnet publish desktop/ProfileStudio/ProfileStudio.csproj -c Release -r win-x64 --self-contained true -o C:/build/ProfileStudio
python tooling/package_profile_studio.py --publish C:/build/ProfileStudio --python C:/PythonEmbedded --artifacts C:/LoaderArtifacts --output C:/ProfileStudio
~~~

打包脚本可用 --ghidra 和 --jdk 附带完整依赖目录；输出目录必须不存在。
构件目录需包含 manifest.json 及对应 G1A。默认“导出 Loader”会校验并导出所有配套启动器。
打包过程同时纳入 bundle_v2.py、ext_profile.py、Ghidra 脚本、中英文手册和依赖许可证。
支持 Windows 10 build 19041 及以上 x64；本轮实际环境为 Windows 11，验证范围见 VALIDATION.json。

开发验证参数 --verify request.json 会启动真实 WinUI 窗口并调用与按钮相同的任务逻辑。
请求支持 inputs、output、language（zh-CN/en）、includeLoader、deep、ghidra、java、select、
cancelAfterMs、width、height、screenshot。mode 可为 generate（默认）、export-loader 或 preview。
输出 ui-verification.json 为版本 2，包含 items、状态代码、实际输出路径、复用信息或错误。
开发环境可用 --settings-dir、--python、--engine、--artifacts 覆盖组件位置；普通用户无需这些参数。
