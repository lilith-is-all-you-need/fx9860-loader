# FX Profile Studio（Windows x64）

独立 WinUI 3 桌面工具。全部在电脑本地处理，不需要 LLM、网络服务或原程序源码。
基础生成不依赖 Ghidra；深度分析需要随包提供或自行指定的 Ghidra 和完整 JDK。

## 使用

1. 完整解压程序目录，双击 `ProfileStudio.exe`。不要单独移动 EXE。
2. 添加或拖入多个 `.g1a` / `.bin`，选择结果根目录。
3. 如需深度分析，展开 Ghidra 选项，启用分析并检查依赖。
4. 点击“分析并生成”。每个输入生成独立的新目录，旧结果不会覆盖。
5. 状态为“可实机测试”时，将该项 `calculator` 中全部文件复制到计算器存储根目录。
   保留加载器文件名；阅读结果里的说明。不同项目的 `target.bin`、索引等不能混放覆盖，
   此版本以每个项目独立测试包为单位，不提供多项目合并目录。

没有启用 Ghidra 的分析通常很快。深度分析每个文件有 10 分钟上限；批量依次处理。
可以取消任务。取消会结束当前分析进程及子进程，已经完成的结果保留。
被强制中止的临时分析目录可能留在系统临时目录或结果根目录下，不会标为可用结果。

## 加载范围

| 输入 | 当前处理 |
| --- | --- |
| 普通 G1A，≤2 MiB | 通用 Flash 映射，检查指令形态后生成 profile；不以程序名称或 SHA 白名单决定兼容 |
| 已登记原版 KhiCAS | 配套映射及内存池适配，保持完整镜像布局 |
| 已登记 699 页 Giac 构建 | 配对的超限加载器；payload 已做源码级运行库接入 |
| 未知 G1A，>2 MiB | 生成分页及分析报告，仍需运行时接入，不输出可运行安装包 |

当前分析输入范围为 516 字节至 4 MiB。2 MiB 指 2,097,152 字节。
真实物理页地址依赖计算器当前存储布局，电脑端不能预先推算；加载时由计算器查询。
512 页之后的自动补页需要 guest 页表与异常处理，不能靠一份静态 JSON 自动完成。
“可实机测试”表示文件配套并通过现有静态检查，不表示已证明所有代码路径稳定。
直接 OS 跳转、自管 MMU/VBR、RAM 回调、内存共存和系统切换仍有兼容性边界。

## 输出

- `calculator/`：通过检查时生成的配套测试文件。基础依赖缺失时不构成完整安装包。
- `original.bin`：原始字节，未删初始化代码或资源。
- `analysis.json`、`job-result.json`：加载路径、阻塞项、警告及状态。
- `paging-plan.json`：每页偏移、虚拟地址、有效字节数、SHA-256 和是否超出原 OS 窗口。
  这是分析文档，**不是计算器可执行 profile**，不包含物理地址。
- `checksums.json`：输入、加载器、profile、报告和 Ghidra 导出证据的摘要。
  Ghidra 可变项目数据库不纳入该文件。
- `ghidra/evidence.json`：可选的函数、指令、常量候选、引用、间接控制流及最多 24 个函数的反编译样本。
- `ghidra/project/` 和日志：可用 Ghidra 继续人工复查。Ghidra 项目路径不接受单引号，
  如结果路径含单引号，请把关闭的项目文件与同名 `.rep` 目录一起复制到简单路径再打开。

Ghidra 的地址范围分类是候选证据，不能单独认定一个常量是指针，也不会自动授权重定位。
深度分析失败或超时不会被显示为可测试成功；可修复依赖后重试。
程序设置写入当前用户 LocalAppData/FxProfileStudio；原始文件不会上传。

## 构建与复现

使用 .NET 10 SDK、Windows SDK 和 Windows App SDK 2.6.5：

```powershell
dotnet publish desktop/ProfileStudio/ProfileStudio.csproj -c Release -r win-x64 --self-contained true -o C:/build/ProfileStudio
python tooling/package_profile_studio.py --publish C:/build/ProfileStudio --python C:/PythonEmbedded --artifacts C:/LoaderArtifacts --output C:/ProfileStudio
python -m unittest discover -s tests -v
```

`--ghidra`、`--jdk` 可以向打包脚本提供完整依赖目录。保留各组件许可证。
WinUI 是解包式、自带 .NET 和 Windows App SDK 的桌面程序；无需管理员权限安装。
支持 Windows 10 2004（build 19041）及以上 x64，本轮实际验证环境为 Windows 11。

开发验证参数：`--verify request.json --settings-dir <独立目录>` 启动实际窗口、运行同一批处理逻辑、
保存 `ui-verification.json`，可用 `screenshot` 指定 PNG。JSON 的 `inputs` 为绝对输入路径数组，
`output` 为结果根目录，可选 `deep`、`ghidra`、`java`、`select`。
开发目录可用 `--python`、`--engine` 覆盖运行组件位置。正常用户无需这些参数。
