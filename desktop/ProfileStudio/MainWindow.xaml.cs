using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Pickers;
using System.Runtime.InteropServices.WindowsRuntime;

namespace ProfileStudio;

public sealed partial class MainWindow : Window
{
    public ObservableCollection<QueueItem> Items { get; } = new();
    readonly Settings settings = Settings.Load();
    readonly JobEngine engine = new();
    CancellationTokenSource? cancellation;
    bool loaded, languageReady;
    string? exportedOutput, operationError;
    JsonElement? exportResult;

    public MainWindow()
    {
        InitializeComponent();
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1360, 960));
        OutputBox.Text = settings.Output; GhidraBox.Text = settings.Ghidra; JavaBox.Text = settings.Java;
        DeepSwitch.IsOn = settings.Deep; IncludeLoaderBox.IsChecked = settings.IncludeLoader;
        LanguageBox.SelectedIndex = settings.Language == "en" ? 1 : 0;
        languageReady = true; ApplyLanguage();
        Closed += (_, _) => cancellation?.Cancel();
    }
    void ApplyLanguage()
    {
        L.English = LanguageBox.SelectedIndex == 1;
        SidebarStep.Text = L.T("01  准备加载文件", "01  Prepare files");
        OfflineTitle.Text = L.T("全部在本机处理", "Processed locally");
        OfflineBody.Text = L.T("离线生成 · 无需 LLM\n保留原始镜像布局", "Offline · No LLM required\nPreserves image layout");
        VersionText.Text = L.T("预览版 0.2", "Preview 0.2");
        PageTitle.Text = L.T("准备计算器加载文件", "Prepare calculator files");
        PageSubtitle.Text = L.T("一份程序，一套固定目录。Loader 可共用，也可随时单独导出。", "One stable folder per program. Share a Loader or export it separately.");
        CompatibilityNote.Title = L.T("生成文件 ≠ 已验证兼容", "Generated does not mean verified");
        CompatibilityNote.Message = L.T("普通程序生成独立依赖；未知超限程序仍需适配合约。Ghidra 分析不能替代实机测试。", "Prepare program dependencies independently. Unknown oversized programs still need an adapter contract. Ghidra analysis does not replace device testing.");
        QueueTitle.Text = L.T("文件队列", "Files");
        ClearButton.Content = L.T("清空", "Clear"); AddButton.Content = L.T("添加文件", "Add files");
        QueueHint.Text = L.T("拖入 .g1a / .bin，可批量生成；原始文件保持不变。", "Drop .g1a / .bin files for batch processing. Source files stay unchanged.");
        OutputTitle.Text = L.T("保存位置", "Output location");
        OutputBox.PlaceholderText = L.T("选择结果根目录", "Choose an output root");
        BrowseButton.Content = L.T("浏览", "Browse");
        OutputHint.Text = L.T("目录由名称 + 短 hash 标识。同一输入与配置可复用；配置冲突会明确提示，不覆盖旧日志。", "Folders use a name + short hash. Matching input and settings reuse results; conflicts are reported without replacing logs.");
        IncludeLoaderBox.Content = L.T("同时导出配套 Loader", "Include matching Loader");
        LoaderHint.Text = L.T("默认只生成程序依赖。已有 Loader 时直接复制程序目录；丢失时可用下方按钮单独导出。", "The default export contains program dependencies only. Keep your shared Loader, or export a replacement below.");
        Advanced.Header = L.T("Ghidra 深度分析", "Ghidra analysis");
        DeepSwitch.Header = L.T("导出交叉引用、控制流和反编译样本", "Export references, control flow and decompilation samples");
        DeepSwitch.OnContent = L.T("本次启用", "Enabled"); DeepSwitch.OffContent = L.T("仅基础分析", "Basic analysis only");
        DeepHint.Text = L.T("需要 Ghidra 与完整 JDK。未知超限程序需要进一步分析及运行时适配，勾选此项不会自动获得兼容性。", "Requires Ghidra and a full JDK. Unknown oversized programs need analysis and runtime adaptation; enabling this option does not establish compatibility.");
        GhidraBox.Header = L.T("Ghidra 安装目录", "Ghidra directory");
        GhidraBox.PlaceholderText = L.T("包含 Ghidra 和 support 的目录", "Directory containing Ghidra and support");
        JavaBox.Header = L.T("JDK 目录", "JDK directory"); JavaBox.PlaceholderText = "Ghidra 12.2 / JDK 25";
        DependenciesButton.Content = L.T("检查依赖", "Check dependencies");
        DetailTitle.Text = L.T("任务详情", "Task details");
        PageHint.Text = L.T("每页 4 KiB；OS 原有窗口 512 页。超限 profile 的容量按输入计算。", "4 KiB per page; the original OS window has 512 pages. Extended profile capacity follows the input.");
        OpenButton.Content = L.T("打开目录", "Open folder"); ReportButton.Content = L.T("查看报告", "View report");
        Diagnostics.Header = L.T("原始诊断", "Raw diagnostics");
        ResultsTitle.Text = L.T("输出内容", "What is exported");
        ResultsBody.Text = L.T("calculator/FXAPPS/：独立程序目录\nprofile、镜像和图标：供 Loader 读取\nanalysis.json：适配判断\npaging-plan.json：分页分析\nghidra/：可选深度分析", "calculator/FXAPPS/: program folders\nProfile, image and icon: Loader inputs\nanalysis.json: adaptation report\npaging-plan.json: page analysis\nghidra/: optional analysis evidence");
        ResultsHint.Text = L.T("不同程序目录可合并到 FXAPPS 下。请按每项报告使用对应加载方式；受阻项目只提供分析材料。", "Program folders can coexist in FXAPPS. Follow each report for its loading method; blocked inputs provide analysis only.");
        ExportButton.Content = L.T("单独导出 Loader", "Export Loader");
        OpenExportButton.Content = L.T("导出目录", "Export folder");
        CancelButton.Content = L.T("取消", "Cancel"); GenerateButton.Content = L.T("分析并生成", "Analyze & generate");
        ProgressText.Text = L.T("准备就绪", "Ready");
        foreach (var item in Items) item.Refresh();
        UpdateDetail();
    }
    void LanguageChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!languageReady) return;
        ApplyLanguage();
        try { SaveSettings(); } catch (Exception ex) { ProgressText.Text = ex.Message; }
    }
    void LayoutChanged(object sender, SizeChangedEventArgs e)
    {
        if (DetailsPanel == null) return;
        bool narrow = e.NewSize.Width < 1100;
        Sidebar.Visibility = e.NewSize.Width < 900 ? Visibility.Collapsed : Visibility.Visible;
        SidebarColumn.Width = new GridLength(e.NewSize.Width < 900 ? 0 : 192);
        DetailsColumn.Width = new GridLength(narrow ? 0 : 320);
        Grid.SetColumn(DetailsPanel, narrow ? 0 : 1);
        Grid.SetRow(DetailsPanel, narrow ? 1 : 0);
    }
    async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (loaded) return; loaded = true;
        if (Settings.Argument("--verify") is not { } request) return;
        try
        {
            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(request));
            var cfg = doc.RootElement;
            OutputBox.Text = cfg.GetProperty("output").GetString()!;
            if (cfg.TryGetProperty("language", out var lang)) LanguageBox.SelectedIndex = lang.GetString() == "en" ? 1 : 0;
            if (cfg.TryGetProperty("ghidra", out var g)) GhidraBox.Text = g.GetString();
            if (cfg.TryGetProperty("java", out var j)) JavaBox.Text = j.GetString();
            if (cfg.TryGetProperty("deep", out var d)) DeepSwitch.IsOn = d.GetBoolean();
            if (cfg.TryGetProperty("includeLoader", out var include)) IncludeLoaderBox.IsChecked = include.GetBoolean();
            if (cfg.TryGetProperty("width", out var width))
                AppWindow.Resize(new Windows.Graphics.SizeInt32(width.GetInt32(), cfg.TryGetProperty("height", out var height) ? height.GetInt32() : 800));
            if (cfg.TryGetProperty("inputs", out var inputs)) AddFiles(inputs.EnumerateArray().Select(x => x.GetString()!));
            string mode = cfg.TryGetProperty("mode", out var m) ? m.GetString()! : "generate";
            int cancel = cfg.TryGetProperty("cancelAfterMs", out var c) ? c.GetInt32() : 0;
            if (mode == "export-loader") await ExportLoader(cancel);
            else if (mode != "preview") await Generate(cancel);
            if (cfg.TryGetProperty("select", out var select)) QueueList.SelectedIndex = select.GetInt32();
            if (QueueList.SelectedItem is { } selected) QueueList.ScrollIntoView(selected);
            Directory.CreateDirectory(OutputBox.Text);
            await File.WriteAllTextAsync(Path.Combine(OutputBox.Text, "ui-verification.json"), JsonSerializer.Serialize(new {
                schemaVersion = 2, language = L.English ? "en" : "zh-CN", mode,
                includeLoader = IncludeLoaderBox.IsChecked == true, operationError,
                exportedOutput, exportResult, progress = ProgressText.Text,
                items = Items.Select(x => new { x.Name, x.StatusCode, x.Status, x.Output, x.Error, x.Result })
            }, new JsonSerializerOptions { WriteIndented = true }));
            if (cfg.TryGetProperty("screenshot", out var screenshot))
            {
                await Task.Delay(500); await Capture(screenshot.GetString()!);
            }
        }
        catch (Exception ex)
        {
            Directory.CreateDirectory(Settings.Root);
            await File.WriteAllTextAsync(Path.Combine(Settings.Root, "verification-error.txt"), ex.ToString());
        }
        finally { Application.Current.Exit(); }
    }
    async Task Capture(string path)
    {
        var bitmap = new RenderTargetBitmap(); await bitmap.RenderAsync(RootPanel);
        var pixels = await bitmap.GetPixelsAsync();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllBytes(path, Array.Empty<byte>());
        var file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(path));
        using var stream = await file.OpenAsync(FileAccessMode.ReadWrite);
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, pixels.ToArray());
        await encoder.FlushAsync();
    }
    void AddFiles(IEnumerable<string> files)
    {
        if (cancellation != null) return;
        foreach (var file in files)
        {
            string full = Path.GetFullPath(file), ext = Path.GetExtension(full).ToLowerInvariant();
            if (ext is not (".g1a" or ".bin") || Items.Any(x => string.Equals(x.Source, full, StringComparison.OrdinalIgnoreCase))) continue;
            try { Items.Add(new() { Source = full, Bytes = new FileInfo(full).Length }); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { ProgressText.Text = ex.Message; }
        }
        if (Items.Count > 0 && QueueList.SelectedIndex < 0) QueueList.SelectedIndex = 0;
        ProgressText.Text = L.T($"队列中有 {Items.Count} 个文件。", $"{Items.Count} file(s) in the queue.");
    }
    async void AddClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker(); picker.FileTypeFilter.Add(".g1a"); picker.FileTypeFilter.Add(".bin");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            AddFiles((await picker.PickMultipleFilesAsync()).Select(f => f.Path));
        }
        catch (Exception ex) { ProgressText.Text = ex.Message; }
    }
    async void OutputBrowse(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FolderPicker(); picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            if (await picker.PickSingleFolderAsync() is { } folder) OutputBox.Text = folder.Path;
        }
        catch (Exception ex) { ProgressText.Text = ex.Message; }
    }
    void OnDragOver(object sender, DragEventArgs e) { if (cancellation == null && e.DataView.Contains(StandardDataFormats.StorageItems)) e.AcceptedOperation = DataPackageOperation.Copy; }
    async void OnDrop(object sender, DragEventArgs e)
    {
        if (cancellation != null || !e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        try { AddFiles((await e.DataView.GetStorageItemsAsync()).OfType<StorageFile>().Select(f => f.Path)); }
        catch (Exception ex) { ProgressText.Text = ex.Message; }
    }
    void ClearClick(object sender, RoutedEventArgs e) { if (cancellation == null) { Items.Clear(); UpdateDetail(); ProgressText.Text = L.T("准备就绪", "Ready"); } }
    void CancelClick(object sender, RoutedEventArgs e) { cancellation?.Cancel(); ProgressText.Text = L.T("正在停止当前任务…", "Stopping the current task…"); }
    void SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateDetail();
    static bool Flag(JsonElement result, string key) => result.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.True;
    static string Field(JsonElement result, string key, string fallback = "") => result.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString()! : fallback;
    void UpdateDetail()
    {
        if (DetailName == null) return;
        if (QueueList.SelectedItem is not QueueItem item)
        {
            DetailName.Text = L.T("选择一个文件", "Select a file"); DetailSize.Text = L.T("添加需要准备的程序。", "Add a program to prepare.");
            PageBar.Value = 0; DetailStatus.Text = L.T("等待导入", "Waiting for input");
            DetailBody.Text = L.T("生成后可查看加载方式、阻塞原因和完整报告。", "See the loading method, blockers and full report after generation.");
            DetailPath.Text = RawDetail.Text = ""; OpenButton.IsEnabled = ReportButton.IsEnabled = false; return;
        }
        DetailName.Text = item.Name; DetailSize.Text = item.Size; PageBar.Value = Math.Min(768, (item.Bytes + 4095) / 4096);
        DetailStatus.Text = item.Status; DetailStatus.Foreground = item.StatusColor;
        DetailPath.Text = item.Output ?? "";
        OpenButton.IsEnabled = item.Output != null && Directory.Exists(item.Output);
        ReportButton.IsEnabled = item.Output != null && File.Exists(Path.Combine(item.Output, "analysis.json"));
        if (item.Result is not { } r) { DetailBody.Text = item.Error ?? L.T("自动选择加载方式，检查文件与分页边界。", "Selects a loading method and checks the input and page boundaries."); RawDetail.Text = item.Error ?? ""; return; }
        string status = Field(r, "status"), backend = Field(r, "backend");
        string body = status switch {
            "program-ready" => L.T("程序依赖已生成，无需重复安装已有 Loader。将 calculator 内的程序目录复制到计算器相应位置；需要 Loader 时，可单独导出或勾选随包附带。", "Program dependencies are ready. Copy the program folders from calculator to the matching calculator location. Use your existing Loader, export one separately, or enable Include matching Loader."),
            "candidate" => L.T("已生成含配套 Loader 的实机测试包。请按报告复制文件，验证运行、退出与重入。此状态不代表稳定性保证。", "A device test bundle with its matching Loader is ready. Follow the report and test launch, exit and re-entry. This is not a stability guarantee."),
            "needs-adapter" or "needs-review" => L.T("已生成分析材料，但未建立可执行的运行时适配。未知超限程序需要 Ghidra 证据和适配合约，不能仅凭分页表直接运行。", "Analysis is available, but an executable runtime adapter is missing. Unknown oversized programs need Ghidra evidence and an adapter contract; a page table alone is insufficient."),
            _ => L.T("尚未生成完整可测试结果，请查看诊断和报告。", "The result is not ready for device testing. Review the diagnostics and report.")
        };
        DetailBody.Text = L.Backend(backend) + "\n\n" + body;
        if (Flag(r, "reused")) DetailBody.Text += "\n\n" + L.T("已复用相同输入与配置的结果，原有日志保留。", "Reused the matching input and settings; existing logs were preserved.");
        if (r.TryGetProperty("deepAnalysis", out var deep))
        {
            string state = Field(deep, "status");
            if (state == "completed")
            {
                int funcs = deep.TryGetProperty("functionCount", out var f) ? f.GetInt32() : 0;
                int instructions = deep.TryGetProperty("instructionCount", out var n) ? n.GetInt32() : 0;
                DetailBody.Text += "\n\n" + L.T($"Ghidra：{funcs:N0} 个函数、{instructions:N0} 条指令。证据保存在 ghidra 目录。", $"Ghidra: {funcs:N0} functions, {instructions:N0} instructions. Evidence is in the ghidra folder.");
            }
            else if (state != "" && state != "not-requested")
                DetailBody.Text += "\n\n" + L.T("Ghidra 分析未完成，请检查依赖和日志。", "Ghidra analysis did not complete. Check the dependencies and logs.");
        }
        RawDetail.Text = JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true });
    }
    void SaveSettings()
    {
        settings.Output = Path.GetFullPath(OutputBox.Text.Trim());
        settings.Ghidra = GhidraBox.Text.Trim(); settings.Java = JavaBox.Text.Trim();
        settings.Deep = DeepSwitch.IsOn; settings.IncludeLoader = IncludeLoaderBox.IsChecked == true;
        settings.Language = L.English ? "en" : "zh-CN"; settings.Save();
    }
    void SetBusy(bool busy)
    {
        GenerateButton.IsEnabled = ExportButton.IsEnabled = AddButton.IsEnabled = ClearButton.IsEnabled =
            OutputBox.IsEnabled = BrowseButton.IsEnabled = IncludeLoaderBox.IsEnabled =
            Advanced.IsEnabled = LanguageBox.IsEnabled = !busy;
        CancelButton.IsEnabled = busy; Progress.IsIndeterminate = busy;
        if (!busy) Progress.Value = 100;
    }
    async Task<JsonElement> RunJob(IEnumerable<string> args, Action<string> progress, CancellationToken token)
    {
        JsonElement? result = null; string lastError = "";
        try
        {
            await engine.Run(args, line => {
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var evt = doc.RootElement; string phase = Field(evt, "phase");
                    progress(L.Phase(phase));
                    if (phase == "error") lastError = Field(evt, "message");
                    if (evt.TryGetProperty("result", out var r)) result = r.Clone();
                }
                catch (JsonException) { }
            }, token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && lastError.Length > 0)
        { throw new IOException(lastError, ex); }
        if (result is not { } complete)
            throw new IOException(lastError.Length > 0 ? lastError : L.T("分析工具未返回完整结果。", "The analysis tool did not return a complete result."));
        return complete;
    }
    async void GenerateClick(object sender, RoutedEventArgs e) => await Generate();
    async Task Generate(int cancelAfterMs = 0)
    {
        if (cancellation != null) return;
        if (Items.Count == 0) { ProgressText.Text = L.T("请先添加 G1A 或 BIN 文件。", "Add a G1A or BIN file first."); return; }
        if (string.IsNullOrWhiteSpace(OutputBox.Text)) { ProgressText.Text = L.T("请选择保存位置。", "Choose an output location."); return; }
        cancellation = new(); var token = cancellation.Token;
        if (cancelAfterMs > 0) cancellation.CancelAfter(cancelAfterMs);
        SetBusy(true); operationError = null;
        int completed = 0, ready = 0;
        try
        {
            SaveSettings();
            foreach (var item in Items)
            {
                token.ThrowIfCancellationRequested(); QueueList.SelectedItem = item;
                item.StatusCode = "working"; item.Result = null; item.Error = null; item.Output = null; UpdateDetail();
                var args = new List<string> { "generate", "--input", item.Source, "--output-root", settings.Output, "--artifacts", engine.Artifacts };
                if (settings.IncludeLoader) args.Add("--include-loader");
                if (settings.Deep) args.AddRange(new[] { "--deep", "--ghidra", settings.Ghidra, "--java", settings.Java });
                try
                {
                    var result = await RunJob(args, message => ProgressText.Text = $"{completed + 1}/{Items.Count} · {item.Name} · {message}", token);
                    item.Result = result; item.Output = Field(result, "output");
                    item.StatusCode = Field(result, "status"); item.BackendCode = Field(result, "backend");
                    if (Flag(result, "programReady") || Flag(result, "installableCandidate")) ready++;
                    completed++;
                }
                catch (OperationCanceledException) { item.StatusCode = "cancelled"; item.Error = L.T("任务已停止；未完成内容不作为可用结果。", "The task stopped; incomplete files are not published as ready."); throw; }
                catch (Exception ex) { item.StatusCode = "failed"; item.Error = ex.Message; }
                UpdateDetail();
            }
            ProgressText.Text = L.T($"处理结束：{ready} 个已准备，{completed - ready} 个需继续适配，{Items.Count - completed} 个失败。", $"Finished: {ready} prepared, {completed - ready} need further work, {Items.Count - completed} failed.");
        }
        catch (OperationCanceledException) { operationError = "cancelled"; ProgressText.Text = L.T("任务已取消，已完成结果保留。", "Cancelled. Completed results were retained."); UpdateDetail(); }
        catch (Exception ex) { operationError = ex.Message; ProgressText.Text = ex.Message; }
        finally { cancellation.Dispose(); cancellation = null; SetBusy(false); }
    }
    async void ExportClick(object sender, RoutedEventArgs e) => await ExportLoader();
    async Task ExportLoader(int cancelAfterMs = 0)
    {
        if (cancellation != null) return;
        if (string.IsNullOrWhiteSpace(OutputBox.Text)) { ProgressText.Text = L.T("请选择保存位置。", "Choose an output location."); return; }
        cancellation = new(); if (cancelAfterMs > 0) cancellation.CancelAfter(cancelAfterMs);
        SetBusy(true); operationError = null; exportResult = null; exportedOutput = null; OpenExportButton.IsEnabled = false;
        try
        {
            SaveSettings();
            var result = await RunJob(new[] { "export-loader", "--output", Path.Combine(settings.Output, "FX-Loader"), "--artifacts", engine.Artifacts, "--backend", "all" },
                message => ProgressText.Text = message, cancellation.Token);
            if (Field(result, "status") != "loader-exported")
                throw new IOException(L.T("Loader 导出未完成，请查看诊断。", "Loader export did not complete. Check the diagnostics."));
            exportResult = result; exportedOutput = Field(result, "output");
            OpenExportButton.IsEnabled = Directory.Exists(exportedOutput);
            ProgressText.Text = L.T("Loader 已单独导出：", "Loader exported to: ") + exportedOutput;
        }
        catch (OperationCanceledException) { operationError = "cancelled"; ProgressText.Text = L.T("已取消导出。", "Export cancelled."); }
        catch (Exception ex) { operationError = ex.Message; ProgressText.Text = ex.Message; }
        finally { cancellation.Dispose(); cancellation = null; SetBusy(false); }
    }
    async void CheckDependencies(object sender, RoutedEventArgs e)
    {
        DependenciesButton.IsEnabled = false;
        try
        {
            DependencyText.Text = L.T("正在检查…", "Checking…");
            await engine.Run(new[] { "dependencies", "--ghidra", GhidraBox.Text.Trim(), "--java", JavaBox.Text.Trim() }, line => {
                using var doc = JsonDocument.Parse(line); var r = doc.RootElement;
                DependencyText.Text = r.GetProperty("available").GetBoolean()
                    ? L.T("可用：", "Available: ") + $"Ghidra {Field(r, "ghidraVersion")} / JDK {r.GetProperty("javaMajor").GetInt32()}"
                    : string.Join("\n", r.GetProperty("problems").EnumerateArray().Select(x => x.GetString()));
            }, CancellationToken.None);
        }
        catch (Exception ex) { DependencyText.Text = ex.Message; }
        finally { DependenciesButton.IsEnabled = true; }
    }
    void OpenPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) { ProgressText.Text = ex.Message; }
    }
    void OpenResult(object sender, RoutedEventArgs e) => OpenPath((QueueList.SelectedItem as QueueItem)?.Output);
    void OpenReport(object sender, RoutedEventArgs e)
    {
        if (QueueList.SelectedItem is QueueItem { Output: { } output }) OpenPath(Path.Combine(output, "analysis.json"));
    }
    void OpenExport(object sender, RoutedEventArgs e) => OpenPath(exportedOutput);
}
