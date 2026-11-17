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
    bool loaded;
    public MainWindow()
    {
        InitializeComponent();
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1360, 1000));
        OutputBox.Text = settings.Output; GhidraBox.Text = settings.Ghidra; JavaBox.Text = settings.Java; DeepSwitch.IsOn = settings.Deep;
        Closed += (_, _) => { cancellation?.Cancel(); };
    }
    async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (loaded) return; loaded = true;
        if (Settings.Argument("--verify") is not { } request) return;
        try
        {
            var cfg = JsonDocument.Parse(await File.ReadAllTextAsync(request)).RootElement;
            OutputBox.Text = cfg.GetProperty("output").GetString()!;
            if (cfg.TryGetProperty("ghidra", out var g)) GhidraBox.Text = g.GetString();
            if (cfg.TryGetProperty("java", out var j)) JavaBox.Text = j.GetString();
            DeepSwitch.IsOn = cfg.TryGetProperty("deep", out var d) && d.GetBoolean();
            AddFiles(cfg.GetProperty("inputs").EnumerateArray().Select(x => x.GetString()!));
            await Generate(cfg.TryGetProperty("cancelAfterMs", out var cancel) ? cancel.GetInt32() : 0);
            if (cfg.TryGetProperty("select", out var select)) QueueList.SelectedIndex = select.GetInt32();
            if (QueueList.SelectedItem is { } selected) QueueList.ScrollIntoView(selected);
            Directory.CreateDirectory(OutputBox.Text);
            await File.WriteAllTextAsync(Path.Combine(OutputBox.Text, "ui-verification.json"), JsonSerializer.Serialize(Items.Select(x => new { x.Name, x.Status, x.Output, x.Error, x.Result }), new JsonSerializerOptions { WriteIndented = true }));
            if (cfg.TryGetProperty("screenshot", out var screenshot))
            {
                await Task.Delay(500); await Capture(screenshot.GetString()!);
            }
        }
        catch (Exception ex)
        {
            Directory.CreateDirectory(Settings.Root); await File.WriteAllTextAsync(Path.Combine(Settings.Root, "verification-error.txt"), ex.ToString());
        }
        finally { Application.Current.Exit(); }
    }
    async Task Capture(string path)
    {
        var bitmap = new RenderTargetBitmap(); await bitmap.RenderAsync(RootPanel);
        var pixels = await bitmap.GetPixelsAsync();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(CreateFile(path)));
        using var stream = await file.OpenAsync(FileAccessMode.ReadWrite);
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, pixels.ToArray());
        await encoder.FlushAsync();
    }
    static string CreateFile(string path) { File.WriteAllBytes(path, Array.Empty<byte>()); return path; }
    void AddFiles(IEnumerable<string> files)
    {
        if (cancellation != null) return;
        foreach (var file in files)
        {
            string full = Path.GetFullPath(file), ext = Path.GetExtension(full).ToLowerInvariant();
            if (ext is not (".g1a" or ".bin") || Items.Any(x => string.Equals(x.Source, full, StringComparison.OrdinalIgnoreCase))) continue;
            try { Items.Add(new() { Source = full, Bytes = new FileInfo(full).Length }); }
            catch (IOException ex) { ProgressText.Text = ex.Message; }
        }
        if (Items.Count > 0 && QueueList.SelectedIndex < 0) QueueList.SelectedIndex = 0;
        ProgressText.Text = $"队列中有 {Items.Count} 个文件。";
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
    void ClearClick(object sender, RoutedEventArgs e) { if (cancellation == null) { Items.Clear(); UpdateDetail(); } }
    void CancelClick(object sender, RoutedEventArgs e) { cancellation?.Cancel(); ProgressText.Text = "正在停止当前任务…"; }
    void SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateDetail();
    void UpdateDetail()
    {
        if (QueueList.SelectedItem is not QueueItem item) { DetailName.Text = "选择一个文件"; DetailSize.Text = "先添加需要转换的程序。"; PageBar.Value = 0; DetailStatus.Text = "等待导入"; DetailBody.Text = "生成后可查看加载方式、阻塞原因和完整报告。"; RawDetail.Text = ""; OpenButton.IsEnabled = false; return; }
        DetailName.Text = item.Name; DetailSize.Text = item.Size; PageBar.Value = Math.Min(1024, (item.Bytes + 4095) / 4096);
        DetailStatus.Text = item.Status; DetailStatus.Foreground = item.StatusColor; OpenButton.IsEnabled = item.Output != null && Directory.Exists(item.Output);
        if (item.Result is not { } r) { DetailBody.Text = item.Error ?? "将自动选择加载方式，并检查文件与分页边界。"; RawDetail.Text = item.Error ?? ""; return; }
        bool candidate = r.GetProperty("installableCandidate").GetBoolean();
        string backend = r.GetProperty("backend").GetString()!;
        DetailBody.Text = JobEngine.BackendName(backend) + "\n\n" + (candidate
            ? "已生成 calculator 测试目录。请完整复制到计算器，再验证运行、退出与重入。此结果不代表实机稳定性保证。"
            : backend == "extended" ? "已生成逐页分析。这个超限镜像尚无配套运行时，不能仅凭本报告运行；需接入补页异常处理并协调 RAM、VBR 和系统切换。"
            : "未生成完整可测试包。请查看下方诊断与 analysis.json。") ;
        var deep = r.GetProperty("deepAnalysis"); string state = deep.GetProperty("status").GetString()!;
        if (state == "completed") DetailBody.Text += $"\n\nGhidra 已分析 {deep.GetProperty("functionCount").GetInt32():N0} 个函数、{deep.GetProperty("instructionCount").GetInt32():N0} 条指令。交叉引用与反编译样本保存在 ghidra 目录。";
        else if (state != "not-requested") DetailBody.Text += "\n\nGhidra 分析未完成，检查依赖或日志后重试。";
        RawDetail.Text = JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true });
    }
    async void GenerateClick(object sender, RoutedEventArgs e) => await Generate();
    async Task Generate(int cancelAfterMs = 0)
    {
        if (cancellation != null) return;
        if (Items.Count == 0) { ProgressText.Text = "请先添加 G1A 或 BIN 文件。"; return; }
        if (string.IsNullOrWhiteSpace(OutputBox.Text)) { ProgressText.Text = "请选择保存位置。"; return; }
        cancellation = new(); var token = cancellation.Token;
        if (cancelAfterMs > 0) cancellation.CancelAfter(cancelAfterMs);
        GenerateButton.IsEnabled = AddButton.IsEnabled = ClearButton.IsEnabled = OutputBox.IsEnabled = Advanced.IsEnabled = false;
        CancelButton.IsEnabled = true; Progress.IsIndeterminate = true;
        int completed = 0, runnable = 0;
        try
        {
            settings.Output = Path.GetFullPath(OutputBox.Text.Trim()); settings.Ghidra = GhidraBox.Text.Trim(); settings.Java = JavaBox.Text.Trim(); settings.Deep = DeepSwitch.IsOn; settings.Save();
            foreach (var item in Items)
            {
                token.ThrowIfCancellationRequested(); QueueList.SelectedItem = item;
                item.Status = "处理中"; item.Result = null; item.Error = null; item.Output = null;
                string name = string.Concat(Path.GetFileNameWithoutExtension(item.Source).Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
                if (name.Length > 48) name = name[..48];
                string output = Path.Combine(settings.Output, $"{name}-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}");
                var args = new List<string> { "generate", "--input", item.Source, "--output", output, "--artifacts", engine.Artifacts };
                if (settings.Deep) args.AddRange(new[] { "--deep", "--ghidra", settings.Ghidra, "--java", settings.Java });
                string lastError = "";
                try
                {
                    await engine.Run(args, line => {
                        try { var evt = JsonDocument.Parse(line).RootElement; string message = evt.GetProperty("message").GetString()!;
                            DispatcherQueue.TryEnqueue(() => ProgressText.Text = $"{completed + 1}/{Items.Count} · {item.Name} · {message}");
                            if (evt.GetProperty("phase").GetString() == "error") lastError = message;
                        } catch (JsonException) { }
                    }, token);
                    var r = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(output, "job-result.json"))).RootElement.Clone();
                    item.Result = r; item.Output = output; item.Status = JobEngine.StatusName(r.GetProperty("status").GetString()!); item.Backend = JobEngine.BackendName(r.GetProperty("backend").GetString()!);
                    if (r.GetProperty("installableCandidate").GetBoolean()) runnable++;
                    completed++;
                }
                catch (OperationCanceledException) { item.Status = "已取消"; item.Error = "任务已停止。未完成的内容不作为可用结果发布。"; throw; }
                catch (Exception ex) { item.Status = "失败"; item.Error = string.IsNullOrEmpty(lastError) ? ex.Message : lastError; }
                UpdateDetail();
            }
            ProgressText.Text = $"处理结束：{runnable} 个可供实机测试，{completed - runnable} 个需继续处理，{Items.Count - completed} 个失败。";
        }
        catch (OperationCanceledException) { ProgressText.Text = "任务已取消。已完成项目的结果仍保留。"; UpdateDetail(); }
        catch (Exception ex) { ProgressText.Text = ex.Message; }
        finally
        {
            cancellation.Dispose(); cancellation = null; Progress.IsIndeterminate = false; Progress.Value = 100;
            GenerateButton.IsEnabled = AddButton.IsEnabled = ClearButton.IsEnabled = OutputBox.IsEnabled = Advanced.IsEnabled = true; CancelButton.IsEnabled = false;
        }
    }
    async void CheckDependencies(object sender, RoutedEventArgs e)
    {
        try
        {
            DependencyText.Text = "正在检查…";
            await engine.Run(new[] { "dependencies", "--ghidra", GhidraBox.Text.Trim(), "--java", JavaBox.Text.Trim() }, line => {
                var r = JsonDocument.Parse(line).RootElement; string message = r.GetProperty("available").GetBoolean()
                    ? $"可用：Ghidra {r.GetProperty("ghidraVersion").GetString()} / JDK {r.GetProperty("javaMajor").GetInt32()}"
                    : string.Join("\n", r.GetProperty("problems").EnumerateArray().Select(x => x.GetString()));
                DispatcherQueue.TryEnqueue(() => DependencyText.Text = message);
            }, CancellationToken.None);
        }
        catch (Exception ex) { DependencyText.Text = ex.Message; }
    }
    void OpenResult(object sender, RoutedEventArgs e)
    {
        if (QueueList.SelectedItem is not QueueItem { Output: { } output }) return;
        try { Process.Start(new ProcessStartInfo(output) { UseShellExecute = true }); }
        catch (Exception ex) { ProgressText.Text = ex.Message; }
    }
}
