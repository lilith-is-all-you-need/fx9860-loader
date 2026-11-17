using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace ProfileStudio;

public sealed class QueueItem : INotifyPropertyChanged
{
    public string Source { get; set; } = "";
    public string Name => Path.GetFileName(Source);
    public long Bytes { get; set; }
    public string Size => $"{Bytes / 1024.0:N1} KiB · {(Bytes + 4095) / 4096:N0} 页";
    string status = "待处理", backend = "自动选择";
    public string Status { get => status; set { status = value; Changed(); Changed(nameof(StatusColor)); } }
    public SolidColorBrush StatusColor => new(status switch {
        "可实机测试" => Color.FromArgb(255,22,106,85),
        "需要运行时适配" or "缺少加载器" or "深度分析未完成" => Color.FromArgb(255,145,89,15),
        "失败" => Color.FromArgb(255,170,44,44),
        _ => Color.FromArgb(255,89,101,121) });
    public string Backend { get => backend; set { backend = value; Changed(); } }
    public string? Output { get; set; }
    public JsonElement? Result { get; set; }
    public string? Error { get; set; }
    public event PropertyChangedEventHandler? PropertyChanged;
    void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}

public sealed class Settings
{
    public static string Root { get; } = Argument("--settings-dir") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FxProfileStudio");
    public string Output { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "FxProfileStudio");
    public string Ghidra { get; set; } = "";
    public string Java { get; set; } = "";
    public bool Deep { get; set; }
    public static string? Argument(string key)
    {
        var args = Environment.GetCommandLineArgs(); int i = Array.IndexOf(args, key);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
    public static Settings Load()
    {
        Settings value;
        try { value = JsonSerializer.Deserialize<Settings>(File.ReadAllText(Path.Combine(Root, "settings.json"))) ?? new(); }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { value = new(); }
        var deps = Path.Combine(AppContext.BaseDirectory, "dependencies");
        if (string.IsNullOrEmpty(value.Ghidra) && Directory.Exists(deps))
            value.Ghidra = Directory.GetDirectories(deps, "ghidra*").FirstOrDefault() ?? "";
        if (string.IsNullOrEmpty(value.Java) && Directory.Exists(deps))
            value.Java = Directory.GetDirectories(deps, "jdk*").FirstOrDefault() ?? "";
        return value;
    }
    public void Save()
    {
        Directory.CreateDirectory(Root);
        var file = Path.Combine(Root, "settings.json");
        File.WriteAllText(file + ".tmp", JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(file + ".tmp", file, true);
    }
}

public sealed class JobEngine
{
    public string Python { get; }
    public string Script { get; }
    public string Artifacts { get; }
    public JobEngine()
    {
        string baseDir = AppContext.BaseDirectory;
        Python = Settings.Argument("--python") ?? Path.Combine(baseDir, "runtime", "python", "python.exe");
        var engine = Settings.Argument("--engine") ?? Path.Combine(baseDir, "engine");
        Script = Path.Combine(engine, "tooling", "profile_job.py");
        Artifacts = Path.Combine(engine, "loader-artifacts");
    }
    public async Task<int> Run(IEnumerable<string> arguments, Action<string> onLine, CancellationToken token)
    {
        if (!File.Exists(Python) || !File.Exists(Script)) throw new FileNotFoundException("工具文件不完整。请完整解压程序目录，不要只移动 EXE。");
        var info = new ProcessStartInfo(Python) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        foreach (var arg in new[] { "-B", "-X", "utf8", Script }.Concat(arguments)) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("无法启动文件分析工具。");
        using var cancellation = token.Register(() => { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } });
        var error = process.StandardError.ReadToEndAsync();
        while (await process.StandardOutput.ReadLineAsync() is { } line) onLine(line);
        await process.WaitForExitAsync();
        string stderr = await error;
        token.ThrowIfCancellationRequested();
        if (process.ExitCode != 0 && process.ExitCode != 2) throw new IOException(string.IsNullOrWhiteSpace(stderr) ? "生成失败，请查看任务详情。" : stderr.Trim());
        return process.ExitCode;
    }
    public static string BackendName(string backend) => backend switch {
        "flash" => "通用 Flash 映射", "ram" => "RAM 装载", "mapped" => "KhiCAS 配套映射",
        "extended" => "超限分页", _ => backend };
    public static string StatusName(string status) => status switch {
        "candidate" => "可实机测试", "needs-review" => "需要运行时适配", "profile-only" => "缺少加载器",
        "analysis-incomplete" => "深度分析未完成", _ => status };
}
