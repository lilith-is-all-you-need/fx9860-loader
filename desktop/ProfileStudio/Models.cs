using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace ProfileStudio;

public static class L
{
    public static bool English { get; set; }
    public static string T(string zh, string en) => English ? en : zh;
    public static string Status(string code) => code switch {
        "pending" => T("待处理", "Pending"), "working" => T("处理中", "Processing"),
        "cancelled" => T("已取消", "Cancelled"), "failed" or "invalid-input" => T("失败", "Failed"),
        "candidate" => T("可实机测试", "Ready to test"),
        "program-ready" => T("依赖已准备", "Dependencies ready"),
        "needs-review" or "needs-adapter" => T("需要运行时适配", "Adapter required"),
        "profile-only" => T("配套不完整", "Incomplete bundle"),
        "analysis-incomplete" => T("深度分析未完成", "Analysis incomplete"), _ => code
    };
    public static string Backend(string code) => code switch {
        "flash" => T("通用 Flash 映射", "Shared Flash Loader"),
        "ram" => T("RAM 装载", "RAM loading"),
        "mapped" => T("配套映射", "Paired mapping"),
        "extended" => T("超限分页", "Extended paging"),
        "" => T("自动选择", "Automatic"), _ => code
    };
    public static string Phase(string code) => code switch {
        "analysis" or "analyze" or "analyzing" => T("分析文件", "Analyzing input"),
        "profile" => T("生成 profile", "Preparing profile"),
        "ghidra" or "deep-analysis" => T("Ghidra 深度分析", "Ghidra analysis"),
        "package" or "bundle" or "preparing" => T("准备配套文件", "Preparing files"),
        "completed" or "complete" => T("处理完成", "Completed"),
        "error" => T("遇到问题，详见诊断", "See diagnostics for the error"),
        _ => T("正在处理", "Processing")
    };
}

public sealed class QueueItem : INotifyPropertyChanged
{
    public string Source { get; set; } = "";
    public string Name => Path.GetFileName(Source);
    public long Bytes { get; set; }
    public string Size => $"{Bytes / 1024.0:N1} KiB · {(Bytes + 4095) / 4096:N0} " + L.T("页", "pages");
    string statusCode = "pending", backendCode = "";
    public string StatusCode { get => statusCode; set { statusCode = value; Refresh(); } }
    public string BackendCode { get => backendCode; set { backendCode = value; Changed(nameof(Backend)); } }
    public string Status => L.Status(StatusCode);
    public string Backend => L.Backend(BackendCode);
    public SolidColorBrush StatusColor => new(StatusCode switch {
        "candidate" or "program-ready" => Color.FromArgb(255,22,106,85),
        "needs-review" or "needs-adapter" or "profile-only" or "analysis-incomplete" => Color.FromArgb(255,145,89,15),
        "failed" or "invalid-input" => Color.FromArgb(255,170,44,44),
        _ => Color.FromArgb(255,89,101,121)
    });
    public string? Output { get; set; }
    public JsonElement? Result { get; set; }
    public string? Error { get; set; }
    public event PropertyChangedEventHandler? PropertyChanged;
    public void Refresh() { Changed(nameof(Size)); Changed(nameof(Status)); Changed(nameof(StatusColor)); Changed(nameof(Backend)); }
    void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}

public sealed class Settings
{
    public static string Root { get; } = Argument("--settings-dir") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FxProfileStudio");
    public string Output { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "FxProfileStudio");
    public string Ghidra { get; set; } = "";
    public string Java { get; set; } = "";
    public bool Deep { get; set; }
    public bool IncludeLoader { get; set; }
    public string Language { get; set; } = "zh-CN";
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
        Artifacts = Settings.Argument("--artifacts") ?? Path.Combine(engine, "loader-artifacts");
    }
    public async Task<int> Run(IEnumerable<string> arguments, Action<string> onLine, CancellationToken token)
    {
        if (!File.Exists(Python) || !File.Exists(Script))
            throw new FileNotFoundException(L.T("工具文件不完整。请完整解压程序目录，不要只移动 EXE。", "Tool files are missing. Extract the entire application folder, not only the EXE."));
        var info = new ProcessStartInfo(Python) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        foreach (var arg in new[] { "-B", "-X", "utf8", Script }.Concat(arguments)) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException(L.T("无法启动文件分析工具。", "Could not start the analysis tool."));
        using var cancellation = token.Register(() => {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        });
        var error = process.StandardError.ReadToEndAsync();
        while (await process.StandardOutput.ReadLineAsync() is { } line) onLine(line);
        await process.WaitForExitAsync();
        string stderr = await error;
        token.ThrowIfCancellationRequested();
        if (process.ExitCode != 0 && process.ExitCode != 2)
            throw new IOException(string.IsNullOrWhiteSpace(stderr) ? L.T("生成失败，请查看任务详情。", "Generation failed. See task diagnostics.") : stderr.Trim());
        return process.ExitCode;
    }
}
