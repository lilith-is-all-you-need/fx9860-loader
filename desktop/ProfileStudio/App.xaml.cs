using Microsoft.UI.Xaml;
using System.IO;

namespace ProfileStudio;
public partial class App : Application
{
    private MainWindow? window;
    public App() { InitializeComponent(); UnhandledException += (_, e) => {
        try { Directory.CreateDirectory(Settings.Root); File.WriteAllText(Path.Combine(Settings.Root,"last-error.txt"),e.Exception.ToString()); } catch(IOException) { }
    }; }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        window=new MainWindow(); window.Activate();
    }
}
