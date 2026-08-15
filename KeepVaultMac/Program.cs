using Avalonia;
using KalynaArchiver.Services;

namespace KalynaArchiver;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        MacProcessHardening.Apply();
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont();
    }
}
