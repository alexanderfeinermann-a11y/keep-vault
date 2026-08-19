using System.Windows;

namespace QrScanner;

/// <summary>
/// Start-up, and nothing else.
/// </summary>
/// <remarks>
/// This app shares no code with Keep Vault, reads nothing out of its
/// installation and is built separately. It exists to read a printed key sheet
/// back, which needs a camera - and Keep Vault, which holds the archive keys,
/// must never be the process that has one.
/// </remarks>
internal static class Program
{
    [STAThread]
    private static int Main()
    {
        var application = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        var window = new MainWindow();
        application.MainWindow = window;
        window.Show();
        return application.Run();
    }
}
