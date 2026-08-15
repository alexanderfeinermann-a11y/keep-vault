using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace KalynaArchiver.Services;

public static partial class WindowProtection
{
    private const uint WdaExcludefromcapture = 0x00000011;

    public static bool TryExcludeFromCapture(Window window)
    {
        nint handle = new WindowInteropHelper(window).Handle;
        return handle != 0 && SetWindowDisplayAffinity(handle, WdaExcludefromcapture);
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowDisplayAffinity(nint hWnd, uint dwAffinity);
}
