using System.Runtime.InteropServices;
using System.Threading;

namespace KalynaArchiver.Services;

internal static partial class MacProcessHardening
{
    private const int RlimitCore = 4;
    private const int PtDenyAttach = 31;
    private const uint PrivateFilesUmask = 0x3F; // 0077

    private static readonly string[] DynamicLoaderVariables =
    [
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_IMAGE_SUFFIX",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_PRINT_TO_FILE",
        "LD_LIBRARY_PATH",
    ];

    private static int _applied;

    internal static MacProcessHardeningStatus LastStatus { get; private set; } =
        new(false, false, false, false);

    internal static MacProcessHardeningStatus Apply()
    {
        if (Interlocked.Exchange(ref _applied, 1) != 0)
        {
            return LastStatus;
        }

        if (!OperatingSystem.IsMacOSVersionAtLeast(14))
        {
            throw new PlatformNotSupportedException("Keep Vault requires macOS 14 or newer.");
        }

        bool coreDumpsDisabled = DisableCoreDumps();
        bool restrictiveUmaskApplied = ApplyPrivateUmask();
        bool dynamicLoaderEnvironmentCleared = ClearDynamicLoaderEnvironment();
        bool debuggerDenied = DenyDebuggerAttachment();

        LastStatus = new MacProcessHardeningStatus(
            coreDumpsDisabled,
            debuggerDenied,
            restrictiveUmaskApplied,
            dynamicLoaderEnvironmentCleared);

        if (!LastStatus.AllRequiredApplied)
        {
            throw new InvalidOperationException(
                "The required macOS process hardening could not be applied. Keep Vault stopped before loading its user interface.");
        }

        return LastStatus;
    }

    private static bool DisableCoreDumps()
    {
        var limit = new Rlimit(0, 0);
        return setrlimit(RlimitCore, in limit) == 0;
    }

    private static bool ApplyPrivateUmask()
    {
        _ = umask(PrivateFilesUmask);
        return true;
    }

    private static bool ClearDynamicLoaderEnvironment()
    {
        bool success = true;
        foreach (string variable in DynamicLoaderVariables)
        {
            success &= unsetenv(variable) == 0;
        }

        return success && DynamicLoaderVariables.All(variable => Environment.GetEnvironmentVariable(variable) is null);
    }

    private static bool DenyDebuggerAttachment()
    {
        return ptrace(PtDenyAttach, 0, 0, 0) == 0;
    }

    [LibraryImport("libSystem.B.dylib", SetLastError = true)]
    private static partial int setrlimit(int resource, in Rlimit limit);

    [LibraryImport("libSystem.B.dylib")]
    private static partial uint umask(uint mask);

    [LibraryImport("libSystem.B.dylib", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int unsetenv(string name);

    [LibraryImport("libSystem.B.dylib", SetLastError = true)]
    private static partial int ptrace(int request, int processId, nint address, int data);

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct Rlimit(ulong Current, ulong Maximum);
}

internal sealed record MacProcessHardeningStatus(
    bool CoreDumpsDisabled,
    bool DebuggerDenied,
    bool RestrictiveUmaskApplied,
    bool DynamicLoaderEnvironmentCleared)
{
    internal bool AllRequiredApplied =>
        CoreDumpsDisabled
        && DebuggerDenied
        && RestrictiveUmaskApplied
        && DynamicLoaderEnvironmentCleared;
}
