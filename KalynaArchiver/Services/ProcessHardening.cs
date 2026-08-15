using System.Runtime.InteropServices;
using System.Threading;

namespace KalynaArchiver.Services;

internal static partial class ProcessHardening
{
    private const uint SemFailCriticalErrors = 0x0001;
    private const uint SemNoGpFaultErrorBox = 0x0002;
    private const uint SemNoOpenFileErrorBox = 0x8000;
    private const uint HardenedErrorMode = SemFailCriticalErrors | SemNoGpFaultErrorBox | SemNoOpenFileErrorBox;

    private const uint WerFaultReportingFlagNoHeap = 0x00000001;
    private const uint WerFaultReportingNoUi = 0x00000020;
    private const uint WerFaultReportingFlagNoHeapOnQueue = 0x00000040;
    private const uint WerFaultReportingDisableSnapshotCrash = 0x00000080;
    private const uint WerFaultReportingDisableSnapshotHang = 0x00000100;
    private const uint WerHardeningFlags =
        WerFaultReportingFlagNoHeap |
        WerFaultReportingNoUi |
        WerFaultReportingFlagNoHeapOnQueue |
        WerFaultReportingDisableSnapshotCrash |
        WerFaultReportingDisableSnapshotHang;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const uint ImageLoadPolicyHardened = 0x00000007;

    private static int _applied;

    public static ProcessHardeningStatus LastStatus { get; private set; } = new(false, false, false, false, false, false);

    public static ProcessHardeningStatus Apply()
    {
        if (Interlocked.Exchange(ref _applied, 1) != 0)
        {
            return LastStatus;
        }

        bool errorModeSet = TrySetErrorModes();
        bool werSet = TrySetWerFlags();
        bool strictHandleSet = TrySetMitigation(ProcessMitigationPolicy.ProcessStrictHandleCheckPolicy, 0x3);
        bool extensionPointsDisabled = TrySetMitigation(ProcessMitigationPolicy.ProcessExtensionPointDisablePolicy, 0x1);
        bool imageLoadPolicySet = TrySetMitigation(ProcessMitigationPolicy.ProcessImageLoadPolicy, ImageLoadPolicyHardened);
        bool dllSearchRestricted = TryRestrictDllSearch();
        LastStatus = new ProcessHardeningStatus(
            errorModeSet,
            werSet,
            strictHandleSet,
            extensionPointsDisabled,
            imageLoadPolicySet,
            dllSearchRestricted);
        return LastStatus;
    }

    private static bool TryRestrictDllSearch()
    {
        try
        {
            return SetDefaultDllDirectories(LoadLibrarySearchSystem32);
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetErrorModes()
    {
        try
        {
            _ = SetErrorMode(HardenedErrorMode);
            return SetThreadErrorMode(HardenedErrorMode, out _);
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetWerFlags()
    {
        try
        {
            return WerSetFlags(WerHardeningFlags) >= 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetMitigation(ProcessMitigationPolicy policy, uint flags)
    {
        try
        {
            return SetProcessMitigationPolicy(policy, ref flags, sizeof(uint));
        }
        catch
        {
            return false;
        }
    }

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint SetErrorMode(uint uMode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetThreadErrorMode(uint dwNewMode, out uint lpOldMode);

    [LibraryImport("wer.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WerSetFlags(uint dwFlags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessMitigationPolicy(ProcessMitigationPolicy mitigationPolicy, ref uint lpBuffer, nuint dwLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint directoryFlags);

    private enum ProcessMitigationPolicy
    {
        ProcessDEPPolicy,
        ProcessASLRPolicy,
        ProcessDynamicCodePolicy,
        ProcessStrictHandleCheckPolicy,
        ProcessSystemCallDisablePolicy,
        ProcessMitigationOptionsMask,
        ProcessExtensionPointDisablePolicy,
        ProcessControlFlowGuardPolicy,
        ProcessSignaturePolicy,
        ProcessFontDisablePolicy,
        ProcessImageLoadPolicy,
    }
}

internal sealed record ProcessHardeningStatus(
    bool ErrorModeSet,
    bool WerFlagsSet,
    bool StrictHandlePolicySet,
    bool ExtensionPointsDisabled,
    bool ImageLoadPolicySet,
    bool DllSearchRestricted);
