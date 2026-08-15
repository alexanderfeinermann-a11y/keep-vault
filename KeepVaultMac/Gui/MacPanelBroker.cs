using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using KalynaArchiver.Services;

namespace KalynaArchiver.Gui;

/// <summary>
/// Raises open and save panels through the bundled helper application.
/// </summary>
/// <remarks>
/// macOS serves a panel only to a process that owns its sandbox. The core does
/// not: the launcher establishes the sandbox and replaces itself with the core,
/// which runs with com.apple.security.inherit so that the launcher can verify
/// it before any of its code runs. Keeping that order means the core can never
/// raise a panel itself, so the panel is delegated to a helper bundle that the
/// system serves normally.
///
/// The helper returns security-scoped bookmarks rather than paths. A path alone
/// would be useless — the user's grant lives in the sandbox extension, not in
/// the name — so the bookmark is what actually carries access across the
/// process boundary, resolved here through the application group both bundles
/// declare.
///
/// The helper is verified before it is spawned, exactly like every other
/// executable this app runs.
/// </remarks>
internal static partial class MacPanelBroker
{
    private const string HelperRelativePath =
        "Library/Helpers/Keep Vault Panels.app/Contents/MacOS/Keep Vault Panels";

    /// <summary>NSURLBookmarkResolutionWithSecurityScope.</summary>
    private const nuint ResolveWithSecurityScope = 1 << 10;

    /// <summary>
    /// Caps the helper's response. A panel cannot realistically return more,
    /// and a fixed ceiling keeps a malformed response from being read without
    /// limit.
    /// </summary>
    private const int MaxResponseBytes = 4 * 1024 * 1024;

    private static readonly TimeSpan HelperTimeout = TimeSpan.FromMinutes(10);

    internal enum PanelKind
    {
        OpenFile,
        OpenFiles,
        OpenFolder,
        SaveFile,
    }

    internal sealed record PanelSelection(string Path, MacSecurityScopedResourceLease Lease) : IDisposable
    {
        public void Dispose() => Lease.Dispose();
    }

    /// <summary>
    /// Resolves the helper inside this app bundle. The path is derived from the
    /// running image rather than searched for, so nothing outside the sealed
    /// bundle can be started in its place.
    /// </summary>
    private static string ResolveHelperPath()
    {
        string baseDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        string? contents = Path.GetDirectoryName(baseDirectory);
        if (contents is null || !string.Equals(Path.GetFileName(contents), "Contents", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The panel helper is only available inside the application bundle.");
        }

        string helper = Path.Combine(contents, HelperRelativePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(helper) || File.ResolveLinkTarget(helper, returnFinalTarget: false) is not null)
        {
            throw new FileNotFoundException("The panel helper is missing from the application bundle.", helper);
        }

        return helper;
    }

    internal static async Task<IReadOnlyList<PanelSelection>> ShowAsync(
        PanelKind kind,
        string title,
        string suggestedName,
        CancellationToken cancellationToken)
    {
        string helper = ResolveHelperPath();

        // The helper is executable code inside the bundle, so it passes the same
        // Apple signature and Team ID gate as everything else this app runs.
        MacSignatureInfo signature = MacCodeSignature.Check(helper, nestedBundle: true);
        if (!IntegrityService.IsAcceptedSignatureState(signature.State))
        {
            throw new InvalidOperationException($"The panel helper failed Apple signature validation: {signature.Message}");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = helper,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add(kind switch
        {
            PanelKind.OpenFile => "open-file",
            PanelKind.OpenFiles => "open-files",
            PanelKind.OpenFolder => "open-folder",
            PanelKind.SaveFile => "save-file",
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        });
        startInfo.ArgumentList.Add(title);
        if (kind == PanelKind.SaveFile)
        {
            startInfo.ArgumentList.Add(Path.GetFileName(suggestedName));
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The panel helper could not be started.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HelperTimeout);

        string response;
        try
        {
            Task<string> readOutput = process.StandardOutput.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            response = await readOutput.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }

        if (response.Length > MaxResponseBytes)
        {
            throw new InvalidDataException("The panel helper returned an oversized response.");
        }

        // Exit code 2 means the user cancelled, which is not a failure.
        if (process.ExitCode == 2)
        {
            return [];
        }

        if (process.ExitCode != 0)
        {
            string error = await process.StandardError.ReadToEndAsync(CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException($"The panel helper failed: {error.Trim()}");
        }

        var selections = new List<PanelSelection>();
        try
        {
            foreach (string line in response.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                selections.Add(ResolveBookmark(line));
            }
        }
        catch
        {
            foreach (PanelSelection selection in selections)
            {
                selection.Dispose();
            }

            throw;
        }

        return selections;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException)
        {
            // The helper already exited; nothing to stop.
        }
    }

    private static PanelSelection ResolveBookmark(string base64)
    {
        byte[] bookmark;
        try
        {
            bookmark = Convert.FromBase64String(base64);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The panel helper returned a malformed bookmark.", exception);
        }

        nint data = 0;
        nint url;
        nint stale = 0;
        nint error = 0;
        try
        {
            unsafe
            {
                fixed (byte* bytes = bookmark)
                {
                    data = ObjcMessageSendDataWithBytes(
                        ObjcGetClass("NSData"),
                        SelRegisterName("dataWithBytes:length:"),
                        (nint)bytes,
                        (nuint)bookmark.Length);
                }
            }

            if (data == 0)
            {
                throw new InvalidDataException("Foundation could not wrap the bookmark data.");
            }

            unsafe
            {
                nint staleFlag = 0;
                nint errorObject = 0;
                url = ObjcMessageSendResolveBookmark(
                    ObjcGetClass("NSURL"),
                    SelRegisterName("URLByResolvingBookmarkData:options:relativeToURL:bookmarkDataIsStale:error:"),
                    data,
                    ResolveWithSecurityScope,
                    0,
                    (nint)(&staleFlag),
                    (nint)(&errorObject));
                stale = staleFlag;
                error = errorObject;
            }

            if (url == 0)
            {
                throw new UnauthorizedAccessException(
                    "macOS refused to resolve the security-scoped bookmark returned by the panel helper.");
            }

            // A stale bookmark still resolves, but the grant it carries can no
            // longer be trusted to name what the user picked.
            if (stale != 0)
            {
                throw new UnauthorizedAccessException("The panel helper returned a stale security-scoped bookmark.");
            }

            MacSecurityScopedResourceLease lease = MacSecurityScopedResourceLease.AdoptResolvedUrl(url);
            try
            {
                string path = ReadUrlPath(url);
                return new PanelSelection(path, lease);
            }
            catch
            {
                lease.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperationsZero(bookmark);
        }
    }

    private static void CryptographicOperationsZero(byte[] value)
        => System.Security.Cryptography.CryptographicOperations.ZeroMemory(value);

    private static string ReadUrlPath(nint url)
    {
        nint pathString = ObjcMessageSendPtr(url, SelRegisterName("path"));
        if (pathString == 0)
        {
            throw new InvalidDataException("The resolved bookmark does not expose a file system path.");
        }

        nint utf8 = ObjcMessageSendPtr(pathString, SelRegisterName("UTF8String"));
        if (utf8 == 0)
        {
            throw new InvalidDataException("The resolved bookmark path could not be read.");
        }

        return Marshal.PtrToStringUTF8(utf8)
            ?? throw new InvalidDataException("The resolved bookmark path is not valid UTF-8.");
    }

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_getClass", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint ObjcGetClass(string name);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "sel_registerName", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint SelRegisterName(string name);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    private static partial nint ObjcMessageSendPtr(nint receiver, nint selector);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    private static partial nint ObjcMessageSendDataWithBytes(nint receiver, nint selector, nint bytes, nuint length);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    private static partial nint ObjcMessageSendResolveBookmark(
        nint receiver,
        nint selector,
        nint bookmarkData,
        nuint options,
        nint relativeTo,
        nint isStale,
        nint error);
}
