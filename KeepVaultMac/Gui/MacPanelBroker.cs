using System.Diagnostics;
using System.Security.Cryptography;
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

    /// <summary>Path of the helper's app bundle, which is what LaunchServices opens.</summary>
    private static string ResolveHelperBundlePath()
    {
        string executable = ResolveHelperPath();
        string bundle = Path.GetFullPath(Path.Combine(executable, "..", "..", ".."));
        if (!string.Equals(Path.GetExtension(bundle), ".app", StringComparison.Ordinal) || !Directory.Exists(bundle))
        {
            throw new InvalidOperationException("The panel helper bundle could not be located.");
        }

        return bundle;
    }

    /// <summary>
    /// The directory in the shared application group where the helper leaves
    /// its answer. Created private to the user.
    /// </summary>
    private static string ResolveReplyDirectory()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string directory = Path.Combine(
            home,
            "Library",
            "Group Containers",
            "2T6K9PGS55.de.michael-feinermann.keep-vault",
            "PanelReplies");
        Directory.CreateDirectory(directory);
        File.SetUnixFileMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return directory;
    }

    /// <summary>
    /// Waits for the helper's reply, which appears only once the user has
    /// dismissed the panel — hence the generous ceiling.
    /// </summary>
    private static async Task<string> AwaitReplyAsync(string replyPath, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HelperTimeout);
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            if (File.Exists(replyPath))
            {
                var info = new FileInfo(replyPath);
                if (info.Length > MaxResponseBytes)
                {
                    throw new InvalidDataException("The panel helper returned an oversized reply.");
                }

                if (info.LinkTarget is not null)
                {
                    throw new InvalidDataException("The panel reply is a symbolic link.");
                }

                return await File.ReadAllTextAsync(replyPath, Encoding.UTF8, timeout.Token).ConfigureAwait(false);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(120), timeout.Token).ConfigureAwait(false);
        }
    }

    private static void TryDeleteReply(string replyPath)
    {
        try
        {
            File.Delete(replyPath);
            File.Delete(replyPath + ".partial");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A leftover reply is inert: it is named by a spent nonce and is
            // overwritten before the next request of the same name could exist.
        }
    }

    internal static async Task<IReadOnlyList<PanelSelection>> ShowAsync(
        PanelKind kind,
        string title,
        string suggestedName,
        CancellationToken cancellationToken)
    {
        string helper = ResolveHelperPath();
        string helperBundle = ResolveHelperBundlePath();

        // The helper is executable code inside the bundle, so it passes the same
        // Apple signature and Team ID gate as everything else this app runs.
        MacSignatureInfo signature = MacCodeSignature.Check(helper, nestedBundle: true);
        if (!IntegrityService.IsAcceptedSignatureState(signature.State))
        {
            throw new InvalidOperationException($"The panel helper failed Apple signature validation: {signature.Message}");
        }

        // The helper is started through LaunchServices rather than spawned. A
        // sandboxed process cannot create a child that establishes a sandbox of
        // its own: such a child hangs inside libsecinit before reaching main,
        // which is exactly what happened when this went through posix_spawn.
        // LaunchServices gives the helper the independent sandbox that lets it
        // raise a panel at all.
        //
        // That also removes the inherited pipe, so the answer comes back through
        // the application group both bundles share, in a file named by a nonce
        // this request generates. The nonce means a reply can only satisfy the
        // request that asked for it.
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        string replyPath = Path.Combine(ResolveReplyDirectory(), nonce);

        var startInfo = new ProcessStartInfo
        {
            FileName = "/usr/bin/open",
            UseShellExecute = false,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("-n");
        startInfo.ArgumentList.Add("-a");
        startInfo.ArgumentList.Add(helperBundle);
        startInfo.ArgumentList.Add("--args");
        startInfo.ArgumentList.Add(kind switch
        {
            PanelKind.OpenFile => "open-file",
            PanelKind.OpenFiles => "open-files",
            PanelKind.OpenFolder => "open-folder",
            PanelKind.SaveFile => "save-file",
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        });
        startInfo.ArgumentList.Add(nonce);
        startInfo.ArgumentList.Add(title);
        if (kind == PanelKind.SaveFile)
        {
            startInfo.ArgumentList.Add(Path.GetFileName(suggestedName));
        }

        string response;
        try
        {
            using (Process launcher = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The panel helper could not be started."))
            {
                await launcher.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                if (launcher.ExitCode != 0)
                {
                    string error = await launcher.StandardError.ReadToEndAsync(CancellationToken.None).ConfigureAwait(false);
                    throw new InvalidOperationException($"The panel helper could not be launched: {error.Trim()}");
                }
            }

            response = await AwaitReplyAsync(replyPath, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TryDeleteReply(replyPath);
        }

        string[] lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
        {
            throw new InvalidDataException("The panel helper returned an empty reply.");
        }

        if (string.Equals(lines[0], "CANCELLED", StringComparison.Ordinal))
        {
            return [];
        }

        if (!string.Equals(lines[0], "OK", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The panel helper reported a failure: {string.Join(' ', lines.Skip(1)).Trim()}");
        }

        var selections = new List<PanelSelection>();
        try
        {
            foreach (string line in lines.Skip(1))
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
