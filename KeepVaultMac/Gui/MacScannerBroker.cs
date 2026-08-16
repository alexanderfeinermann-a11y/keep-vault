using System.Diagnostics;
using System.Security.Cryptography;
using KalynaArchiver.Services;

namespace KalynaArchiver.Gui;

/// <summary>
/// Reads one printed key-sheet factor from the camera through the bundled
/// scanner helper.
/// </summary>
/// <remarks>
/// Typing 128 hexadecimal characters by hand, twice, is where a recovery
/// realistically goes wrong, so the key sheet's QR code can be read instead.
///
/// Camera access is confined to the helper rather than granted to the core.
/// The core holds the archive keys and runs for as long as the app is open;
/// letting it look through the camera for that whole time buys nothing and
/// widens what a flaw in it could reach. The helper exists only for the seconds
/// a scan takes.
///
/// The helper is verified before it is started, exactly like every other
/// executable this app runs, and what it returns is validated again here so
/// neither side depends on the other having done it.
/// </remarks>
internal static class MacScannerBroker
{
    private const string HelperRelativePath =
        "Library/Helpers/Keep Vault Scanner.app/Contents/MacOS/Keep Vault Scanner";

    /// <summary>
    /// A factor is 128 hexadecimal characters, so anything beyond a few hundred
    /// bytes is malformed. The ceiling keeps a broken helper from being read
    /// without limit.
    /// </summary>
    private const int MaxReplyCharacters = 4096;

    private static readonly TimeSpan ScanTimeout = TimeSpan.FromMinutes(5);

    internal sealed record ScanResult(bool Cancelled, string? Factor, string? Failure);

    private static string ResolveHelperPath()
    {
        string baseDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        string? contents = Path.GetDirectoryName(baseDirectory);
        if (contents is null || !string.Equals(Path.GetFileName(contents), "Contents", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The scanner helper is only available inside the application bundle.");
        }

        string executable = Path.Combine(contents, HelperRelativePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(executable) || File.ResolveLinkTarget(executable, returnFinalTarget: false) is not null)
        {
            throw new FileNotFoundException("The scanner helper is missing from the application bundle.", executable);
        }

        MacSignatureInfo signature = MacCodeSignature.Check(executable, nestedBundle: true);
        if (!IntegrityService.IsAcceptedSignatureState(signature.State))
        {
            throw new InvalidOperationException(
                $"The scanner helper failed Apple signature validation: {signature.Message}");
        }

        return executable;
    }

    internal static async Task<ScanResult> ScanFactorAsync(string title, CancellationToken cancellationToken)
    {
        string helper;
        try
        {
            helper = ResolveHelperPath();
        }
        catch (Exception exception) when (exception is InvalidOperationException or FileNotFoundException)
        {
            return new ScanResult(Cancelled: false, Factor: null, Failure: exception.Message);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = helper,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("scan-factor");
        startInfo.ArgumentList.Add(title);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ScanTimeout);

        Process? process = null;
        try
        {
            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The scanner helper could not be started.");
            string output = await process.StandardOutput.ReadToEndAsync(timeout.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);

            // Exit code 2 means the user closed the scanner window.
            if (process.ExitCode == 2)
            {
                return new ScanResult(Cancelled: true, Factor: null, Failure: null);
            }

            if (process.ExitCode != 0)
            {
                string error = await process.StandardError
                    .ReadToEndAsync(CancellationToken.None).ConfigureAwait(false);
                return new ScanResult(false, null, error.Trim());
            }

            if (output.Length > MaxReplyCharacters)
            {
                return new ScanResult(false, null, "Die Scanner-Antwort ist unplausibel groß.");
            }

            string factor = output.Trim();
            if (factor.Length != PasswordKeyService.GeneratedPasswordLength || !factor.All(Uri.IsHexDigit))
            {
                return new ScanResult(false, null, "Der gescannte Code ist kein gültiger Schlüsselfaktor.");
            }

            return new ScanResult(false, factor.ToUpperInvariant(), null);
        }
        catch (OperationCanceledException)
        {
            TryStop(process);
            return new ScanResult(Cancelled: true, Factor: null, Failure: null);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            TryStop(process);
            return new ScanResult(false, null, $"{exception.GetType().Name}: {exception.Message}");
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static void TryStop(Process? process)
    {
        try
        {
            if (process is { HasExited: false })
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException)
        {
            // The helper already exited; nothing to stop.
        }
    }
}
