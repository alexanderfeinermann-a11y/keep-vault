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
    /// <summary>
    /// The helper sits beside the other native tools, under the same seal and
    /// the same dual signature.
    /// </summary>
    /// <remarks>
    /// It used to be a nested helper application under Contents/Library/Helpers,
    /// which is what the App Sandbox required. Dropping the sandbox made it an
    /// ordinary signed Mach-O next to zpaq and argon2, and it is verified the
    /// same way they are.
    /// </remarks>
    private const string HelperFileName = "keep-vault-scanner";

    /// <summary>
    /// A factor is 128 hexadecimal characters, so anything beyond a few hundred
    /// bytes is malformed. The ceiling keeps a broken helper from being read
    /// without limit.
    /// </summary>
    private const int MaxReplyCharacters = 4096;

    private static readonly TimeSpan ScanTimeout = TimeSpan.FromMinutes(5);

    internal sealed record ScanResult(bool Cancelled, string? Factor, string? Failure);

    /// <summary>
    /// Resolves the helper and returns a lease that holds it verified and open.
    /// </summary>
    /// <remarks>
    /// The helper is the component that sees the key factors in the clear, so
    /// it gets the full check every native tool gets: the SHA3-512 and
    /// Skein-1024 manifests plus both signatures of the hybrid pair, on top of
    /// Apple's. Apple's signature alone would rest entirely on RSA and ECDSA,
    /// which is exactly the assumption this app refuses to make.
    ///
    /// The lease keeps a descriptor on the verified file open for as long as the
    /// caller holds it, so the bytes that were checked stay reachable while the
    /// process is started.
    /// </remarks>
    private static TrustedNativeFileLease AcquireHelper()
    {
        string baseDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        string executable = Path.Combine(baseDirectory, "Native", HelperFileName);
        if (!File.Exists(executable) || File.ResolveLinkTarget(executable, returnFinalTarget: false) is not null)
        {
            throw new FileNotFoundException("The scanner helper is missing from the application bundle.", executable);
        }

        MacSignatureInfo signature = MacCodeSignature.Check(executable, nestedBundle: false);
        if (!IntegrityService.IsAcceptedSignatureState(signature.State))
        {
            throw new InvalidOperationException(
                $"The scanner helper failed Apple signature validation: {signature.Message}");
        }

        return NativeToolIntegrity.AcquireTrustedFile(executable);
    }

    internal static async Task<ScanResult> ScanFactorAsync(string title, CancellationToken cancellationToken)
    {
        TrustedNativeFileLease helperLease;
        try
        {
            helperLease = AcquireHelper();
        }
        catch (Exception exception) when (exception is InvalidOperationException or FileNotFoundException or IOException or UnauthorizedAccessException)
        {
            return new ScanResult(Cancelled: false, Factor: null, Failure: exception.Message);
        }

        using TrustedNativeFileLease scopedHelperLease = helperLease;
        string helper = scopedHelperLease.Path;

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
