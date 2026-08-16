using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
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
    /// The scanner is a nested application, not a plain tool.
    /// </summary>
    /// <remarks>
    /// A camera prompt has to name who is asking, and only a bundle has a name.
    /// As a bare executable spawned by this app the request was attributed to
    /// Keep Vault, which macOS cannot resolve to the bundle — the bundle's main
    /// executable is the launcher, while the process that runs is the core — so
    /// the camera was refused outright instead of being offered to the user.
    ///
    /// Do not flatten this back into Native/. It carries the same dual signature
    /// as every other executable here and is verified the same way; the nesting
    /// is what makes the permission grantable at all.
    /// </remarks>
    private const string HelperRelativePath =
        "Library/Helpers/Keep Vault Scanner.app/Contents/MacOS/Keep Vault Scanner";

    private const string HelperBundleRelativePath = "Library/Helpers/Keep Vault Scanner.app";

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
        string helperBundle = Path.Combine(
            Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory)))!,
            HelperBundleRelativePath.Replace('/', Path.DirectorySeparatorChar));

        // A private directory only this user can enter, holding the socket the
        // helper answers on. The factor therefore never touches the file system.
        string replyDirectory = Directory.CreateTempSubdirectory("keep-vault-scan-").FullName;
        File.SetUnixFileMode(
            replyDirectory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string socketPath = Path.Combine(replyDirectory, "reply.sock");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ScanTimeout);

        Process? process = null;
        try
        {
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(socketPath));
            listener.Listen(1);

            // Started through LaunchServices, not spawned. That is the whole
            // point of the nested bundle: a spawned helper is answered for by
            // this app, which macOS cannot resolve to a name, so it refused the
            // camera outright rather than asking. Opened as an application the
            // helper answers for itself and appears under Privacy by name.
            var startInfo = new ProcessStartInfo
            {
                FileName = "/usr/bin/open",
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            startInfo.ArgumentList.Add("-a");
            startInfo.ArgumentList.Add(helperBundle);
            startInfo.ArgumentList.Add("--args");
            startInfo.ArgumentList.Add("scan-factor");
            startInfo.ArgumentList.Add(title);
            startInfo.ArgumentList.Add(socketPath);

            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The scanner helper could not be started.");
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                string launchError = await process.StandardError
                    .ReadToEndAsync(CancellationToken.None).ConfigureAwait(false);
                return new ScanResult(false, null, launchError.Trim().Length > 0
                    ? launchError.Trim()
                    : "Der Scanner konnte nicht gestartet werden.");
            }

            // The helper connects before it touches the camera, so this both
            // proves it started and gives the only handle there is on it: it was
            // opened as an application, and the process actually started here
            // was `open`, which is already gone. Dropping this connection is how
            // a cancelled scan reaches the helper and releases the camera.
            using Socket reply = await AcceptOrExplainAsync(listener, replyDirectory, timeout.Token)
                .ConfigureAwait(false);
            byte[] buffer = new byte[MaxReplyCharacters];
            int filled = 0;
            while (filled < buffer.Length)
            {
                int read = await reply
                    .ReceiveAsync(buffer.AsMemory(filled), SocketFlags.None, timeout.Token)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                filled += read;
            }

            string output;
            try
            {
                output = Encoding.ASCII.GetString(buffer, 0, filled).Trim();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }

            if (output.Length == 0)
            {
                // The helper hung up without sending anything. It connects
                // before it touches the camera, so this is the shape every
                // failure after that point takes: the reason it left is in the
                // file beside the socket, and reporting "invalid code" instead
                // would send the user looking at their key sheet.
                string reason = ReadFailure(replyDirectory);
                return reason.Length > 0
                    ? new ScanResult(false, null, reason)
                    : new ScanResult(Cancelled: true, Factor: null, Failure: null);
            }

            if (output.Length != PasswordKeyService.GeneratedPasswordLength || !output.All(Uri.IsHexDigit))
            {
                return new ScanResult(false, null, "Der gescannte Code ist kein gültiger Schlüsselfaktor.");
            }

            return new ScanResult(false, output.ToUpperInvariant(), null);
        }
        catch (OperationCanceledException)
        {
            // The listener and any accepted connection are disposed on the way
            // out, which is what tells the helper to stop.
            return new ScanResult(Cancelled: true, Factor: null, Failure: null);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new ScanResult(false, null, $"{exception.GetType().Name}: {exception.Message}");
        }
        finally
        {
            process?.Dispose();
            try
            {
                Directory.Delete(replyDirectory, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static string ReadFailure(string replyDirectory)
    {
        string failurePath = Path.Combine(replyDirectory, "failure.txt");
        try
        {
            return File.Exists(failurePath) ? File.ReadAllText(failurePath).Trim() : string.Empty;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Waits for the helper, or explains why it never answered.
    /// </summary>
    /// <remarks>
    /// The helper is opened as an application, so nothing it writes to stderr
    /// reaches this process. When it fails before connecting it leaves the
    /// reason beside the socket; without this the user would only ever see the
    /// scan time out.
    /// </remarks>
    private static async Task<Socket> AcceptOrExplainAsync(
        Socket listener,
        string replyDirectory,
        CancellationToken cancellationToken)
    {
        string failurePath = Path.Combine(replyDirectory, "failure.txt");
        Task<Socket> accept = listener.AcceptAsync(cancellationToken).AsTask();
        while (true)
        {
            Task finished = await Task.WhenAny(accept, Task.Delay(250, cancellationToken))
                .ConfigureAwait(false);
            if (finished == accept)
            {
                return await accept.ConfigureAwait(false);
            }

            if (File.Exists(failurePath))
            {
                string reason = (await File.ReadAllTextAsync(failurePath, cancellationToken)
                    .ConfigureAwait(false)).Trim();
                throw new InvalidOperationException(reason.Length > 0
                    ? reason
                    : "Der Scanner wurde ohne Angabe eines Grundes beendet.");
            }
        }
    }

}
