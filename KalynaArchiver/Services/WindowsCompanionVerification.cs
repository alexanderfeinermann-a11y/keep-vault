using System.IO;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// The outcome of checking a companion application that ships with Keep Vault.
/// </summary>
/// <param name="Found">Whether a companion executable was located at all.</param>
/// <param name="Trusted">
/// Whether it carried a valid RSA-PSS/SHA-512 and ML-DSA-87 signature from the
/// pinned release keys. Always false when <paramref name="Found"/> is false.
/// </param>
/// <param name="Path">Where it was found, or null.</param>
/// <param name="Message">A sentence naming what was checked and what came of it.</param>
public sealed record CompanionVerificationResult(
    bool Found,
    bool Trusted,
    string? Path,
    string Message);

/// <summary>
/// Verifies the QR scanner that travels with Keep Vault.
/// </summary>
/// <remarks>
/// The scanner reads the QR codes off the printed key sheets, so it handles the
/// two secret factors. It is a separate application that shares no code with
/// Keep Vault and cannot check itself: an app that verifies its own signature
/// proves nothing to anyone who has already replaced it. Keep Vault checks it
/// instead, against the same six compiled key fingerprints it holds itself.
///
/// A failure here does not stop Keep Vault. The scanner is a separate program
/// and Keep Vault never loads its code; the honest response is to say so
/// loudly, not to refuse to archive anything.
///
/// The same arrangement as the macOS build's MacCompanionVerification, over the
/// Windows layout: an executable beside Keep Vault or in a QR-Scanner folder
/// next to it, with its detached hybrid signature as a sidecar.
/// </remarks>
internal static class WindowsCompanionVerification
{
    private const string ScannerExecutable = "QR-Scanner.exe";
    private const string ScannerDirectory = "QR-Scanner";

    /// <summary>
    /// Looks for the scanner beside Keep Vault and in its own subfolder, and
    /// verifies the first executable it finds.
    /// </summary>
    public static CompanionVerificationResult VerifyQrScanner()
    {
        string? executable = LocateScanner();
        if (executable is null)
        {
            return new CompanionVerificationResult(
                false,
                false,
                null,
                $"{ScannerExecutable} was not found beside Keep Vault or in a {ScannerDirectory} folder.");
        }

        try
        {
            HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
                ?? throw new InvalidOperationException("The compiled hybrid signing policy is unavailable.");

            string sidecar = executable + HybridSignatureService.SidecarExtension;
            if (!File.Exists(sidecar))
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    executable,
                    $"{ScannerExecutable} has no detached hybrid signature beside it; it is not the scanner this build signs.");
            }

            HybridSignatureVerificationResult signature = HybridSignatureService.VerifyFile(
                executable,
                sidecar,
                policy);
            if (!signature.IsTrusted || !signature.RsaPssValid || !signature.Mldsa87Valid)
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    executable,
                    $"{ScannerExecutable} failed its dual signature check: {signature.Message}");
            }

            return new CompanionVerificationResult(
                true,
                true,
                executable,
                $"{ScannerExecutable} carries a valid RSA-PSS/SHA-512 and ML-DSA-87 signature from the pinned keys.");
        }
        catch (Exception exception)
        {
            return new CompanionVerificationResult(
                true,
                false,
                executable,
                $"{ScannerExecutable} could not be checked: {exception.Message}");
        }
    }

    /// <summary>
    /// The scanner sits beside Keep Vault in the portable package, or in its
    /// own folder next to it. Both are checked, nearest first.
    /// </summary>
    /// <remarks>
    /// A reparse point is refused rather than followed: the whole value of this
    /// check is that it names the file that will actually run, and a junction
    /// pointing somewhere else would let a verified path describe an
    /// unverified program.
    /// </remarks>
    private static string? LocateScanner()
    {
        foreach (string directory in CandidateDirectories())
        {
            string candidate = Path.Combine(directory, ScannerExecutable);
            if (File.Exists(candidate) && (File.GetAttributes(candidate) & FileAttributes.ReparsePoint) == 0)
            {
                return Path.GetFullPath(candidate);
            }
        }

        return null;
    }

    private static IEnumerable<string> CandidateDirectories()
    {
        string root = Path.GetFullPath(AppContext.BaseDirectory);
        yield return root;
        yield return Path.Combine(root, ScannerDirectory);

        string? parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(root));
        if (!string.IsNullOrEmpty(parent))
        {
            yield return Path.Combine(parent, ScannerDirectory);
        }
    }
}
