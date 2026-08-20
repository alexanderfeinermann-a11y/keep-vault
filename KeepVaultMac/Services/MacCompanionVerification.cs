using System.Runtime.Versioning;
using System.Security.Cryptography;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// The outcome of checking a companion application that ships with Keep Vault.
/// </summary>
/// <param name="Found">Whether a companion bundle was located at all.</param>
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
/// two secret factors. It is a separate, sandboxed application that shares no
/// code with Keep Vault and cannot check itself: an app that verifies its own
/// signature proves nothing to anyone who has already replaced it. Keep Vault
/// checks it instead, against the same six compiled key fingerprints it holds
/// itself.
///
/// The scanner's sidecars sit beside its bundle rather than inside it. Apple's
/// seal covers Contents/Resources, so a signature file added there afterwards
/// would invalidate the very seal it lives under — the same reason Keep Vault's
/// own launcher signature is published next to the app.
///
/// A failure here does not stop Keep Vault. The scanner is a separate program
/// and Keep Vault never loads its code; the honest response is to say so
/// loudly, not to refuse to archive anything.
/// </remarks>
[SupportedOSPlatform("macos14.0")]
internal static class MacCompanionVerification
{
    private const string ScannerBundleName = "QR-Scanner.app";
    private const string ScannerExecutable = "Contents/MacOS/QR-Scanner";

    /// <summary>
    /// Looks for the scanner beside Keep Vault and in /Applications, and
    /// verifies the first bundle it finds.
    /// </summary>
    public static CompanionVerificationResult VerifyQrScanner()
    {
        string? bundle = LocateScanner();
        if (bundle is null)
        {
            return new CompanionVerificationResult(
                false,
                false,
                null,
                "QR-Scanner.app was not found beside Keep Vault or in /Applications.");
        }

        try
        {
            HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
                ?? throw new InvalidOperationException("The compiled hybrid signing policy is unavailable.");

            string executable = Path.Combine(
                bundle,
                ScannerExecutable.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(executable))
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    $"QR-Scanner.app has no {ScannerExecutable}; it is not the scanner this build signs.");
            }

            HybridSignatureVerificationResult signature = HybridSignatureService.VerifyFile(
                executable,
                bundle + HybridSignatureService.SidecarExtension,
                policy);
            if (!signature.IsTrusted || !signature.RsaPssValid || !signature.Mldsa87Valid)
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    $"QR-Scanner.app failed its dual signature check: {signature.Message}");
            }

            // The hybrid signature binds a SHA-512 digest. Everything else in
            // the package is additionally held to the SHA3-512 and Skein-1024
            // dual manifest, and the scanner ships those files too -- checking
            // only the signature here would have left one component measured by
            // fewer hashes than the rest, for no reason other than that this
            // check was written later.
            string? manifestFailure = VerifyDualManifest(bundle, executable, policy);
            if (manifestFailure is not null)
            {
                return new CompanionVerificationResult(true, false, bundle, manifestFailure);
            }

            return new CompanionVerificationResult(
                true,
                true,
                bundle,
                "QR-Scanner.app matches its SHA3-512/Skein-1024 manifest and carries a valid "
                + "RSA-PSS/SHA-512 and ML-DSA-87 signature from the pinned keys.");
        }
        catch (Exception exception)
        {
            return new CompanionVerificationResult(
                true,
                false,
                bundle,
                $"QR-Scanner.app could not be checked: {exception.Message}");
        }
    }

    /// <summary>
    /// Holds the companion to the same SHA3-512 and Skein-1024 dual manifest as
    /// every other artifact, and requires both manifests to be signed by the
    /// pinned keys themselves.
    /// </summary>
    /// <remarks>
    /// Returns null when everything matches, otherwise the sentence to report.
    /// An unsigned manifest is worth nothing: whoever replaced the executable
    /// would simply write the new digests next to it.
    /// </remarks>
    private static string? VerifyDualManifest(
        string bundle,
        string executable,
        HybridSignaturePolicy policy)
    {
        const int Sha3HexLength = 128;
        const int SkeinHexLength = 256;

        foreach ((string suffix, int hexLength, string algorithm) in new[]
        {
            (".sha3", Sha3HexLength, "SHA3-512"),
            (".skein", SkeinHexLength, "Skein-1024"),
        })
        {
            string manifestPath = bundle + suffix;
            if (!File.Exists(manifestPath))
            {
                return $"QR-Scanner.app has no {algorithm} manifest ({Path.GetFileName(manifestPath)}).";
            }

            HybridSignatureVerificationResult manifestSignature = HybridSignatureService.VerifyFile(
                manifestPath,
                manifestPath + HybridSignatureService.SidecarExtension,
                policy);
            if (!manifestSignature.IsTrusted
                || !manifestSignature.RsaPssValid
                || !manifestSignature.Mldsa87Valid)
            {
                return $"The {algorithm} manifest of QR-Scanner.app is not signed by the pinned keys: "
                    + manifestSignature.Message;
            }

            string expected = new(File.ReadAllText(manifestPath)
                .Where(character => !char.IsWhiteSpace(character))
                .ToArray());
            if (expected.Length != hexLength || expected.Any(character => !Uri.IsHexDigit(character)))
            {
                return $"The {algorithm} manifest of QR-Scanner.app is not {hexLength} hexadecimal characters.";
            }

            byte[] actual = suffix == ".sha3"
                ? Sha3_512Compat.HashData(File.ReadAllBytes(executable))
                : Skein1024Digest.HashData(File.ReadAllBytes(executable));
            byte[] expectedBytes = Convert.FromHexString(expected);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actual, expectedBytes))
                {
                    return $"QR-Scanner.app does not match its {algorithm} manifest.";
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
                CryptographicOperations.ZeroMemory(expectedBytes);
            }
        }

        return null;
    }

    /// <summary>
    /// The scanner sits beside Keep Vault in the portable package and in
    /// /Applications once installed. Both are checked, nearest first.
    /// </summary>
    private static string? LocateScanner()
    {
        foreach (string directory in CandidateDirectories())
        {
            string candidate = Path.Combine(directory, ScannerBundleName);
            if (Directory.Exists(candidate) && new DirectoryInfo(candidate).LinkTarget is null)
            {
                return Path.GetFullPath(candidate);
            }
        }

        return null;
    }

    private static IEnumerable<string> CandidateDirectories()
    {
        // The directory the bundle sits in: Contents/MacOS/<binary> up to the
        // bundle, then one more to its parent.
        string? bundleParent = Path.GetDirectoryName(
            Path.GetDirectoryName(
                Path.GetDirectoryName(
                    Path.GetDirectoryName(Environment.ProcessPath))));
        if (!string.IsNullOrEmpty(bundleParent))
        {
            yield return bundleParent;
        }

        yield return "/Applications";
    }
}
