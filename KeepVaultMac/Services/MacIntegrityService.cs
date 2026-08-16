using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

public sealed class IntegrityService : IDisposable
{
    private const int MaxManifestBytes = 4096;
    private readonly object _leaseGate = new();
    private List<FileStream> _applicationLeases = [];
    private bool _disposed;

    public async Task<IntegrityStatus> CheckSelfAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("Der Programmpfad ist unbekannt.");
        var componentPaths = new List<string> { executable };
        foreach (string logicalName in NativeToolIntegrity.RequiredLogicalToolNames)
        {
            string? resolved = NativeToolIntegrity.ResolveKnownTool(logicalName);
            if (resolved is not null)
            {
                componentPaths.Add(resolved);
            }
        }

        var statuses = new List<ToolIntegrityStatus>();
        var candidateLeases = new List<FileStream>();
        bool transferred = false;
        try
        {
            foreach (string path in componentPaths.Select(Path.GetFullPath).Distinct(StringComparer.Ordinal))
            {
                FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
                candidateLeases.Add(stream);
                statuses.Add(await CheckFileAsync(stream, path, requireManifest: true, cancellationToken).ConfigureAwait(false));
            }

            foreach (string logicalName in NativeToolIntegrity.RequiredLogicalToolNames)
            {
                if (NativeToolIntegrity.ResolveKnownTool(logicalName) is null)
                {
                    statuses.Add(ToolIntegrityStatus.Missing(logicalName));
                }
            }

            ToolIntegrityStatus main = statuses.First(status =>
                string.Equals(Path.GetFullPath(status.FilePath), Path.GetFullPath(executable), StringComparison.Ordinal));
            bool hashes = statuses.Count == NativeToolIntegrity.RequiredLogicalToolNames.Count + 1
                && statuses.All(status => status.HashMatches);
            bool hybrid = statuses.All(status => status.HybridSignatureMatches);
            bool signatures = statuses.All(status => IsAcceptedSignatureState(status.SignatureState));
            bool signerPolicy = SigningTrustPolicy.IsConfigured && hybrid;
            string message = !hashes
                ? "WARNUNG: SHA3-512-/Skein-1024-Programmintegrität verletzt oder Artefakt fehlt."
                : !hybrid
                    ? "WARNUNG: Hybride RSA-PSS-/ML-DSA-87-Signaturprüfung fehlgeschlagen."
                    : !signatures
                        ? "WARNUNG: Apple-Code-Signatur oder fest gebundene Team-ID ist ungültig."
                        : !signerPolicy
                            ? "WARNUNG: Die fest eingebundene hybride Signierrichtlinie ist unvollständig."
                            : "Integritätsprüfung bestanden.";

            var result = new IntegrityStatus(
                main.ActualSha3_512 ?? string.Empty,
                main.ExpectedSha3_512,
                main.ActualSkein1024 ?? string.Empty,
                main.ExpectedSkein1024,
                message,
                hashes,
                hybrid,
                signatures ? SignatureState.Trusted : SignatureState.PresentButUntrustedOrInvalid,
                signerPolicy,
                statuses);
            if (result.IsTrusted)
            {
                List<FileStream> previous;
                lock (_leaseGate)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);
                    previous = _applicationLeases;
                    _applicationLeases = candidateLeases;
                    transferred = true;
                }

                DisposeStreams(previous);
            }

            return result;
        }
        finally
        {
            if (!transferred)
            {
                DisposeStreams(candidateLeases);
            }
        }
    }

    public async Task<IReadOnlyList<ToolIntegrityStatus>> CheckNativeToolsAsync(CancellationToken cancellationToken)
    {
        var statuses = new List<ToolIntegrityStatus>(NativeToolIntegrity.RequiredLogicalToolNames.Count);
        foreach (string logicalName in NativeToolIntegrity.RequiredLogicalToolNames)
        {
            string? path = NativeToolIntegrity.ResolveKnownTool(logicalName);
            statuses.Add(path is null
                ? ToolIntegrityStatus.Missing(logicalName)
                : await CheckFileAsync(path, requireManifest: true, cancellationToken).ConfigureAwait(false));
        }

        return statuses;
    }

    internal static async Task<ToolIntegrityStatus> CheckFileAsync(string path, bool requireManifest, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return ToolIntegrityStatus.Missing(fullPath);
        }

        await using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
        return await CheckFileAsync(stream, fullPath, requireManifest, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<ToolIntegrityStatus> CheckFileAsync(
        FileStream lockedStream,
        string path,
        bool requireManifest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lockedStream);
        string canonical = NativePathResolver.RequireCanonicalFilePath(lockedStream.SafeFileHandle, path, "Integrity-check");
        lockedStream.Position = 0;
        (byte[] sha3, byte[] skein, byte[] sha512, long length) = await HashStreamWithSha512Async(lockedStream, cancellationToken).ConfigureAwait(false);
        return BuildStatus(canonical, lockedStream, sha3, skein, sha512, length, requireManifest);
    }

    internal static ToolIntegrityStatus CheckFile(FileStream lockedStream, string path, bool requireManifest)
    {
        ArgumentNullException.ThrowIfNull(lockedStream);
        string canonical = NativePathResolver.RequireCanonicalFilePath(lockedStream.SafeFileHandle, path, "Integrity-check");
        lockedStream.Position = 0;
        (byte[] sha3, byte[] skein, byte[] sha512, long length) = HashStreamWithSha512(lockedStream);
        return BuildStatus(canonical, lockedStream, sha3, skein, sha512, length, requireManifest);
    }

    internal static ToolIntegrityStatus CheckFile(string path, bool requireManifest)
    {
        using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
        return CheckFile(stream, path, requireManifest);
    }

    private static ToolIntegrityStatus BuildStatus(
        string path,
        FileStream lockedStream,
        byte[] sha3,
        byte[] skein,
        byte[] sha512,
        long length,
        bool requireManifest)
    {
        try
        {
            string sidecarBase = ResolveSidecarBasePath(path);
            string? sha3Text = ReadManifest(sidecarBase + ".sha3");
            string? skeinText = ReadManifest(sidecarBase + ".skein");
            string actualSha3 = Convert.ToHexString(sha3);
            string actualSkein = Convert.ToHexString(skein);
            string actualSha512 = Convert.ToHexString(sha512);
            bool manifestsPresent = sha3Text is not null && skeinText is not null;
            bool hashesMatch = false;
            string? expectedSha3 = null;
            string? expectedSkein = null;
            string manifestMessage;
            try
            {
                if (manifestsPresent)
                {
                    expectedSha3 = NormalizeHex(sha3Text!, 128, "SHA3-512");
                    expectedSkein = NormalizeHex(skeinText!, 256, "Skein-1024");
                    byte[] expectedSha3Bytes = Convert.FromHexString(expectedSha3);
                    byte[] expectedSkeinBytes = Convert.FromHexString(expectedSkein);
                    try
                    {
                        hashesMatch = CryptographicOperations.FixedTimeEquals(sha3, expectedSha3Bytes)
                            & CryptographicOperations.FixedTimeEquals(skein, expectedSkeinBytes);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(expectedSha3Bytes);
                        CryptographicOperations.ZeroMemory(expectedSkeinBytes);
                    }
                }

                manifestMessage = !manifestsPresent
                    ? "SHA3-512/Skein-1024 dual manifest missing; file is blocked."
                    : hashesMatch
                        ? "SHA3-512 and Skein-1024 manifests match."
                        : "SHA3-512/Skein-1024 dual manifest mismatch; file is blocked.";
            }
            catch (FormatException ex)
            {
                manifestMessage = $"Invalid dual manifest: {ex.Message}";
            }

            HybridArtifactStatus hybrid = VerifyHybridArtifacts(path, length, sha512, requireManifest);
            MacSignatureInfo signature = MacCodeSignature.Check(path);
            MacSafeFileSystem.RequirePathStillNamesHandle(lockedStream.SafeFileHandle, path);
            return new ToolIntegrityStatus(
                path,
                actualSha3,
                expectedSha3,
                actualSkein,
                expectedSkein,
                actualSha512,
                hashesMatch,
                hybrid.IsTrusted,
                hybrid.Message,
                signature.State,
                signature.TeamIdentifier,
                null,
                null,
                null,
                null,
                signature.Message,
                manifestMessage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
            CryptographicOperations.ZeroMemory(sha512);
        }
    }

    private static HybridArtifactStatus VerifyHybridArtifacts(
        string path,
        long length,
        byte[] sha512,
        bool requireManifests)
    {
        HybridSignaturePolicy? policy = SigningTrustPolicy.HybridPolicy;
        if (policy is null)
        {
            return new HybridArtifactStatus(false, "Compiled ML-DSA-87 verification policy is missing or invalid.");
        }

        string sidecarBase = ResolveSidecarBasePath(path);
        HybridSignatureVerificationResult target = HybridSignatureService.VerifyDigest(
            length,
            sha512,
            sidecarBase + HybridSignatureService.SidecarExtension,
            policy);
        if (!target.IsTrusted)
        {
            return new HybridArtifactStatus(false, target.Message);
        }

        if (!requireManifests)
        {
            return new HybridArtifactStatus(true, target.Message);
        }

        string sha3Path = sidecarBase + ".sha3";
        string skeinPath = sidecarBase + ".skein";
        HybridSignatureVerificationResult sha3Result = File.Exists(sha3Path)
            ? HybridSignatureService.VerifyFile(sha3Path, sha3Path + HybridSignatureService.SidecarExtension, policy)
            : HybridSignatureVerificationResult.Invalid("SHA3-512 manifest is missing.");
        HybridSignatureVerificationResult skeinResult = File.Exists(skeinPath)
            ? HybridSignatureService.VerifyFile(skeinPath, skeinPath + HybridSignatureService.SidecarExtension, policy)
            : HybridSignatureVerificationResult.Invalid("Skein-1024 manifest is missing.");
        bool trusted = target.IsTrusted & sha3Result.IsTrusted & skeinResult.IsTrusted;
        return trusted
            ? new HybridArtifactStatus(true, "Target and both hash manifests have valid RSA-PSS/SHA-512 and ML-DSA-87 signatures.")
            : new HybridArtifactStatus(false, $"Hybrid signature failure: target={target.Message}; SHA3={sha3Result.Message}; Skein={skeinResult.Message}");
    }

    private const string HybridSignatureDirectoryName = "HybridSignatures";

    /// <summary>
    /// Maps a sealed binary to the base path of its detached hash and hybrid
    /// signature sidecars.
    /// </summary>
    /// <remarks>
    /// Apple's bundle format reserves Contents/MacOS for Mach-O executables:
    /// codesign treats every other file there as an unsigned nested code
    /// object and refuses to seal the bundle. The sidecars therefore live in
    /// Contents/Resources/HybridSignatures, mirroring the directory layout
    /// under Contents/MacOS. That location is additionally covered by the
    /// bundle's own CodeResources seal, so tampering with a manifest now
    /// breaks the Apple signature as well as the hybrid one.
    /// Outside a real app bundle — notably the private re-verification
    /// snapshot in a temporary directory — sidecars stay adjacent to the file.
    /// </remarks>
    internal static string ResolveSidecarBasePath(string path)
    {
        string full = Path.GetFullPath(path);
        return TryGetSealedBundleLayout(full, out string contents, out string relative)
            ? Path.Combine(contents, "Resources", HybridSignatureDirectoryName, relative)
            : full;
    }

    /// <summary>
    /// Determines whether <paramref name="path"/> lies under an app bundle's
    /// Contents/MacOS directory, reporting that bundle's Contents directory and
    /// the path relative to Contents/MacOS.
    /// </summary>
    /// <remarks>
    /// The decision is a property of where the file sits, not of the running
    /// process, so a verifier inspecting a bundle other than its own reaches the
    /// same answer the app itself does.
    /// </remarks>
    /// <summary>
    /// Recognises a helper application nested inside another bundle and returns
    /// the outer bundle's Contents directory.
    /// </summary>
    private static bool TryGetOuterHelperLayout(string nestedContents, out string outerContents, out string helperName)
    {
        outerContents = string.Empty;
        helperName = string.Empty;

        string? nestedApp = Path.GetDirectoryName(nestedContents);
        string? helpers = nestedApp is null ? null : Path.GetDirectoryName(nestedApp);
        string? library = helpers is null ? null : Path.GetDirectoryName(helpers);
        string? candidate = library is null ? null : Path.GetDirectoryName(library);
        if (nestedApp is null || helpers is null || library is null || candidate is null
            || !Path.GetFileName(nestedApp).EndsWith(".app", StringComparison.Ordinal)
            || !string.Equals(Path.GetFileName(helpers), "Helpers", StringComparison.Ordinal)
            || !string.Equals(Path.GetFileName(library), "Library", StringComparison.Ordinal)
            || !string.Equals(Path.GetFileName(candidate), "Contents", StringComparison.Ordinal))
        {
            return false;
        }

        outerContents = candidate;
        helperName = Path.GetFileNameWithoutExtension(Path.GetFileName(nestedApp));
        return true;
    }

    internal static bool TryGetSealedBundleLayout(string path, out string contents, out string relative)
    {
        string full = Path.GetFullPath(path);
        for (string? directory = Path.GetDirectoryName(full);
            directory is not null;
            directory = Path.GetDirectoryName(directory))
        {
            if (!string.Equals(Path.GetFileName(directory), "MacOS", StringComparison.Ordinal))
            {
                continue;
            }

            string? parent = Path.GetDirectoryName(directory);
            if (parent is null || !string.Equals(Path.GetFileName(parent), "Contents", StringComparison.Ordinal))
            {
                continue;
            }

            relative = full[(Path.TrimEndingDirectorySeparator(directory).Length + 1)..];

            // A helper application nested under Contents/Library/Helpers is
            // sealed as its own bundle, so its detached signatures cannot live
            // inside it: adding a file after sealing invalidates that seal. They
            // belong to the outer bundle instead, under a directory named
            // without an ".app" suffix so codesign does not mistake it for yet
            // another nested bundle.
            if (TryGetOuterHelperLayout(parent, out string outerContents, out string helperName))
            {
                contents = outerContents;
                relative = Path.Combine("Helpers", helperName, relative);
                return true;
            }

            contents = parent;
            return true;
        }

        contents = string.Empty;
        relative = string.Empty;
        return false;
    }

    private static string? ReadManifest(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
        if (stream.Length is <= 0 or > MaxManifestBytes)
        {
            throw new InvalidDataException($"Integrity manifest has an invalid length: {Path.GetFileName(path)}");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        try
        {
            stream.ReadExactly(bytes);
            return Encoding.ASCII.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string NormalizeHex(string value, int expectedLength, string algorithm)
    {
        string normalized = new(value.Where(character => !char.IsWhiteSpace(character)).ToArray());
        if (normalized.Length != expectedLength || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new FormatException($"{algorithm} expected {expectedLength} hexadecimal characters.");
        }

        return normalized.ToUpperInvariant();
    }

    internal static async Task<(byte[] Sha3, byte[] Skein)> HashStreamAsync(Stream stream, CancellationToken cancellationToken)
    {
        (byte[] sha3, byte[] skein, byte[] sha512, _) = await HashStreamWithSha512Async(stream, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(sha512);
        return (sha3, skein);
    }

    internal static (byte[] Sha3, byte[] Skein) HashStream(Stream stream)
    {
        (byte[] sha3, byte[] skein, byte[] sha512, _) = HashStreamWithSha512(stream);
        CryptographicOperations.ZeroMemory(sha512);
        return (sha3, skein);
    }

    private static async Task<(byte[] Sha3, byte[] Skein, byte[] Sha512, long Length)> HashStreamWithSha512Async(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var sha3 = new Sha3_512Incremental();
        using IncrementalHash sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        using var skein = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        long length = 0;
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                length = checked(length + read);
                sha3.AppendData(buffer.AsSpan(0, read));
                sha512.AppendData(buffer.AsSpan(0, read));
                skein.AppendData(buffer.AsSpan(0, read));
            }

            return (sha3.GetHashAndReset(), skein.GetHashAndReset(), sha512.GetHashAndReset(), length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static (byte[] Sha3, byte[] Skein, byte[] Sha512, long Length) HashStreamWithSha512(Stream stream)
    {
        using var sha3 = new Sha3_512Incremental();
        using IncrementalHash sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        using var skein = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        long length = 0;
        try
        {
            int read;
            while ((read = stream.Read(buffer)) > 0)
            {
                length = checked(length + read);
                sha3.AppendData(buffer.AsSpan(0, read));
                sha512.AppendData(buffer.AsSpan(0, read));
                skein.AppendData(buffer.AsSpan(0, read));
            }

            return (sha3.GetHashAndReset(), skein.GetHashAndReset(), sha512.GetHashAndReset(), length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static bool IsAcceptedSignatureState(SignatureState state) =>
        state is SignatureState.Trusted or SignatureState.PinnedDevelopment;

    public void Dispose()
    {
        List<FileStream> leases;
        lock (_leaseGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            leases = _applicationLeases;
            _applicationLeases = [];
        }

        DisposeStreams(leases);
        GC.SuppressFinalize(this);
    }

    private static void DisposeStreams(IEnumerable<FileStream> streams)
    {
        foreach (FileStream stream in streams)
        {
            stream.Dispose();
        }
    }
}

public sealed record IntegrityStatus(
    string ActualSha3_512,
    string? ExpectedSha3_512,
    string ActualSkein1024,
    string? ExpectedSkein1024,
    string Message,
    bool HashMatches,
    bool HybridSignatureMatches,
    SignatureState SignatureState,
    bool SignerMatchesExpected,
    IReadOnlyList<ToolIntegrityStatus> Components)
{
    public bool IsTrusted => ExpectedSha3_512 is not null
        && ExpectedSkein1024 is not null
        && HashMatches
        && HybridSignatureMatches
        && SignerMatchesExpected
        && IntegrityService.IsAcceptedSignatureState(SignatureState);
}

public sealed record ToolIntegrityStatus(
    string FilePath,
    string? ActualSha3_512,
    string? ExpectedSha3_512,
    string? ActualSkein1024,
    string? ExpectedSkein1024,
    string? ActualSha512,
    bool HashMatches,
    bool HybridSignatureMatches,
    string HybridSignatureMessage,
    SignatureState SignatureState,
    string? Signer,
    string? SignatureThumbprint,
    string? SignerSha256,
    string? SignerSha3_512,
    string? SignerSkein1024,
    string SignatureMessage,
    string Message)
{
    public bool IsTrusted => ExpectedSha3_512 is not null
        && ExpectedSkein1024 is not null
        && HashMatches
        && HybridSignatureMatches
        && IntegrityService.IsAcceptedSignatureState(SignatureState);

    public static ToolIntegrityStatus Missing(string filePath) => new(
        filePath, null, null, null, null, null, false, false,
        "Hybrid signature unavailable because the file is missing.",
        SignatureState.Unknown, null, null, null, null, null,
        "file not found", "Native tool not found.");
}

internal sealed record HybridArtifactStatus(bool IsTrusted, string Message);

public enum SignatureState
{
    Unknown,
    Missing,
    PresentButUntrustedOrInvalid,
    PinnedDevelopment,
    Trusted,
}

internal static class NativeToolIntegrity
{
    internal static IReadOnlyList<string> RequiredLogicalToolNames { get; } =
        new[] { "zpaq.exe", "kalyna_ref.dll", "threefish_ref.dll", "argon2_ref.dll", "argon2.exe" };

    private static readonly IReadOnlyDictionary<string, string> MacNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["zpaq.exe"] = "zpaq",
        ["kalyna_ref.dll"] = "libkalyna_ref.dylib",
        ["threefish_ref.dll"] = "libthreefish_ref.dylib",
        ["argon2_ref.dll"] = "libargon2_ref.dylib",
        ["argon2.exe"] = "argon2",
    };

    internal static string RequireTrustedFile(string path)
    {
        using TrustedNativeFileLease lease = AcquireTrustedFile(path);
        return lease.Path;
    }

    internal static TrustedNativeFileLease AcquireTrustedFile(string path)
    {
        string fullPath = Path.GetFullPath(path);
        EnsureAllowedPath(fullPath);
        FileStream? stream = null;
        try
        {
            stream = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
            string canonical = NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, fullPath, "Native tool");
            ToolIntegrityStatus status = IntegrityService.CheckFile(stream, canonical, requireManifest: true);
            if (!status.IsTrusted)
            {
                throw new InvalidOperationException($"Native tool integrity verification failed for {Path.GetFileName(path)}: {status.Message} {status.HybridSignatureMessage} {status.SignatureMessage}");
            }

            MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, canonical);

            // A component that already lives inside the sealed app bundle is
            // used where it is, rather than through a private copy.
            //
            // The copy exists to close the window between verifying a file and
            // using it. Inside the bundle macOS closes that window itself and
            // more strongly than a copy could: the file is covered by the
            // bundle's CodeResources seal, and the kernel validates its
            // signature against the pinned Team ID on every dlopen and exec
            // under the hardened runtime, so a swapped file fails to load at
            // all. The verified descriptor stays open for the lifetime of the
            // lease, and the path was just confirmed to still name it.
            //
            // A copy would also be strictly worse here. It lands in a directory
            // this process can write, which is exactly the provenance Gatekeeper
            // refuses: loading an unnotarized library from a writable location
            // raises a malware-verification prompt on every launch, because each
            // launch produces a file identity the user has never approved.
            if (IntegrityService.TryGetSealedBundleLayout(canonical, out _, out _))
            {
                var sealedLease = new TrustedNativeFileLease(canonical, stream);
                stream = null;
                return sealedLease;
            }

            TrustedNativeFileLease snapshot = CreateAuthenticatedSnapshot(canonical, stream);
            stream.Dispose();
            stream = null;
            return snapshot;
        }
        finally
        {
            stream?.Dispose();
        }
    }

    internal static nint LoadTrustedLibrary(string logicalName)
    {
        string path = ResolveKnownTool(logicalName)
            ?? throw new FileNotFoundException("Native library not found.", logicalName);
        using TrustedNativeFileLease lease = AcquireTrustedFile(path);
        nint handle = NativeLibrary.Load(lease.Path);
        MacSafeFileSystem.RequirePathStillNamesHandle(lease.Stream.SafeFileHandle, lease.Path);
        return handle;
    }

    internal static string? ResolveKnownTool(string fileName)
        => ResolveKnownTool(fileName, AppContext.BaseDirectory);

    /// <summary>
    /// Resolves a Windows-reference component name to its macOS counterpart
    /// below <paramref name="searchRoot"/>. The explicit root lets a verifier
    /// inspect the components of a signed bundle other than its own.
    /// </summary>
    internal static string? ResolveKnownTool(string fileName, string searchRoot)
    {
        string mapped = MacNames.TryGetValue(fileName, out string? actual) ? actual : fileName;
        string baseDirectory = Path.GetFullPath(searchRoot);
        string[] candidates =
        [
            Path.Combine(baseDirectory, "Native", mapped),
            Path.Combine(baseDirectory, "Resources", "Native", mapped),
            Path.Combine(baseDirectory, mapped),
        ];
        return candidates.FirstOrDefault(File.Exists) is { } found ? Path.GetFullPath(found) : null;
    }

    private static void EnsureAllowedPath(string fullPath)
    {
        string baseDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        string directory = Path.GetDirectoryName(fullPath) ?? string.Empty;
        // The scanner lives in its own nested bundle, one level outside
        // Contents/MacOS, because macOS only grants camera access to something
        // it can name. It is verified exactly like the tools beside it.
        string? contentsDirectory = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(baseDirectory));
        string helperDirectory = contentsDirectory is null
            ? string.Empty
            : Path.Combine(contentsDirectory, "Library", "Helpers", "Keep Vault Scanner.app", "Contents", "MacOS");

        bool allowed = string.Equals(directory, baseDirectory, StringComparison.Ordinal)
            || string.Equals(directory, Path.Combine(baseDirectory, "Native"), StringComparison.Ordinal)
            || string.Equals(directory, Path.Combine(baseDirectory, "Resources", "Native"), StringComparison.Ordinal)
            || (helperDirectory.Length > 0 && string.Equals(directory, helperDirectory, StringComparison.Ordinal));
        if (!allowed)
        {
            throw new InvalidOperationException($"Native tool is outside the sealed application directories: {fullPath}");
        }
    }

    private static TrustedNativeFileLease CreateAuthenticatedSnapshot(string sourcePath, FileStream source)
    {
        string directory = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-native-").FullName);
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string target = Path.Combine(directory, Path.GetFileName(sourcePath));
        FileStream? targetStream = null;
        try
        {
            source.Position = 0;
            using (FileStream output = new(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough))
            {
                source.CopyTo(output);
                output.Flush(flushToDisk: true);
                MacSafeFileSystem.FullSync(output.SafeFileHandle);
            }

            File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            string sourceSidecarBase = IntegrityService.ResolveSidecarBasePath(sourcePath);
            foreach (string extension in new[] { ".sha3", ".skein", ".khsig", ".sha3.khsig", ".skein.khsig" })
            {
                CopySidecarNoFollow(sourceSidecarBase + extension, target + extension);
            }

            targetStream = MacSafeFileSystem.OpenReadNoSymlinks(target);
            ToolIntegrityStatus snapshotStatus = IntegrityService.CheckFile(targetStream, target, requireManifest: true);
            if (!snapshotStatus.IsTrusted)
            {
                throw new InvalidOperationException($"The private native snapshot failed re-verification: {snapshotStatus.Message} {snapshotStatus.HybridSignatureMessage} {snapshotStatus.SignatureMessage}");
            }

            var lease = new TrustedNativeFileLease(target, targetStream, directory);
            targetStream = null;
            return lease;
        }
        catch
        {
            targetStream?.Dispose();
            TryDeleteSnapshotDirectory(directory);
            throw;
        }
    }

    private static void CopySidecarNoFollow(string sourcePath, string destinationPath)
    {
        using FileStream input = MacSafeFileSystem.OpenReadNoSymlinks(sourcePath);
        using FileStream output = new(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough);
        input.CopyTo(output);
        output.Flush(flushToDisk: true);
        MacSafeFileSystem.FullSync(output.SafeFileHandle);
        File.SetUnixFileMode(destinationPath, UnixFileMode.UserRead);
    }

    internal static void TryDeleteSnapshotDirectory(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch
        {
        }
    }
}

internal sealed class TrustedNativeFileLease : IDisposable
{
    private FileStream? _stream;
    private string? _snapshotDirectory;

    internal TrustedNativeFileLease(string path, FileStream stream, string? snapshotDirectory = null)
    {
        Path = path;
        _stream = stream;
        _snapshotDirectory = snapshotDirectory;
    }

    internal string Path { get; }
    internal FileStream Stream => _stream ?? throw new ObjectDisposedException(nameof(TrustedNativeFileLease));

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
        string? directory = Interlocked.Exchange(ref _snapshotDirectory, null);
        if (directory is not null)
        {
            NativeToolIntegrity.TryDeleteSnapshotDirectory(directory);
        }
    }
}
