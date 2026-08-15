using System.ComponentModel;
using System.Buffers.Binary;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
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
        string executablePath = Environment.ProcessPath ?? throw new InvalidOperationException("Der Programmpfad ist unbekannt.");
        string baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        IEnumerable<string> componentPaths = Directory.EnumerateFiles(baseDirectory, "*.exe", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(baseDirectory, "*.dll", SearchOption.TopDirectoryOnly));
        string toolsDirectory = Path.Combine(baseDirectory, "tools");
        if (Directory.Exists(toolsDirectory)
            && (File.GetAttributes(toolsDirectory) & FileAttributes.ReparsePoint) == 0)
        {
            componentPaths = componentPaths
                .Concat(Directory.EnumerateFiles(toolsDirectory, "*.exe", SearchOption.TopDirectoryOnly))
                .Concat(Directory.EnumerateFiles(toolsDirectory, "*.dll", SearchOption.TopDirectoryOnly));
        }

        componentPaths = componentPaths.Append(executablePath);
        var components = new List<ToolIntegrityStatus>();
        var candidateLeases = new List<FileStream>();
        bool leasesTransferred = false;
        try
        {
            foreach (string path in componentPaths
                .Where(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path))
                .Select(Path.GetFullPath)
                .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                candidateLeases.Add(stream);
                components.Add(await CheckFileAsync(stream, path, requireManifest: true, cancellationToken).ConfigureAwait(false));
            }

            ToolIntegrityStatus status = components.FirstOrDefault(component =>
                    string.Equals(component.FilePath, Path.GetFullPath(executablePath), StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException("The executable could not be included in the application integrity set.");
            bool signerMatchesExpected = components.All(component => SigningTrustPolicy.Matches(
                component.SignerSha256,
                component.SignerSha3_512,
                component.SignerSkein1024));
            bool signatureAccepted = components.All(component => IsAcceptedSignatureState(component.SignatureState));
            bool dualHashesMatch = components.All(component => component.HashMatches);
            bool hybridSignaturesMatch = components.All(component => component.HybridSignatureMatches);
            ToolIntegrityStatus? missingManifest = components.FirstOrDefault(component =>
                component.ExpectedSha3_512 is null || component.ExpectedSkein1024 is null);
            string message = missingManifest is not null
                ? $"SHA3-512-/Skein-1024-Dualmanifest fehlt fuer {Path.GetFileName(missingManifest.FilePath)}."
                : !dualHashesMatch
                    ? "WARNUNG: Programmintegrität verletzt."
                    : !hybridSignaturesMatch
                        ? "WARNUNG: Hybride RSA-/ML-DSA-Signaturprüfung fehlgeschlagen."
                    : !signatureAccepted
                        ? "WARNUNG: Programmsignatur ist nicht vertrauenswürdig."
                        : !signerMatchesExpected
                            ? "WARNUNG: Programmsignatur entspricht nicht der fest gebundenen hybriden Signierrichtlinie."
                            : "Integritätsprüfung bestanden.";

            var result = new IntegrityStatus(
                status.ActualSha3_512 ?? string.Empty,
                status.ExpectedSha3_512,
                status.ActualSkein1024 ?? string.Empty,
                status.ExpectedSkein1024,
                message,
                dualHashesMatch,
                hybridSignaturesMatch,
                signatureAccepted ? status.SignatureState : SignatureState.PresentButUntrustedOrInvalid,
                signerMatchesExpected,
                components);

            if (result.IsTrusted)
            {
                List<FileStream> previousLeases;
                lock (_leaseGate)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);
                    previousLeases = _applicationLeases;
                    _applicationLeases = candidateLeases;
                    leasesTransferred = true;
                }

                DisposeStreams(previousLeases);
            }

            return result;
        }
        finally
        {
            if (!leasesTransferred)
            {
                DisposeStreams(candidateLeases);
            }
        }
    }

    public async Task<IReadOnlyList<ToolIntegrityStatus>> CheckNativeToolsAsync(CancellationToken cancellationToken)
    {
        string[] toolNames = ["zpaq.exe", "kalyna_ref.dll", "threefish_ref.dll", "argon2_ref.dll", "argon2.exe"];
        var statuses = new List<ToolIntegrityStatus>(toolNames.Length);
        foreach (string toolName in toolNames)
        {
            string? path = NativeToolIntegrity.ResolveKnownTool(toolName);
            statuses.Add(path is null
                ? ToolIntegrityStatus.Missing(toolName)
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

        await using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        string resolvedPath = NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, fullPath, "Integrity-check");
        (byte[] sha3Digest, byte[] skeinDigest, byte[] sha512Digest, long length) = await HashStreamWithSha512Async(stream, cancellationToken).ConfigureAwait(false);
        return await BuildStatusAsync(resolvedPath, sha3Digest, skeinDigest, sha512Digest, length, requireManifest, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<ToolIntegrityStatus> CheckFileAsync(
        FileStream lockedStream,
        string path,
        bool requireManifest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lockedStream);
        if (!lockedStream.CanRead)
        {
            throw new ArgumentException("The locked application stream must be readable.", nameof(lockedStream));
        }

        string resolvedPath = NativePathResolver.RequireCanonicalFilePath(lockedStream.SafeFileHandle, path, "Integrity-check");
        lockedStream.Position = 0;
        (byte[] sha3Digest, byte[] skeinDigest, byte[] sha512Digest, long length) = await HashStreamWithSha512Async(lockedStream, cancellationToken).ConfigureAwait(false);
        return await BuildStatusAsync(resolvedPath, sha3Digest, skeinDigest, sha512Digest, length, requireManifest, cancellationToken).ConfigureAwait(false);
    }

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

    internal static ToolIntegrityStatus CheckFile(string path, bool requireManifest)
    {
        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return ToolIntegrityStatus.Missing(fullPath);
        }

        using FileStream stream = new(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        string resolvedPath = NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, fullPath, "Integrity-check");
        (byte[] sha3Digest, byte[] skeinDigest, byte[] sha512Digest, long length) = HashStreamWithSha512(stream);
        return BuildStatus(resolvedPath, sha3Digest, skeinDigest, sha512Digest, length, requireManifest);
    }

    internal static ToolIntegrityStatus CheckFile(FileStream lockedStream, string path, bool requireManifest)
    {
        ArgumentNullException.ThrowIfNull(lockedStream);
        if (!lockedStream.CanRead)
        {
            throw new ArgumentException("The locked native-tool stream must be readable.", nameof(lockedStream));
        }

        string resolvedPath = NativePathResolver.RequireCanonicalFilePath(lockedStream.SafeFileHandle, path, "Integrity-check");
        lockedStream.Position = 0;
        (byte[] sha3Digest, byte[] skeinDigest, byte[] sha512Digest, long length) = HashStreamWithSha512(lockedStream);
        return BuildStatus(resolvedPath, sha3Digest, skeinDigest, sha512Digest, length, requireManifest);
    }

    private static async Task<ToolIntegrityStatus> BuildStatusAsync(
        string path,
        byte[] sha3Digest,
        byte[] skeinDigest,
        byte[] sha512Digest,
        long fileLength,
        bool requireManifest,
        CancellationToken cancellationToken)
    {
        try
        {
            string? sha3Manifest = await ReadManifestAsync(path + ".sha3", cancellationToken).ConfigureAwait(false);
            string? skeinManifest = await ReadManifestAsync(path + ".skein", cancellationToken).ConfigureAwait(false);
            return BuildStatus(path, sha3Digest, skeinDigest, sha512Digest, fileLength, requireManifest, sha3Manifest, skeinManifest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3Digest);
            CryptographicOperations.ZeroMemory(skeinDigest);
            CryptographicOperations.ZeroMemory(sha512Digest);
        }
    }

    private static ToolIntegrityStatus BuildStatus(
        string path,
        byte[] sha3Digest,
        byte[] skeinDigest,
        byte[] sha512Digest,
        long fileLength,
        bool requireManifest)
    {
        try
        {
            return BuildStatus(
                path,
                sha3Digest,
                skeinDigest,
                sha512Digest,
                fileLength,
                requireManifest,
                ReadManifest(path + ".sha3"),
                ReadManifest(path + ".skein"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3Digest);
            CryptographicOperations.ZeroMemory(skeinDigest);
            CryptographicOperations.ZeroMemory(sha512Digest);
        }
    }

    private static ToolIntegrityStatus BuildStatus(
        string path,
        byte[] sha3Digest,
        byte[] skeinDigest,
        byte[] sha512Digest,
        long fileLength,
        bool requireManifest,
        string? sha3ManifestText,
        string? skeinManifestText)
    {
        string actualSha3 = Convert.ToHexString(sha3Digest);
        string actualSkein = Convert.ToHexString(skeinDigest);
        string actualSha512 = Convert.ToHexString(sha512Digest);
        SignatureInfo signature = AuthenticodeSignature.Check(path);
        HybridArtifactStatus hybrid = VerifyHybridArtifacts(
            path,
            fileLength,
            sha512Digest,
            signature.Thumbprint,
            requireManifest);

        if (sha3ManifestText is null || skeinManifestText is null)
        {
            string message = requireManifest
                ? "SHA3-512/Skein-1024 dual manifest missing; file is blocked."
                : "SHA3-512/Skein-1024 dual manifest missing.";
            return new ToolIntegrityStatus(
                path,
                actualSha3,
                sha3ManifestText?.Trim(),
                actualSkein,
                skeinManifestText?.Trim(),
                actualSha512,
                false,
                hybrid.IsTrusted,
                hybrid.Message,
                signature.State,
                signature.Signer,
                signature.Thumbprint,
                signature.SignerSha256,
                signature.SignerSha3_512,
                signature.SignerSkein1024,
                signature.Message,
                message);
        }

        try
        {
            string expectedSha3 = NormalizeHex(sha3ManifestText, 128, "SHA3-512");
            string expectedSkein = NormalizeHex(skeinManifestText, 256, "Skein-1024");
            byte[] expectedSha3Bytes = Convert.FromHexString(expectedSha3);
            byte[] expectedSkeinBytes = Convert.FromHexString(expectedSkein);
            bool sha3Matches;
            bool skeinMatches;
            try
            {
                sha3Matches = CryptographicOperations.FixedTimeEquals(sha3Digest, expectedSha3Bytes);
                skeinMatches = CryptographicOperations.FixedTimeEquals(skeinDigest, expectedSkeinBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedSha3Bytes);
                CryptographicOperations.ZeroMemory(expectedSkeinBytes);
            }

            bool hashMatches = sha3Matches & skeinMatches;
            return new ToolIntegrityStatus(
                path,
                actualSha3,
                expectedSha3,
                actualSkein,
                expectedSkein,
                actualSha512,
                hashMatches,
                hybrid.IsTrusted,
                hybrid.Message,
                signature.State,
                signature.Signer,
                signature.Thumbprint,
                signature.SignerSha256,
                signature.SignerSha3_512,
                signature.SignerSkein1024,
                signature.Message,
                hashMatches
                    ? "SHA3-512 and Skein-1024 manifests match."
                    : "SHA3-512/Skein-1024 dual manifest mismatch; file is blocked.");
        }
        catch (FormatException ex)
        {
            return new ToolIntegrityStatus(
                path,
                actualSha3,
                sha3ManifestText.Trim(),
                actualSkein,
                skeinManifestText.Trim(),
                actualSha512,
                false,
                hybrid.IsTrusted,
                hybrid.Message,
                signature.State,
                signature.Signer,
                signature.Thumbprint,
                signature.SignerSha256,
                signature.SignerSha3_512,
                signature.SignerSkein1024,
                signature.Message,
                $"Invalid dual manifest: {ex.Message}");
        }
    }

    private static HybridArtifactStatus VerifyHybridArtifacts(
        string path,
        long fileLength,
        byte[] sha512Digest,
        string? authenticodeThumbprint,
        bool requireManifests)
    {
        HybridSignaturePolicy? policy = SigningTrustPolicy.HybridPolicy;
        if (policy is null)
        {
            return new HybridArtifactStatus(false, "Compiled ML-DSA-87 verification policy is missing or invalid.");
        }

        HybridSignatureVerificationResult target = HybridSignatureService.VerifyDigest(
            fileLength,
            sha512Digest,
            path + HybridSignatureService.SidecarExtension,
            policy);
        bool signerBound = target.IsTrusted
            && !string.IsNullOrWhiteSpace(authenticodeThumbprint)
            && string.Equals(target.RsaThumbprint, authenticodeThumbprint, StringComparison.OrdinalIgnoreCase);
        if (!target.IsTrusted || !signerBound)
        {
            return new HybridArtifactStatus(
                false,
                signerBound ? target.Message : $"{target.Message} Detached RSA signer does not match Authenticode.");
        }

        if (!requireManifests)
        {
            return new HybridArtifactStatus(true, target.Message);
        }

        string sha3Manifest = path + ".sha3";
        string skeinManifest = path + ".skein";
        HybridSignatureVerificationResult sha3 = File.Exists(sha3Manifest)
            ? HybridSignatureService.VerifyFile(
                sha3Manifest,
                sha3Manifest + HybridSignatureService.SidecarExtension,
                policy)
            : HybridSignatureVerificationResult.Invalid("SHA3-512 manifest is missing.");
        HybridSignatureVerificationResult skein = File.Exists(skeinManifest)
            ? HybridSignatureService.VerifyFile(
                skeinManifest,
                skeinManifest + HybridSignatureService.SidecarExtension,
                policy)
            : HybridSignatureVerificationResult.Invalid("Skein-1024 manifest is missing.");
        bool trusted = target.IsTrusted & sha3.IsTrusted & skein.IsTrusted & signerBound;
        return trusted
            ? new HybridArtifactStatus(true, "Target and both hash manifests have valid RSA-PSS/SHA-512 and ML-DSA-87 signatures.")
            : new HybridArtifactStatus(false, $"Hybrid signature failure: target={target.Message}; SHA3={sha3.Message}; Skein={skein.Message}");
    }

    private static string NormalizeHex(string value, int expectedLength, string algorithm)
    {
        string normalized = new(value.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.Length != expectedLength || normalized.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new FormatException($"{algorithm} expected {expectedLength} hexadecimal characters.");
        }

        return normalized.ToUpperInvariant();
    }

    private static async Task<string?> ReadManifestAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > MaxManifestBytes)
        {
            throw new InvalidDataException($"Integrity manifest has an invalid length: {Path.GetFileName(path)}");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return Encoding.ASCII.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string? ReadManifest(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
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

    internal static async Task<(byte[] Sha3, byte[] Skein)> HashStreamAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using IncrementalHash sha3 = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
        using var skein = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        byte[]? sha3Result = null;
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                sha3.AppendData(buffer.AsSpan(0, read));
                skein.AppendData(buffer.AsSpan(0, read));
            }

            sha3Result = sha3.GetHashAndReset();
            byte[] skeinResult = skein.GetHashAndReset();
            return (sha3Result, skeinResult);
        }
        catch
        {
            if (sha3Result is not null)
            {
                CryptographicOperations.ZeroMemory(sha3Result);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static (byte[] Sha3, byte[] Skein) HashStream(Stream stream)
    {
        using IncrementalHash sha3 = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
        using var skein = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        byte[]? sha3Result = null;
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha3.AppendData(buffer.AsSpan(0, read));
                skein.AppendData(buffer.AsSpan(0, read));
            }

            sha3Result = sha3.GetHashAndReset();
            byte[] skeinResult = skein.GetHashAndReset();
            return (sha3Result, skeinResult);
        }
        catch
        {
            if (sha3Result is not null)
            {
                CryptographicOperations.ZeroMemory(sha3Result);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static async Task<(byte[] Sha3, byte[] Skein, byte[] Sha512, long Length)> HashStreamWithSha512Async(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using IncrementalHash sha3 = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
        using IncrementalHash sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        using var skein = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        byte[]? sha3Result = null;
        byte[]? skeinResult = null;
        byte[]? sha512Result = null;
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

            sha3Result = sha3.GetHashAndReset();
            skeinResult = skein.GetHashAndReset();
            sha512Result = sha512.GetHashAndReset();
            return (sha3Result, skeinResult, sha512Result, length);
        }
        catch
        {
            if (sha3Result is not null) CryptographicOperations.ZeroMemory(sha3Result);
            if (skeinResult is not null) CryptographicOperations.ZeroMemory(skeinResult);
            if (sha512Result is not null) CryptographicOperations.ZeroMemory(sha512Result);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static (byte[] Sha3, byte[] Skein, byte[] Sha512, long Length) HashStreamWithSha512(Stream stream)
    {
        using IncrementalHash sha3 = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
        using IncrementalHash sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        using var skein = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        byte[]? sha3Result = null;
        byte[]? skeinResult = null;
        byte[]? sha512Result = null;
        long length = 0;
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                length = checked(length + read);
                sha3.AppendData(buffer.AsSpan(0, read));
                sha512.AppendData(buffer.AsSpan(0, read));
                skein.AppendData(buffer.AsSpan(0, read));
            }

            sha3Result = sha3.GetHashAndReset();
            skeinResult = skein.GetHashAndReset();
            sha512Result = sha512.GetHashAndReset();
            return (sha3Result, skeinResult, sha512Result, length);
        }
        catch
        {
            if (sha3Result is not null) CryptographicOperations.ZeroMemory(sha3Result);
            if (skeinResult is not null) CryptographicOperations.ZeroMemory(skeinResult);
            if (sha512Result is not null) CryptographicOperations.ZeroMemory(sha512Result);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static bool IsAcceptedSignatureState(SignatureState state)
    {
        return state is SignatureState.Trusted or SignatureState.PinnedDevelopment;
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
        && IntegrityService.IsAcceptedSignatureState(SignatureState)
        && SigningTrustPolicy.Matches(SignerSha256, SignerSha3_512, SignerSkein1024);

    public static ToolIntegrityStatus Missing(string filePath)
    {
        return new ToolIntegrityStatus(
            filePath,
            null,
            null,
            null,
            null,
            null,
            false,
            false,
            "Hybrid signature unavailable because the file is missing.",
            SignatureState.Unknown,
            null,
            null,
            null,
            null,
            null,
            "file not found",
            "Native tool not found.");
    }
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
    public static string RequireTrustedFile(string path)
    {
        using TrustedNativeFileLease lease = AcquireTrustedFile(path);
        return lease.Path;
    }

    public static TrustedNativeFileLease AcquireTrustedFile(string path)
    {
        string fullPath = Path.GetFullPath(path);
        EnsureNativeToolPathAllowed(fullPath);

        FileStream? lockedFile = null;
        try
        {
            // Denying write and delete sharing pins the same file object while it is
            // hashed, Authenticode-checked, and handed to the Windows image loader.
            lockedFile = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            string resolvedPath = NativePathResolver.ResolveFinalDosPath(lockedFile.SafeFileHandle);
            EnsureNativeToolPathAllowed(resolvedPath);
            if (!IsSameDirectory(Path.GetDirectoryName(resolvedPath) ?? string.Empty, Path.GetDirectoryName(fullPath) ?? string.Empty)
                || !string.Equals(Path.GetFileName(resolvedPath), Path.GetFileName(fullPath), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Native tool path resolves through a reparse point or alias: {fullPath} -> {resolvedPath}");
            }

            ToolIntegrityStatus status = IntegrityService.CheckFile(lockedFile, resolvedPath, requireManifest: true);
            RequireTrustedStatus(status);
            return new TrustedNativeFileLease(resolvedPath, lockedFile);
        }
        catch
        {
            lockedFile?.Dispose();
            throw;
        }
    }

    public static nint LoadTrustedLibrary(string fileName)
    {
        string fullPath = ResolveKnownTool(fileName)
            ?? throw new FileNotFoundException("Native library not found.", fileName);
        using TrustedNativeFileLease lease = AcquireTrustedFile(fullPath);
        return NativeLibrary.Load(lease.Path);
    }

    private static void RequireTrustedStatus(ToolIntegrityStatus status)
    {
        if (!status.HashMatches)
        {
            throw new InvalidOperationException($"Native tool integrity check failed for {Path.GetFileName(status.FilePath)}: {status.Message}");
        }

        if (!status.HybridSignatureMatches)
        {
            throw new InvalidOperationException($"Native tool hybrid RSA/ML-DSA signature check failed for {Path.GetFileName(status.FilePath)}: {status.HybridSignatureMessage}");
        }

        if (!IntegrityService.IsAcceptedSignatureState(status.SignatureState))
        {
            throw new InvalidOperationException($"Native tool signature check failed for {Path.GetFileName(status.FilePath)}: {status.SignatureMessage}");
        }

        if (!SigningTrustPolicy.IsConfigured || !SigningTrustPolicy.Matches(
            status.SignerSha256,
            status.SignerSha3_512,
            status.SignerSkein1024))
        {
            throw new InvalidOperationException($"Native tool signer is not the pinned release/development signer for {Path.GetFileName(status.FilePath)}. Expected: {SigningTrustPolicy.Describe()}.");
        }

        // Bind the native tool signer to the application's own signed binary, not to
        // Environment.ProcessPath. The process host can be a shared, differently signed
        // launcher (e.g. dotnet.exe) even though the app itself is signed; anchoring to
        // the app binary keeps the check host-independent.
        string? appBinary = ResolveApplicationSignerAnchor();
        if (appBinary is null)
        {
            return;
        }

        SignatureInfo appSignature = AuthenticodeSignature.Check(appBinary);
        if (IntegrityService.IsAcceptedSignatureState(appSignature.State)
            && (!SigningTrustPolicy.Matches(
                    appSignature.SignerSha256,
                    appSignature.SignerSha3_512,
                    appSignature.SignerSkein1024)
                || !string.Equals(appSignature.Thumbprint, status.SignatureThumbprint, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(appSignature.SignerSha256, status.SignerSha256, StringComparison.Ordinal)
                || !string.Equals(appSignature.SignerSha3_512, status.SignerSha3_512, StringComparison.Ordinal)
                || !string.Equals(appSignature.SignerSkein1024, status.SignerSkein1024, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException($"Native tool signer does not match the application signer for {Path.GetFileName(status.FilePath)}.");
        }
    }

    private static string? ResolveApplicationSignerAnchor()
    {
        string baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        System.Reflection.Assembly appAssembly = typeof(NativeToolIntegrity).Assembly;

        // 1) The application's own apphost executable next to the app assembly. This is the
        //    artifact that gets Authenticode-signed and shipped, including the single-file
        //    portable build, and is present regardless of the launching host.
        string? assemblyName = appAssembly.GetName().Name;
        if (!string.IsNullOrEmpty(assemblyName))
        {
            string appHost = Path.Combine(baseDirectory, assemblyName + ".exe");
            if (File.Exists(appHost))
            {
                return appHost;
            }
        }

        // 2) The process host, but only when it actually lives in the app base directory
        //    (i.e. it IS our apphost, not a shared host such as dotnet.exe).
        string? processPath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(processPath)
            && File.Exists(processPath)
            && IsSameDirectory(Path.GetDirectoryName(processPath) ?? string.Empty, baseDirectory))
        {
            return processPath;
        }

        // A single-file deployment has no stable Assembly.Location. Production apphosts
        // always take one of the two paths above; otherwise the pinned signer remains the
        // mandatory native-tool trust boundary.
        return null;
    }

    public static string? ResolveKnownTool(string fileName)
    {
        foreach (string candidate in KnownToolCandidates(fileName).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        return null;
    }

    private static void EnsureNativeToolPathAllowed(string fullPath)
    {
        string directory = Path.GetDirectoryName(Path.GetFullPath(fullPath)) ?? string.Empty;
        string baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        string toolsDirectory = Path.GetFullPath(Path.Combine(baseDirectory, "tools"));
        if (!IsSameDirectory(directory, baseDirectory) && !IsSameDirectory(directory, toolsDirectory))
        {
            throw new InvalidOperationException($"Native tool must be located next to the application or in its tools directory: {fullPath}");
        }
    }

    private static bool IsSameDirectory(string left, string right)
    {
        return string.Equals(
            Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> KnownToolCandidates(string fileName)
    {
        string baseDirectory = AppContext.BaseDirectory;
        yield return Path.Combine(baseDirectory, fileName);
        yield return Path.Combine(baseDirectory, "tools", fileName);
    }
}

internal static unsafe partial class NativePathResolver
{
    private const int MaxWindowsPathCharacters = 32768;

    public static string ResolveFinalDosPath(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        char[] buffer = new char[MaxWindowsPathCharacters];
        fixed (char* bufferPointer = buffer)
        {
            uint length = GetFinalPathNameByHandle(
                handle,
                bufferPointer,
                checked((uint)buffer.Length),
                0);
            if (length == 0 || length >= buffer.Length)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not resolve the final path from its locked file handle.");
            }

            string path = new(buffer, 0, checked((int)length));
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                path = @"\\" + path[8..];
            }
            else if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                path = path[4..];
            }

            return Path.GetFullPath(path);
        }
    }

    public static string RequireCanonicalFilePath(SafeFileHandle handle, string expectedPath, string pathKind)
    {
        string fullExpectedPath = Path.GetFullPath(expectedPath);
        string resolvedPath = ResolveFinalDosPath(handle);
        if (!string.Equals(fullExpectedPath, resolvedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{pathKind} path resolves through a reparse point or alias: {fullExpectedPath} -> {resolvedPath}");
        }

        return resolvedPath;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        char* path,
        uint pathCharacters,
        uint flags);
}

internal sealed class TrustedNativeFileLease : IDisposable
{
    private FileStream? _lockedFile;

    internal TrustedNativeFileLease(string path, FileStream lockedFile)
    {
        Path = path;
        _lockedFile = lockedFile;
    }

    public string Path { get; }

    public void Dispose()
    {
        Interlocked.Exchange(ref _lockedFile, null)?.Dispose();
    }
}

internal sealed record SignatureInfo(
    SignatureState State,
    string? Signer,
    string? Thumbprint,
    bool IsSelfSigned,
    string Message,
    string? SignerSha256 = null,
    string? SignerSha3_512 = null,
    string? SignerSkein1024 = null);

internal static partial class AuthenticodeSignature
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WssVerifySpecific = 0x00000001;
    private const uint WssGetSecondarySigCount = 0x00000002;
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";
    private const string Sha512WithRsaOid = "1.2.840.113549.1.1.13";
    private const int MaximumAuthenticodeBlobBytes = 1024 * 1024;

    public static SignatureInfo Check(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SignatureInfo(SignatureState.Unknown, null, null, false, "Authenticode is only available on Windows.");
        }

        CertificateInfo? certificate = TryReadCertificate(path);
        string? signer = certificate?.Signer;
        try
        {
            WinTrustResult trust = WinVerifyTrustFile(path);
            int result = trust.Status;
            bool singlePrimarySignature = trust.SecondarySignatureCount == 0
                && trust.VerifiedSignatureIndex == 0;
            string? digestAlgorithm = TryReadPrimaryDigestAlgorithm(path);
            bool sha512PolicySatisfied = string.Equals(digestAlgorithm, Sha512Oid, StringComparison.Ordinal)
                && certificate?.UsesSha512RsaCertificateSignature == true;
            if (result == 0)
            {
                if (!singlePrimarySignature || !sha512PolicySatisfied)
                {
                    return new SignatureInfo(
                        SignatureState.PresentButUntrustedOrInvalid,
                        signer,
                        certificate?.Thumbprint,
                        certificate?.IsSelfSigned ?? false,
                        !singlePrimarySignature
                            ? "Authenticode verification is ambiguous because the file contains secondary signatures."
                            : "Authenticode must use SHA-512 for both the PE digest and RSA certificate signature.",
                        certificate?.SignerSha256,
                        certificate?.SignerSha3_512,
                        certificate?.SignerSkein1024);
                }

                string trustLabel = certificate?.IsDevelopmentCertificate == true || certificate?.IsSelfSigned == true
                    ? "Trusted development/self-signed Authenticode signature"
                    : "Trusted Authenticode signature";
                return new SignatureInfo(
                    SignatureState.Trusted,
                    signer,
                    certificate?.Thumbprint,
                    certificate?.IsSelfSigned ?? false,
                    signer is null ? $"{trustLabel}." : $"{trustLabel}: {signer}",
                    certificate?.SignerSha256,
                    certificate?.SignerSha3_512,
                    certificate?.SignerSkein1024);
            }

            if (result == CertEUntrustedRoot
                && certificate?.IsDevelopmentCertificate == true
                && singlePrimarySignature
                && sha512PolicySatisfied
                && SigningTrustPolicy.Matches(
                    certificate.SignerSha256,
                    certificate.SignerSha3_512,
                    certificate.SignerSkein1024))
            {
                return new SignatureInfo(
                    SignatureState.PinnedDevelopment,
                    signer,
                    certificate.Thumbprint,
                    certificate.IsSelfSigned,
                    signer is null
                        ? "Pinned development Authenticode signature verified; its root is intentionally not installed as a Windows trust root."
                        : $"Pinned development Authenticode signature verified: {signer}. Its root is intentionally not installed as a Windows trust root.",
                    certificate.SignerSha256,
                    certificate.SignerSha3_512,
                    certificate.SignerSkein1024);
            }

            if (result == TrustENoSignature)
            {
                return new SignatureInfo(SignatureState.Missing, null, null, false, "No Authenticode signature.");
            }

            return signer is null
                ? new SignatureInfo(SignatureState.Unknown, null, certificate?.Thumbprint, certificate?.IsSelfSigned ?? false, $"WinVerifyTrust returned 0x{result:X8}.", certificate?.SignerSha256, certificate?.SignerSha3_512, certificate?.SignerSkein1024)
                : new SignatureInfo(SignatureState.PresentButUntrustedOrInvalid, signer, certificate?.Thumbprint, certificate?.IsSelfSigned ?? false, $"Authenticode signer present but not trusted/valid: 0x{result:X8}; {signer}", certificate?.SignerSha256, certificate?.SignerSha3_512, certificate?.SignerSkein1024);
        }
        catch (Exception ex)
        {
            return signer is null
                ? new SignatureInfo(SignatureState.Unknown, null, certificate?.Thumbprint, certificate?.IsSelfSigned ?? false, $"Authenticode check failed: {ex.Message}", certificate?.SignerSha256, certificate?.SignerSha3_512, certificate?.SignerSkein1024)
                : new SignatureInfo(SignatureState.PresentButUntrustedOrInvalid, signer, certificate?.Thumbprint, certificate?.IsSelfSigned ?? false, $"Authenticode signer present; verification failed: {ex.Message}", certificate?.SignerSha256, certificate?.SignerSha3_512, certificate?.SignerSkein1024);
        }
    }

    private static CertificateInfo? TryReadCertificate(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
            using var certificate2 = new X509Certificate2(certificate);
#pragma warning restore SYSLIB0057
            using RSA? rsa = certificate2.GetRSAPublicKey();
            if (rsa is null)
            {
                return null;
            }

            byte[] subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
            byte[] sha256 = SHA256.HashData(subjectPublicKeyInfo);
            byte[] sha3 = SHA3_512.HashData(subjectPublicKeyInfo);
            byte[] skein = Skein1024Digest.HashData(subjectPublicKeyInfo);
            try
            {
                return new CertificateInfo(
                    $"{certificate2.Subject}; thumbprint {certificate2.Thumbprint}",
                    certificate2.Thumbprint,
                    Convert.ToHexString(sha256),
                    Convert.ToHexString(sha3),
                    Convert.ToHexString(skein),
                    string.Equals(certificate2.Subject, certificate2.Issuer, StringComparison.OrdinalIgnoreCase),
                    certificate2.Subject.Contains("Development", StringComparison.OrdinalIgnoreCase),
                    string.Equals(certificate2.SignatureAlgorithm.Value, Sha512WithRsaOid, StringComparison.Ordinal));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
                CryptographicOperations.ZeroMemory(sha256);
                CryptographicOperations.ZeroMemory(sha3);
                CryptographicOperations.ZeroMemory(skein);
            }
        }
        catch
        {
            return null;
        }
    }

    private sealed record CertificateInfo(
        string Signer,
        string? Thumbprint,
        string SignerSha256,
        string SignerSha3_512,
        string SignerSkein1024,
        bool IsSelfSigned,
        bool IsDevelopmentCertificate,
        bool UsesSha512RsaCertificateSignature);

    private static string? TryReadPrimaryDigestAlgorithm(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> dosHeader = stackalloc byte[64];
            stream.ReadExactly(dosHeader);
            if (BinaryPrimitives.ReadUInt16LittleEndian(dosHeader) != 0x5A4D)
            {
                return null;
            }

            int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[0x3C..]);
            if (peOffset < 64 || peOffset > stream.Length - 24)
            {
                return null;
            }

            stream.Position = peOffset;
            Span<byte> peAndFileHeader = stackalloc byte[24];
            stream.ReadExactly(peAndFileHeader);
            if (BinaryPrimitives.ReadUInt32LittleEndian(peAndFileHeader) != 0x00004550)
            {
                return null;
            }

            int optionalHeaderLength = BinaryPrimitives.ReadUInt16LittleEndian(peAndFileHeader[20..]);
            if (optionalHeaderLength < 128 || optionalHeaderLength > 4096)
            {
                return null;
            }

            byte[] optionalHeader = new byte[optionalHeaderLength];
            byte[]? certificateBlob = null;
            try
            {
                stream.ReadExactly(optionalHeader);
                ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(optionalHeader);
                int dataDirectoryOffset = magic switch
                {
                    0x10B => 96,
                    0x20B => 112,
                    _ => -1,
                };
                int securityDirectoryOffset = checked(dataDirectoryOffset + (4 * 8));
                if (dataDirectoryOffset < 0 || securityDirectoryOffset > optionalHeader.Length - 8)
                {
                    return null;
                }

                uint certificateOffset = BinaryPrimitives.ReadUInt32LittleEndian(optionalHeader.AsSpan(securityDirectoryOffset));
                uint certificateSize = BinaryPrimitives.ReadUInt32LittleEndian(optionalHeader.AsSpan(securityDirectoryOffset + 4));
                if (certificateOffset == 0
                    || certificateSize < 8
                    || certificateSize > MaximumAuthenticodeBlobBytes
                    || certificateOffset > stream.Length - certificateSize)
                {
                    return null;
                }

                stream.Position = certificateOffset;
                Span<byte> winCertificateHeader = stackalloc byte[8];
                stream.ReadExactly(winCertificateHeader);
                uint encodedLength = BinaryPrimitives.ReadUInt32LittleEndian(winCertificateHeader);
                ushort revision = BinaryPrimitives.ReadUInt16LittleEndian(winCertificateHeader[4..]);
                ushort certificateType = BinaryPrimitives.ReadUInt16LittleEndian(winCertificateHeader[6..]);
                if (encodedLength < 8
                    || encodedLength > certificateSize
                    || encodedLength - 8 > MaximumAuthenticodeBlobBytes
                    || revision != 0x0200
                    || certificateType != 0x0002)
                {
                    return null;
                }

                certificateBlob = new byte[checked((int)encodedLength - 8)];
                stream.ReadExactly(certificateBlob);
                var signedCms = new SignedCms();
                signedCms.Decode(certificateBlob);
                return signedCms.SignerInfos.Count == 1
                    ? signedCms.SignerInfos[0].DigestAlgorithm.Value
                    : null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(optionalHeader);
                if (certificateBlob is not null)
                {
                    CryptographicOperations.ZeroMemory(certificateBlob);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or CryptographicException or ArgumentException or OverflowException)
        {
            return null;
        }
    }

    private static WinTrustResult WinVerifyTrustFile(string path)
    {
        nint fileInfoPointer = 0;
        nint trustDataPointer = 0;
        nint signatureSettingsPointer = 0;

        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = path,
            };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var signatureSettings = new WinTrustSignatureSettings
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustSignatureSettings>(),
                dwIndex = 0,
                dwFlags = WssVerifySpecific | WssGetSecondarySigCount,
            };
            signatureSettingsPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustSignatureSettings>());
            Marshal.StructureToPtr(signatureSettings, signatureSettingsPointer, false);

            var trustData = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = fileInfoPointer,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval,
                pSignatureSettings = signatureSettingsPointer,
            };
            trustDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(trustData, trustDataPointer, false);

            Guid action = WinTrustActionGenericVerifyV2;
            int result = WinVerifyTrust(new nint(-1), ref action, trustDataPointer);
            signatureSettings = Marshal.PtrToStructure<WinTrustSignatureSettings>(signatureSettingsPointer);

            trustData = Marshal.PtrToStructure<WinTrustData>(trustDataPointer);
            trustData.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(trustData, trustDataPointer, false);
            _ = WinVerifyTrust(new nint(-1), ref action, trustDataPointer);
            return new WinTrustResult(result, signatureSettings.cSecondarySigs, signatureSettings.dwVerifiedSigIndex);
        }
        finally
        {
            if (trustDataPointer != 0)
            {
                Marshal.DestroyStructure<WinTrustData>(trustDataPointer);
                Marshal.FreeHGlobal(trustDataPointer);
            }

            if (fileInfoPointer != 0)
            {
                Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
                Marshal.FreeHGlobal(fileInfoPointer);
            }

            if (signatureSettingsPointer != 0)
            {
                Marshal.DestroyStructure<WinTrustSignatureSettings>(signatureSettingsPointer);
                Marshal.FreeHGlobal(signatureSettingsPointer);
            }
        }
    }

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WinVerifyTrust(nint hwnd, ref Guid pgActionId, nint pWinTrustData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public nint pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustSignatureSettings
    {
        public uint cbStruct;
        public uint dwIndex;
        public uint dwFlags;
        public uint cSecondarySigs;
        public uint dwVerifiedSigIndex;
        public nint pCryptoPolicy;
    }

    private readonly record struct WinTrustResult(
        int Status,
        uint SecondarySignatureCount,
        uint VerifiedSignatureIndex);
}
