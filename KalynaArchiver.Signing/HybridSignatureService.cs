using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace KalynaArchiver.Signing;

public static class HybridSignatureService
{
    public const string SidecarExtension = ".khsig";
    public const int Sha512DigestBytes = 64;

    private const int FormatVersion = 1;
    private const int Rsa4096SignatureBytes = 512;
    private const int MaximumCertificateBytes = 32 * 1024;
    private const int MaximumSidecarBytes = 64 * 1024;
    private static readonly byte[] Magic = "KZVHSIG1"u8.ToArray();
    private static readonly byte[] PayloadDomain = Encoding.ASCII.GetBytes(
        "KalynaZpaqVault/HybridArtifactSignature/SHA-512/v1\0");
    private const string Sha512WithRsaOid = "1.2.840.113549.1.1.13";
    private const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";

    public static async Task<HybridSignatureCreationResult> CreateAsync(
        string filePath,
        string signaturePath,
        X509Certificate2 certificate,
        ReadOnlyMemory<byte> mldsaPrivateKey,
        ReadOnlyMemory<byte> mldsaPublicKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(signaturePath);
        ArgumentNullException.ThrowIfNull(certificate);
        EnsureSha512RsaCertificate(certificate);
        DateTime utcNow = DateTime.UtcNow;
        if (utcNow < certificate.NotBefore.ToUniversalTime() || utcNow > certificate.NotAfter.ToUniversalTime())
        {
            throw new CryptographicException("The RSA code-signing certificate is not currently valid.");
        }

        byte[] derivedPublicKey = Mldsa87.DerivePublicKey(mldsaPrivateKey.Span);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(derivedPublicKey, mldsaPublicKey.Span))
            {
                throw new CryptographicException("The ML-DSA private and public signing keys do not match.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedPublicKey);
        }

        var lockedFile = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (lockedFile.ConfigureAwait(false))
        {
            FileDigest digest = await ComputeFileDigestAsync(lockedFile, cancellationToken).ConfigureAwait(false);
            byte[] payload = CreatePayload(digest.Length, digest.Sha512);
            byte[]? rsaSignature = null;
            byte[]? mldsaSignature = null;
            byte[]? sidecar = null;
            try
            {
                using RSA rsa = certificate.GetRSAPrivateKey()
                    ?? throw new CryptographicException("The RSA code-signing certificate has no accessible private key.");
                if (rsa.KeySize != 4096)
                {
                    throw new CryptographicException("Hybrid signing requires an RSA-4096 certificate.");
                }

                rsaSignature = rsa.SignData(payload, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                if (rsaSignature.Length != Rsa4096SignatureBytes)
                {
                    throw new CryptographicException("RSA-4096 produced an unexpected signature length.");
                }

                mldsaSignature = Mldsa87.Sign(payload, mldsaPrivateKey.Span);
                sidecar = EncodeSidecar(digest, certificate.RawData, rsaSignature, mldsaSignature);
                await WriteAtomicallyAsync(signaturePath, sidecar, cancellationToken).ConfigureAwait(false);
                return new HybridSignatureCreationResult(
                    digest.Length,
                    Convert.ToHexString(digest.Sha512),
                    certificate.Thumbprint,
                    payload.ToArray(),
                    mldsaSignature.ToArray());
            }
            finally
            {
                digest.Dispose();
                CryptographicOperations.ZeroMemory(payload);
                if (rsaSignature is not null)
                {
                    CryptographicOperations.ZeroMemory(rsaSignature);
                }

                if (mldsaSignature is not null)
                {
                    CryptographicOperations.ZeroMemory(mldsaSignature);
                }

                if (sidecar is not null)
                {
                    CryptographicOperations.ZeroMemory(sidecar);
                }
            }
        }
    }

    public static HybridSignatureVerificationResult VerifyFile(
        string filePath,
        string signaturePath,
        HybridSignaturePolicy policy)
    {
        using var lockedFile = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);
        FileDigest digest = ComputeFileDigest(lockedFile);
        try
        {
            return VerifyDigest(digest.Length, digest.Sha512, signaturePath, policy);
        }
        finally
        {
            digest.Dispose();
        }
    }

    public static HybridSignatureVerificationResult VerifyDigest(
        long fileLength,
        ReadOnlySpan<byte> sha512Digest,
        string signaturePath,
        HybridSignaturePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (fileLength < 0 || sha512Digest.Length != Sha512DigestBytes)
        {
            return HybridSignatureVerificationResult.Invalid("Invalid file length or SHA-512 digest supplied to hybrid verification.");
        }

        if (!File.Exists(signaturePath))
        {
            return HybridSignatureVerificationResult.Invalid($"Hybrid signature missing: {Path.GetFileName(signaturePath)}");
        }

        byte[] encoded = [];
        HybridSignatureEnvelope? envelope = null;
        byte[]? payload = null;
        try
        {
            using (var signature = new FileStream(
                signaturePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.SequentialScan))
            {
                if (signature.Length is <= 0 or > MaximumSidecarBytes)
                {
                    return HybridSignatureVerificationResult.Invalid("Hybrid signature has an invalid length.");
                }

                encoded = new byte[checked((int)signature.Length)];
                signature.ReadExactly(encoded);
            }

            envelope = DecodeSidecar(encoded);
            bool lengthMatches = envelope.FileLength == fileLength;
            bool digestMatches = CryptographicOperations.FixedTimeEquals(envelope.Sha512Digest, sha512Digest);
            if (!(lengthMatches & digestMatches))
            {
                return HybridSignatureVerificationResult.Invalid("Hybrid signature SHA-512 artifact binding does not match the file.");
            }

            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(envelope.Certificate);
            EnsureSha512RsaCertificate(certificate);
            if (!policy.MatchesRsaCertificate(certificate, out string pinError))
            {
                return HybridSignatureVerificationResult.Invalid(pinError);
            }

            payload = CreatePayload(fileLength, sha512Digest);
            using RSA rsa = certificate.GetRSAPublicKey()
                ?? throw new CryptographicException("Hybrid signature certificate does not contain an RSA key.");
            bool rsaValid = rsa.KeySize == 4096
                && rsa.VerifyData(payload, envelope.RsaSignature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
            bool mldsaValid = Mldsa87.Verify(payload, envelope.MldsaSignature, policy.MldsaPublicKey.Span);
            bool trusted = rsaValid & mldsaValid;
            return trusted
                ? new HybridSignatureVerificationResult(true, true, true, certificate.Thumbprint, "RSA-PSS/SHA-512 and ML-DSA-87 signatures are valid.")
                : new HybridSignatureVerificationResult(false, rsaValid, mldsaValid, certificate.Thumbprint, "RSA-PSS/SHA-512 or ML-DSA-87 signature verification failed.");
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or ArgumentException or IOException)
        {
            return HybridSignatureVerificationResult.Invalid($"Hybrid signature is invalid: {ex.Message}");
        }
        finally
        {
            envelope?.Dispose();
            CryptographicOperations.ZeroMemory(encoded);
            if (payload is not null)
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }

    public static async Task<FileDigest> ComputeFileDigestAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (stream.ConfigureAwait(false))
        {
            return await ComputeFileDigestAsync(stream, cancellationToken).ConfigureAwait(false);
        }
    }

    public static async Task<FileDigest> ComputeFileDigestAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        byte[] buffer = new byte[1024 * 1024];
        long length = 0;
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                length = checked(length + read);
                hash.AppendData(buffer.AsSpan(0, read));
            }

            return new FileDigest(length, hash.GetHashAndReset());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static FileDigest ComputeFileDigest(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.SequentialScan);
        return ComputeFileDigest(stream);
    }

    public static FileDigest ComputeFileDigest(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        byte[] buffer = new byte[1024 * 1024];
        long length = 0;
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                length = checked(length + read);
                hash.AppendData(buffer.AsSpan(0, read));
            }

            return new FileDigest(length, hash.GetHashAndReset());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static byte[] CreatePayload(long fileLength, ReadOnlySpan<byte> sha512Digest)
    {
        if (fileLength < 0 || sha512Digest.Length != Sha512DigestBytes)
        {
            throw new ArgumentException("A hybrid-signature payload requires a non-negative length and a 64-byte SHA-512 digest.");
        }

        byte[] payload = new byte[checked(PayloadDomain.Length + sizeof(long) + Sha512DigestBytes)];
        PayloadDomain.CopyTo(payload, 0);
        BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(PayloadDomain.Length), fileLength);
        sha512Digest.CopyTo(payload.AsSpan(PayloadDomain.Length + sizeof(long)));
        return payload;
    }

    public static (byte[] Sha256, byte[] Sha3_512, byte[] Skein1024) Fingerprint(ReadOnlySpan<byte> value)
    {
        byte[] sha256 = SHA256.HashData(value);
        byte[] sha3 = Sha3_512Compat.HashData(value);
        var skein = new SkeinDigest(1024, 1024);
        byte[] input = value.ToArray();
        byte[] skeinResult = new byte[128];
        try
        {
            skein.BlockUpdate(input, 0, input.Length);
            _ = skein.DoFinal(skeinResult, 0);
            return (sha256, sha3, skeinResult);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sha256);
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skeinResult);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static (byte[] Sha256, byte[] Sha3_512, byte[] Skein1024) Fingerprint(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using IncrementalHash sha256Hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var sha3Hasher = new Sha3_512Incremental();
        var skeinHasher = new SkeinDigest(1024, 1024);
        byte[] buffer = new byte[1024 * 1024];
        byte[]? sha256 = null;
        byte[]? sha3 = null;
        byte[]? skein = null;
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha256Hasher.AppendData(buffer.AsSpan(0, read));
                sha3Hasher.AppendData(buffer.AsSpan(0, read));
                skeinHasher.BlockUpdate(buffer, 0, read);
            }

            sha256 = sha256Hasher.GetHashAndReset();
            sha3 = sha3Hasher.GetHashAndReset();
            skein = new byte[128];
            _ = skeinHasher.DoFinal(skein, 0);
            (byte[] Sha256, byte[] Sha3_512, byte[] Skein1024) result = (sha256, sha3, skein);
            sha256 = null;
            sha3 = null;
            skein = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (sha256 is not null) CryptographicOperations.ZeroMemory(sha256);
            if (sha3 is not null) CryptographicOperations.ZeroMemory(sha3);
            if (skein is not null) CryptographicOperations.ZeroMemory(skein);
        }
    }

    private static byte[] EncodeSidecar(
        FileDigest digest,
        byte[] certificate,
        byte[] rsaSignature,
        byte[] mldsaSignature)
    {
        if (certificate.Length is <= 0 or > MaximumCertificateBytes
            || rsaSignature.Length != Rsa4096SignatureBytes
            || mldsaSignature.Length != Mldsa87.SignatureBytes)
        {
            throw new CryptographicException("Hybrid signature component lengths are invalid.");
        }

        int length = checked(Magic.Length + sizeof(int) + sizeof(long) + Sha512DigestBytes
            + (3 * sizeof(int)) + certificate.Length + rsaSignature.Length + mldsaSignature.Length);
        byte[] output = new byte[length];
        int offset = 0;
        Magic.CopyTo(output, offset);
        offset += Magic.Length;
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(offset), FormatVersion);
        offset += sizeof(int);
        BinaryPrimitives.WriteInt64LittleEndian(output.AsSpan(offset), digest.Length);
        offset += sizeof(long);
        digest.Sha512.CopyTo(output.AsSpan(offset, Sha512DigestBytes));
        offset += Sha512DigestBytes;
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(offset), certificate.Length);
        offset += sizeof(int);
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(offset), rsaSignature.Length);
        offset += sizeof(int);
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(offset), mldsaSignature.Length);
        offset += sizeof(int);
        certificate.CopyTo(output, offset);
        offset += certificate.Length;
        rsaSignature.CopyTo(output, offset);
        offset += rsaSignature.Length;
        mldsaSignature.CopyTo(output, offset);
        return output;
    }

    private static HybridSignatureEnvelope DecodeSidecar(byte[] encoded)
    {
        int minimum = Magic.Length + sizeof(int) + sizeof(long) + Sha512DigestBytes + (3 * sizeof(int));
        if (encoded.Length < minimum
            || !CryptographicOperations.FixedTimeEquals(encoded.AsSpan(0, Magic.Length), Magic))
        {
            throw new InvalidDataException("Hybrid signature header is invalid.");
        }

        int offset = Magic.Length;
        int version = BinaryPrimitives.ReadInt32LittleEndian(encoded.AsSpan(offset));
        offset += sizeof(int);
        if (version != FormatVersion)
        {
            throw new InvalidDataException($"Unsupported hybrid signature version {version}.");
        }

        long fileLength = BinaryPrimitives.ReadInt64LittleEndian(encoded.AsSpan(offset));
        offset += sizeof(long);
        if (fileLength < 0)
        {
            throw new InvalidDataException("Hybrid signature contains a negative file length.");
        }

        byte[] digest = encoded.AsSpan(offset, Sha512DigestBytes).ToArray();
        offset += Sha512DigestBytes;
        int certificateLength = ReadLength(encoded, ref offset, 1, MaximumCertificateBytes);
        int rsaLength = ReadLength(encoded, ref offset, Rsa4096SignatureBytes, Rsa4096SignatureBytes);
        int mldsaLength = ReadLength(encoded, ref offset, Mldsa87.SignatureBytes, Mldsa87.SignatureBytes);
        int expectedRemaining = checked(certificateLength + rsaLength + mldsaLength);
        if (offset > encoded.Length - expectedRemaining || offset + expectedRemaining != encoded.Length)
        {
            CryptographicOperations.ZeroMemory(digest);
            throw new InvalidDataException("Hybrid signature is truncated or has trailing data.");
        }

        byte[] certificate = encoded.AsSpan(offset, certificateLength).ToArray();
        offset += certificateLength;
        byte[] rsa = encoded.AsSpan(offset, rsaLength).ToArray();
        offset += rsaLength;
        byte[] mldsa = encoded.AsSpan(offset, mldsaLength).ToArray();
        return new HybridSignatureEnvelope(fileLength, digest, certificate, rsa, mldsa);
    }

    private static int ReadLength(byte[] encoded, ref int offset, int minimum, int maximum)
    {
        if (offset > encoded.Length - sizeof(int))
        {
            throw new InvalidDataException("Hybrid signature length table is truncated.");
        }

        int value = BinaryPrimitives.ReadInt32LittleEndian(encoded.AsSpan(offset));
        offset += sizeof(int);
        if (value < minimum || value > maximum)
        {
            throw new InvalidDataException("Hybrid signature component length is invalid.");
        }

        return value;
    }

    private static void EnsureSha512RsaCertificate(X509Certificate2 certificate)
    {
        using RSA rsa = certificate.GetRSAPublicKey()
            ?? throw new CryptographicException("Hybrid signing requires an RSA certificate.");
        if (rsa.KeySize != 4096)
        {
            throw new CryptographicException("Hybrid signing requires an RSA-4096 certificate.");
        }

        if (!string.Equals(certificate.SignatureAlgorithm.Value, Sha512WithRsaOid, StringComparison.Ordinal))
        {
            throw new CryptographicException("The RSA code-signing certificate must itself use SHA-512 with RSA.");
        }

        bool permitsDigitalSignatures = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .Any(extension => (extension.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0);
        bool permitsCodeSigning = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .Any(usage => string.Equals(usage.Value, CodeSigningEkuOid, StringComparison.Ordinal));
        if (!permitsDigitalSignatures || !permitsCodeSigning)
        {
            throw new CryptographicException("The RSA certificate must permit digital signatures and the code-signing EKU.");
        }
    }

    private static async Task WriteAtomicallyAsync(string path, byte[] contents, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("The hybrid signature path has no parent directory.");
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await using (stream.ConfigureAwait(false))
            {
                await stream.WriteAsync(contents, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) is required for durable atomic signature publication.
                stream.Flush(flushToDisk: true);
#pragma warning restore CA1849
            }

            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private sealed class HybridSignatureEnvelope : IDisposable
    {
        public HybridSignatureEnvelope(long fileLength, byte[] digest, byte[] certificate, byte[] rsaSignature, byte[] mldsaSignature)
        {
            FileLength = fileLength;
            Sha512Digest = digest;
            Certificate = certificate;
            RsaSignature = rsaSignature;
            MldsaSignature = mldsaSignature;
        }

        public long FileLength { get; }
        public byte[] Sha512Digest { get; }
        public byte[] Certificate { get; }
        public byte[] RsaSignature { get; }
        public byte[] MldsaSignature { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Sha512Digest);
            CryptographicOperations.ZeroMemory(Certificate);
            CryptographicOperations.ZeroMemory(RsaSignature);
            CryptographicOperations.ZeroMemory(MldsaSignature);
        }
    }
}

public sealed class FileDigest : IDisposable
{
    private readonly byte[] _sha512;

    public FileDigest(long length, byte[] sha512)
    {
        ArgumentNullException.ThrowIfNull(sha512);
        if (length < 0 || sha512.Length != HybridSignatureService.Sha512DigestBytes)
        {
            throw new ArgumentException("Invalid SHA-512 file digest.");
        }

        Length = length;
        _sha512 = sha512;
    }

    public long Length { get; }
    public ReadOnlySpan<byte> Sha512 => _sha512;

    public void Dispose() => CryptographicOperations.ZeroMemory(_sha512);
}

public sealed class HybridSignaturePolicy
{
    private readonly byte[] _expectedRsaSha256;
    private readonly byte[] _expectedRsaSha3;
    private readonly byte[] _expectedRsaSkein;
    private readonly byte[] _expectedMldsaSha256;
    private readonly byte[] _expectedMldsaSha3;
    private readonly byte[] _expectedMldsaSkein;
    private readonly byte[] _mldsaPublicKey;

    public HybridSignaturePolicy(
        string expectedRsaSha256,
        string expectedRsaSha3512,
        string expectedRsaSkein1024,
        string expectedMldsaSha256,
        string expectedMldsaSha3512,
        string expectedMldsaSkein1024,
        ReadOnlySpan<byte> mldsaPublicKey)
    {
        _expectedRsaSha256 = ParseHex(expectedRsaSha256, 32, nameof(expectedRsaSha256));
        _expectedRsaSha3 = ParseHex(expectedRsaSha3512, 64, nameof(expectedRsaSha3512));
        _expectedRsaSkein = ParseHex(expectedRsaSkein1024, 128, nameof(expectedRsaSkein1024));
        _expectedMldsaSha256 = ParseHex(expectedMldsaSha256, 32, nameof(expectedMldsaSha256));
        _expectedMldsaSha3 = ParseHex(expectedMldsaSha3512, 64, nameof(expectedMldsaSha3512));
        _expectedMldsaSkein = ParseHex(expectedMldsaSkein1024, 128, nameof(expectedMldsaSkein1024));
        if (mldsaPublicKey.Length != Mldsa87.PublicKeyBytes)
        {
            throw new ArgumentException($"ML-DSA-87 public key must contain {Mldsa87.PublicKeyBytes} bytes.", nameof(mldsaPublicKey));
        }

        _mldsaPublicKey = mldsaPublicKey.ToArray();
        (byte[] sha256, byte[] sha3, byte[] skein) = HybridSignatureService.Fingerprint(_mldsaPublicKey);
        try
        {
            if (!(CryptographicOperations.FixedTimeEquals(sha256, _expectedMldsaSha256)
                & CryptographicOperations.FixedTimeEquals(sha3, _expectedMldsaSha3)
                & CryptographicOperations.FixedTimeEquals(skein, _expectedMldsaSkein)))
            {
                throw new CryptographicException("Embedded ML-DSA-87 public key does not match all three compiled fingerprints.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha256);
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    public ReadOnlyMemory<byte> MldsaPublicKey => _mldsaPublicKey;

    public bool MatchesRsaCertificate(X509Certificate2 certificate, out string error)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is null || rsa.KeySize != 4096)
        {
            error = "Hybrid signature certificate is not RSA-4096.";
            return false;
        }

        byte[] spki = rsa.ExportSubjectPublicKeyInfo();
        (byte[] sha256, byte[] sha3, byte[] skein) = HybridSignatureService.Fingerprint(spki);
        try
        {
            bool matches = CryptographicOperations.FixedTimeEquals(sha256, _expectedRsaSha256)
                & CryptographicOperations.FixedTimeEquals(sha3, _expectedRsaSha3)
                & CryptographicOperations.FixedTimeEquals(skein, _expectedRsaSkein);
            error = matches
                ? string.Empty
                : "Hybrid RSA signer does not match the compiled SHA-256/SHA3-512/Skein-1024 SPKI pins.";
            return matches;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
            CryptographicOperations.ZeroMemory(sha256);
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    private static byte[] ParseHex(string value, int expectedBytes, string name)
    {
        string normalized = NormalizeHex(value, checked(expectedBytes * 2), name);
        return Convert.FromHexString(normalized);
    }

    private static string NormalizeHex(string value, int expectedCharacters, string name)
    {
        string normalized = new string(value.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        if (normalized.Length != expectedCharacters || normalized.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new ArgumentException($"{name} must contain exactly {expectedCharacters} hexadecimal characters.", name);
        }

        return normalized;
    }
}

public sealed class HybridSignatureCreationResult : IDisposable
{
    private readonly byte[] _payload;
    private readonly byte[] _mldsaSignature;

    public HybridSignatureCreationResult(
        long fileLength,
        string sha512,
        string rsaThumbprint,
        byte[] payload,
        byte[] mldsaSignature)
    {
        ArgumentNullException.ThrowIfNull(sha512);
        ArgumentNullException.ThrowIfNull(rsaThumbprint);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(mldsaSignature);
        FileLength = fileLength;
        Sha512 = sha512;
        RsaThumbprint = rsaThumbprint;
        _payload = payload;
        _mldsaSignature = mldsaSignature;
    }

    public long FileLength { get; }
    public string Sha512 { get; }
    public string RsaThumbprint { get; }
    public ReadOnlySpan<byte> Payload => _payload;
    public ReadOnlySpan<byte> MldsaSignature => _mldsaSignature;

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_payload);
        CryptographicOperations.ZeroMemory(_mldsaSignature);
    }
}

public sealed record HybridSignatureVerificationResult(
    bool IsTrusted,
    bool RsaPssValid,
    bool Mldsa87Valid,
    string? RsaThumbprint,
    string Message)
{
    public static HybridSignatureVerificationResult Invalid(string message) => new(false, false, false, null, message);
}
