using System.Reflection;
using System.Security.Cryptography;
using System.IO;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

internal static class SigningTrustPolicy
{
    private const string Sha256MetadataKey = "KalynaExpectedSignerSha256";
    private const string Sha3MetadataKey = "KalynaExpectedSignerSha3_512";
    private const string SkeinMetadataKey = "KalynaExpectedSignerSkein1024";
    private const string MldsaSha256MetadataKey = "KalynaExpectedMldsa87Sha256";
    private const string MldsaSha3MetadataKey = "KalynaExpectedMldsa87Sha3_512";
    private const string MldsaSkeinMetadataKey = "KalynaExpectedMldsa87Skein1024";
    private const string MldsaPublicKeyResource = "KeepVault.MLDsa87.PublicKey";
    private static readonly string? ExpectedSha256 = ReadExpectedValue(Sha256MetadataKey, 64);
    private static readonly string? ExpectedSha3_512 = ReadExpectedValue(Sha3MetadataKey, 128);
    private static readonly string? ExpectedSkein1024 = ReadExpectedValue(SkeinMetadataKey, 256);
    private static readonly string? ExpectedMldsaSha256 = ReadExpectedValue(MldsaSha256MetadataKey, 64);
    private static readonly string? ExpectedMldsaSha3_512 = ReadExpectedValue(MldsaSha3MetadataKey, 128);
    private static readonly string? ExpectedMldsaSkein1024 = ReadExpectedValue(MldsaSkeinMetadataKey, 256);
    private static readonly Lazy<HybridSignaturePolicy?> HybridPolicyValue = new(LoadHybridPolicy, true);

    public static bool IsConfigured => ExpectedSha256 is not null
        && ExpectedSha3_512 is not null
        && ExpectedSkein1024 is not null
        && HybridPolicyValue.Value is not null;

    internal static HybridSignaturePolicy? HybridPolicy => HybridPolicyValue.Value;

    public static bool Matches(string? signerSha256, string? signerSha3_512, string? signerSkein1024)
    {
        return IsConfigured
            && !string.IsNullOrWhiteSpace(signerSha256)
            && !string.IsNullOrWhiteSpace(signerSha3_512)
            && !string.IsNullOrWhiteSpace(signerSkein1024)
            && string.Equals(ExpectedSha256, Normalize(signerSha256), StringComparison.Ordinal)
            && string.Equals(ExpectedSha3_512, Normalize(signerSha3_512), StringComparison.Ordinal)
            && string.Equals(ExpectedSkein1024, Normalize(signerSkein1024), StringComparison.Ordinal);
    }

    public static string Describe()
    {
        return IsConfigured
            ? $"SHA-256(RSA-SPKI)={ExpectedSha256}; SHA3-512(RSA-SPKI)={ExpectedSha3_512}; Skein-1024(RSA-SPKI)={ExpectedSkein1024}; SHA-256(ML-DSA-87)={ExpectedMldsaSha256}; SHA3-512(ML-DSA-87)={ExpectedMldsaSha3_512}; Skein-1024(ML-DSA-87)={ExpectedMldsaSkein1024}"
            : "not configured";
    }

    private static HybridSignaturePolicy? LoadHybridPolicy()
    {
        if (ExpectedSha256 is null
            || ExpectedSha3_512 is null
            || ExpectedSkein1024 is null
            || ExpectedMldsaSha256 is null
            || ExpectedMldsaSha3_512 is null
            || ExpectedMldsaSkein1024 is null)
        {
            return null;
        }

        Assembly assembly = typeof(SigningTrustPolicy).Assembly;
        using Stream? resource = assembly.GetManifestResourceStream(MldsaPublicKeyResource);
        if (resource is null || resource.Length != Mldsa87.PublicKeyBytes)
        {
            return null;
        }

        byte[] publicKey = new byte[Mldsa87.PublicKeyBytes];
        try
        {
            resource.ReadExactly(publicKey);
            return new HybridSignaturePolicy(
                ExpectedSha256,
                ExpectedSha3_512,
                ExpectedSkein1024,
                ExpectedMldsaSha256,
                ExpectedMldsaSha3_512,
                ExpectedMldsaSkein1024,
                publicKey);
        }
        catch (CryptographicException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static string? ReadExpectedValue(string metadataKey, int expectedHexLength)
    {
        Assembly assembly = typeof(SigningTrustPolicy).Assembly;
        string? configured = assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, metadataKey, StringComparison.Ordinal))
            ?.Value;
        if (string.IsNullOrWhiteSpace(configured))
        {
            return null;
        }

        string normalized = Normalize(configured);
        return normalized.Length == expectedHexLength ? normalized : null;
    }

    private static string Normalize(string value)
    {
        string normalized = new(value.Where(c => !char.IsWhiteSpace(c)).ToArray());
        return normalized.All(Uri.IsHexDigit)
            ? normalized.ToUpperInvariant()
            : string.Empty;
    }
}
