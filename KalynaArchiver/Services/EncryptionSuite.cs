using System.IO;

namespace KalynaArchiver.Services;

public enum EncryptionSuite
{
    Kalyna512_512 = 0,
    Threefish1024 = 1,
}

internal sealed record EncryptionSuiteParameters(
    EncryptionSuite Suite,
    string Algorithm,
    string DisplayName,
    int BlockBytes,
    int NonceBytes,
    int EncryptionKeyBytes,
    int Sha3MacKeyBytes,
    int SkeinMacKeyBytes,
    int TweakBytes)
{
    public int DerivedKeyBytes => checked(EncryptionKeyBytes + Sha3MacKeyBytes + SkeinMacKeyBytes);
}

internal static class EncryptionSuiteCatalog
{
    public const string KalynaAlgorithm = "Kalyna-512/512-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string ThreefishAlgorithm = "Threefish-1024-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string KdfInputMode = "SHA3-512-LP(UserPassword,FactorA)||SHA3-512-LP(UserPassword,FactorB)";
    public const string CounterEndian = "BigEndian";
    public const string ThreefishTweakMode = "SHA3-512-LP(Domain,Nonce)[0..15]";

    private static readonly EncryptionSuiteParameters Kalyna = new(
        EncryptionSuite.Kalyna512_512,
        KalynaAlgorithm,
        "Kalyna 512/512",
        BlockBytes: 64,
        NonceBytes: 64,
        EncryptionKeyBytes: 64,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 0);

    private static readonly EncryptionSuiteParameters Threefish = new(
        EncryptionSuite.Threefish1024,
        ThreefishAlgorithm,
        "Threefish 1024",
        BlockBytes: 128,
        NonceBytes: 128,
        EncryptionKeyBytes: 128,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16);

    public static EncryptionSuiteParameters Get(EncryptionSuite suite)
    {
        return suite switch
        {
            EncryptionSuite.Kalyna512_512 => Kalyna,
            EncryptionSuite.Threefish1024 => Threefish,
            _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite."),
        };
    }

    public static EncryptionSuiteParameters FromAlgorithm(string? algorithm)
    {
        return algorithm switch
        {
            KalynaAlgorithm => Kalyna,
            ThreefishAlgorithm => Threefish,
            _ => throw new InvalidDataException("Container header specifies an unsupported encryption suite."),
        };
    }
}
