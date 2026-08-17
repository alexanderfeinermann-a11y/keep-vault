using System.IO;

namespace KalynaArchiver.Services;

public enum EncryptionSuite
{
    Kalyna512_512 = 0,
    Threefish1024 = 1,

    /// <summary>
    /// Threefish-1024 applied over Kalyna-512/512, each in CTR mode with its
    /// own key and its own nonce.
    /// </summary>
    /// <remarks>
    /// Both layers are keystream generators, so the composition amounts to the
    /// plaintext masked by two independently keyed keystreams. That is the
    /// point: the construction survives either cipher being broken outright,
    /// which no single-cipher suite can claim. It costs one extra pass over the
    /// data and 192 bytes of key material instead of 128.
    /// </remarks>
    ThreefishOverKalyna = 2,
}

/// <summary>
/// How a cascade divides its derived key and its nonce between the two layers.
/// </summary>
/// <remarks>
/// Written out rather than inferred at the call sites: an off-by-one in this
/// split would hand one layer part of the other layer's key and still produce
/// a container that decrypts correctly on the same build, which is exactly the
/// kind of fault that only surfaces years later on a different one.
/// </remarks>
internal sealed record CascadeLayout(
    int InnerKeyBytes,
    int InnerNonceBytes,
    int InnerBlockBytes,
    int OuterKeyBytes,
    int OuterNonceBytes,
    int OuterBlockBytes)
{
    public int TotalKeyBytes => checked(InnerKeyBytes + OuterKeyBytes);

    public int TotalNonceBytes => checked(InnerNonceBytes + OuterNonceBytes);
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
    int TweakBytes,
    CascadeLayout? Cascade = null)
{
    public int DerivedKeyBytes => checked(EncryptionKeyBytes + Sha3MacKeyBytes + SkeinMacKeyBytes);
}

internal static class EncryptionSuiteCatalog
{
    public const string KalynaAlgorithm = "Kalyna-512/512-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string ThreefishAlgorithm = "Threefish-1024-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string CascadeAlgorithm =
        "Threefish-1024-CTR(Kalyna-512/512-CTR)+HMAC-SHA3-512+Skein-MAC-1024";
    public const string KdfInputMode = "SHA3-512-LP(UserPassword,FactorA)||SHA3-512-LP(UserPassword,FactorB)";
    public const string CounterEndian = "BigEndian";
    public const string ThreefishTweakMode = "SHA3-512-LP(Domain,Nonce)[0..15]";

    /// <summary>
    /// The suite offered unless the user chooses otherwise.
    /// </summary>
    /// <remarks>
    /// The cascade is the default because it is the only suite whose security
    /// does not rest on a single cipher. Its cost is one additional pass over
    /// the data, which is a fraction of what compression and Argon2id already
    /// spend.
    /// </remarks>
    public const EncryptionSuite Default = EncryptionSuite.ThreefishOverKalyna;

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

    // BlockBytes and the key and nonce sizes describe the composite: the header
    // reports the outer block, and the 192-byte key and 192-byte nonce are the
    // two layers' shares laid end to end. The algorithm string pins which share
    // belongs to which layer, and Cascade states it in code.
    private static readonly EncryptionSuiteParameters Cascade = new(
        EncryptionSuite.ThreefishOverKalyna,
        CascadeAlgorithm,
        "Threefish 1024 over Kalyna 512/512",
        BlockBytes: 128,
        NonceBytes: 192,
        EncryptionKeyBytes: 192,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16,
        Cascade: new CascadeLayout(
            InnerKeyBytes: 64,
            InnerNonceBytes: 64,
            InnerBlockBytes: 64,
            OuterKeyBytes: 128,
            OuterNonceBytes: 128,
            OuterBlockBytes: 128));

    public static EncryptionSuiteParameters Get(EncryptionSuite suite)
    {
        return suite switch
        {
            EncryptionSuite.Kalyna512_512 => Kalyna,
            EncryptionSuite.Threefish1024 => Threefish,
            EncryptionSuite.ThreefishOverKalyna => Cascade,
            _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite."),
        };
    }

    public static EncryptionSuiteParameters FromAlgorithm(string? algorithm)
    {
        return algorithm switch
        {
            KalynaAlgorithm => Kalyna,
            ThreefishAlgorithm => Threefish,
            CascadeAlgorithm => Cascade,
            _ => throw new InvalidDataException("Container header specifies an unsupported encryption suite."),
        };
    }

    public static bool IsKnown(EncryptionSuite suite) =>
        suite is EncryptionSuite.Kalyna512_512
            or EncryptionSuite.Threefish1024
            or EncryptionSuite.ThreefishOverKalyna;
}
