using System.IO;
using System.Linq;

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

    /// <summary>
    /// ChaCha20-Poly1305(Threefish-1024(Kalyna-512/512(SHACAL-2-512(MARS-448(AES-256))))).
    /// </summary>
    /// <remarks>
    /// Six independent ciphers and two Argon2id rounds. It is the only suite
    /// whose key material does not fit in one Argon2id output, and the only one
    /// whose outermost layer authenticates as well as encrypts.
    /// </remarks>
    ParanoiaCascade = 3,
}

/// <summary>
/// One layer of a cascade: which cipher, and the key and nonce it owns.
/// </summary>
/// <remarks>
/// Cascades are described as an ordered list of these rather than as named
/// inner and outer halves, because v9 has one with six layers. The order is
/// the order the plaintext travels: index 0 is applied first and is therefore
/// the innermost, and the last entry is what an attacker meets first.
/// </remarks>
internal sealed record CascadeStage(
    CascadeCipher Cipher,
    int KeyBytes,
    int NonceBytes,
    int BlockBytes);

internal enum CascadeCipher
{
    Aes256,
    Mars448,
    Shacal2_512,
    Kalyna512_512,
    Threefish1024,
    ChaCha20Poly1305,
}

/// <summary>
/// How a cascade divides its derived key and its nonce between its layers.
/// </summary>
/// <remarks>
/// Written out rather than inferred at the call sites: an off-by-one in this
/// split would hand one layer part of another layer's key and still produce a
/// container that decrypts correctly on the same build, which is exactly the
/// kind of fault that only surfaces years later on a different one.
/// </remarks>
internal sealed record CascadeLayout(IReadOnlyList<CascadeStage> Stages)
{
    public int TotalKeyBytes => Stages.Sum(stage => stage.KeyBytes);

    public int TotalNonceBytes => Stages.Sum(stage => stage.NonceBytes);

    /// <summary>
    /// Whether the outermost layer authenticates as well as encrypts, which
    /// means every chunk carries a tag the container has to store.
    /// </summary>
    public bool OutermostIsAead => Stages[^1].Cipher == CascadeCipher.ChaCha20Poly1305;
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
    CascadeLayout? Cascade = null,
    bool UsesTwoKdfRounds = false)
{
    public int DerivedKeyBytes => checked(EncryptionKeyBytes + Sha3MacKeyBytes + SkeinMacKeyBytes);
}

internal static class EncryptionSuiteCatalog
{
    public const string KalynaAlgorithm = "Kalyna-512/512-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string ThreefishAlgorithm = "Threefish-1024-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string CascadeAlgorithm =
        "Threefish-1024-CTR(Kalyna-512/512-CTR)+HMAC-SHA3-512+Skein-MAC-1024";
    public const string ParanoiaAlgorithm =
        "ChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(SHACAL-2-512-CTR("
        + "MARS-448-CTR(AES-256-CTR)))))+HMAC-SHA3-512+Skein-MAC-1024";
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
        Cascade: new CascadeLayout([
            new CascadeStage(CascadeCipher.Kalyna512_512, KeyBytes: 64, NonceBytes: 64, BlockBytes: 64),
            new CascadeStage(CascadeCipher.Threefish1024, KeyBytes: 128, NonceBytes: 128, BlockBytes: 128),
        ]));

    /// <summary>
    /// Six ciphers, innermost first, with ChaCha20-Poly1305 authenticating
    /// every chunk on the way out.
    /// </summary>
    /// <remarks>
    /// The five inner layers are keystream generators in CTR, so the composite
    /// is the plaintext masked five times over with independently derived keys.
    /// Breaking any one of them, or any five of them, leaves the attacker
    /// holding the next layer's ciphertext.
    ///
    /// The outermost layer is the RFC 8439 AEAD, kept whole rather than split
    /// into ChaCha20 and Poly1305. That composition derives the Poly1305
    /// one-time key from block counter 0, starts encrypting at counter 1, and
    /// binds the associated data, its length and the ciphertext length into the
    /// tag. Reassembling that by hand adds a failure point at each of those
    /// steps for no gain.
    ///
    /// It is applied per chunk, not once over the archive, for a reason that
    /// decides the format: IETF ChaCha20 has a 32-bit block counter, so one
    /// key/nonce pair covers 2^32 * 64 bytes = 256 GiB. A single AEAD over a
    /// multi-terabyte archive would run past that. Per-chunk nonces remove the
    /// ceiling, and the per-chunk associated data binds each chunk to its
    /// archive, its file and its index so a chunk cannot be moved somewhere
    /// else and still verify.
    ///
    /// Poly1305 is therefore the local, per-chunk authenticator, while
    /// HMAC-SHA3-512 and Skein-MAC-1024 remain the global ones over the whole
    /// container.
    /// </remarks>
    private static readonly EncryptionSuiteParameters Paranoia = new(
        EncryptionSuite.ParanoiaCascade,
        ParanoiaAlgorithm,
        "Paranoia: ChaCha20-Poly1305 over Threefish, Kalyna, SHACAL-2, MARS and AES",
        // The widest block in the stack; the header reports the composite, and
        // Cascade below is what states each layer's own share.
        BlockBytes: 128,
        NonceBytes: 268,
        EncryptionKeyBytes: 376,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16,
        Cascade: new CascadeLayout([
            new CascadeStage(CascadeCipher.Aes256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Mars448, KeyBytes: 56, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Shacal2_512, KeyBytes: 64, NonceBytes: 32, BlockBytes: 32),
            new CascadeStage(CascadeCipher.Kalyna512_512, KeyBytes: 64, NonceBytes: 64, BlockBytes: 64),
            new CascadeStage(CascadeCipher.Threefish1024, KeyBytes: 128, NonceBytes: 128, BlockBytes: 128),
            new CascadeStage(CascadeCipher.ChaCha20Poly1305, KeyBytes: 32, NonceBytes: 12, BlockBytes: 64),
        ]),
        UsesTwoKdfRounds: true);

    public static EncryptionSuiteParameters Get(EncryptionSuite suite)
    {
        return suite switch
        {
            EncryptionSuite.Kalyna512_512 => Kalyna,
            EncryptionSuite.Threefish1024 => Threefish,
            EncryptionSuite.ThreefishOverKalyna => Cascade,
            EncryptionSuite.ParanoiaCascade => Paranoia,
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
            ParanoiaAlgorithm => Paranoia,
            _ => throw new InvalidDataException("Container header specifies an unsupported encryption suite."),
        };
    }

    /// <summary>
    /// The largest nonce any suite needs.
    /// </summary>
    /// <remarks>
    /// The entropy for an archive is prepared before the user has chosen a
    /// suite, so the prepared nonce has to be big enough for whichever one they
    /// pick. Derived from the catalogue rather than written as a number, so
    /// adding a suite with a wider nonce cannot leave the pool one byte short.
    /// </remarks>
    public static int MaxNonceBytes { get; } =
        Enum.GetValues<EncryptionSuite>().Where(IsKnown).Max(suite => Get(suite).NonceBytes);

    public static bool IsKnown(EncryptionSuite suite) =>
        suite is EncryptionSuite.Kalyna512_512
            or EncryptionSuite.Threefish1024
            or EncryptionSuite.ThreefishOverKalyna
            or EncryptionSuite.ParanoiaCascade;
}
