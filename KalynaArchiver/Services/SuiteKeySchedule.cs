using System.Security.Cryptography;
using System.Text;

namespace KalynaArchiver.Services;

/// <summary>
/// What a single key role is for. Part of the canonical role context, so two
/// roles can never derive the same bytes.
/// </summary>
internal enum KeyRolePurpose
{
    Encryption,
    Sha3Mac,
    SkeinMac,
    RecoverySha3Certification,
    RecoverySkeinCertification,
}

/// <summary>
/// Turns the 1024-bit v11 master into the individual cipher, MAC and recovery
/// keys.
/// </summary>
/// <remarks>
/// v9 sliced one flat Argon2id output into cipher and MAC keys, so the same
/// cipher in two positions could end up sharing structure and every role's key
/// was a function of where it happened to sit in that buffer. v11 derives each
/// role separately from a canonical, domain-separated context instead.
///
/// Each role runs through two independent PRF families and the results are
/// XORed:
///
///   U_j — HKDF-Expand with HMAC-SHA3-512 over the two master halves,
///   V_j — keyed Skein-MAC-1024-1024 over the whole master,
///   Z_j = U_j XOR V_j.
///
/// Only after that full 1024-bit value exists is it truncated to the target
/// cipher's key width. Truncating earlier would cap the wide roles at whichever
/// primitive produced them.
///
/// The XOR is a Keep Vault decision, not a proof: it is documented as combining
/// two 1024-bit PRF outputs into one 1024-bit role value under the assumption
/// that both families behave as assumed and the contexts are unique. It is
/// deliberately not claimed to be a robust combiner against arbitrary
/// catastrophic or maliciously correlated primitives.
/// </remarks>
internal static class SuiteKeySchedule
{
    public const int MasterBytes = 128;
    public const int RoleBytes = 128;

    /// <summary>
    /// The role schedule belongs to the container generation it serves, so
    /// every domain string and the context's own version field say v11.
    /// </summary>
    /// <remarks>
    /// There is one generation and no second set of domains to select between.
    /// That is deliberate: a schedule that could still be asked for older
    /// domains is a second derivation to attack and a second thing to get
    /// wrong, and nothing in this build can read an older container anyway.
    /// </remarks>
    public const int ContextVersion = 11;

    private const string RoleDomain = "Kalyna-ZPAQ/v11/RoleKey";
    private const string Sha3RoleDomain = "Kalyna-ZPAQ/v11/RoleKey/HKDF-HMAC-SHA3-512";
    private const string SkeinRoleDomain = "Kalyna-ZPAQ/v11/RoleKey/Skein-MAC-1024-1024";

    /// <summary>
    /// The stage index reserved for keys that belong to the container as a
    /// whole rather than to one cascade stage.
    /// </summary>
    private const int GlobalStageIndex = unchecked((int)0xFFFFFFFF);

    public static string CanonicalPurposeString(KeyRolePurpose purpose) => purpose switch
    {
        KeyRolePurpose.Encryption => "Encryption",
        KeyRolePurpose.Sha3Mac => "Sha3Mac",
        KeyRolePurpose.SkeinMac => "SkeinMac",
        KeyRolePurpose.RecoverySha3Certification => "RecoverySha3Certification",
        KeyRolePurpose.RecoverySkeinCertification => "RecoverySkeinCertification",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, null)
    };

    public static string CanonicalCipherString(CascadeCipher cipher) => cipher switch
    {
        CascadeCipher.Kalyna512_512 => "Kalyna-512/512",
        CascadeCipher.Threefish1024 => "Threefish-1024",
        CascadeCipher.Aes256 => "AES-256",
        CascadeCipher.Mars448 => "MARS-448",
        CascadeCipher.Shacal2_512 => "SHACAL-2-512",
        CascadeCipher.ChaCha20Poly1305 => "ChaCha20-Poly1305",
        _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, null)
    };

    /// <summary>
    /// The canonical context that makes one role distinct from every other.
    /// Format: LP(D_ROLE) || LE32(version) || LP(Algorithm) || LE32(StageIndex) || LP(Cipher) || LP(Purpose) || LE32(KeyBits)
    /// </summary>
    /// <remarks>
    /// KeyBits is part of the context on purpose: a role that asks for 256 bits
    /// and one that asks for 512 must not produce a prefix relationship, which
    /// is exactly what would happen if the same context were truncated twice.
    /// </remarks>
    public static byte[] BuildRoleContext(
        string algorithm,
        int stageIndex,
        string cipher,
        KeyRolePurpose purpose,
        int keyBits)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);
        ArgumentException.ThrowIfNullOrEmpty(cipher);

        byte[] roleDomainBytes = Encoding.UTF8.GetBytes(RoleDomain);
        byte[] algorithmBytes = Encoding.UTF8.GetBytes(algorithm);
        byte[] cipherBytes = Encoding.UTF8.GetBytes(cipher);
        byte[] purposeBytes = Encoding.UTF8.GetBytes(CanonicalPurposeString(purpose));

        int totalLength = (sizeof(int) + roleDomainBytes.Length)
            + sizeof(int)
            + (sizeof(int) + algorithmBytes.Length)
            + sizeof(int)
            + (sizeof(int) + cipherBytes.Length)
            + (sizeof(int) + purposeBytes.Length)
            + sizeof(int);

        byte[] result = new byte[totalLength];
        int offset = 0;

        WriteLengthPrefixed(result, ref offset, roleDomainBytes);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset), ContextVersion);
        offset += sizeof(int);
        WriteLengthPrefixed(result, ref offset, algorithmBytes);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset), stageIndex);
        offset += sizeof(int);
        WriteLengthPrefixed(result, ref offset, cipherBytes);
        WriteLengthPrefixed(result, ref offset, purposeBytes);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset), keyBits);
        offset += sizeof(int);

        return result;
    }

    private static void WriteLengthPrefixed(Span<byte> destination, ref int offset, ReadOnlySpan<byte> data)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(destination.Slice(offset), data.Length);
        offset += sizeof(int);
        data.CopyTo(destination.Slice(offset));
        offset += data.Length;
    }

    public static byte[] RoleContext(
        string algorithm,
        int stageIndex,
        string cipher,
        KeyRolePurpose purpose,
        int keyBits) =>
        BuildRoleContext(algorithm, stageIndex, cipher, purpose, keyBits);

    public static byte[] GlobalRoleContext(string algorithm, string cipher, KeyRolePurpose purpose, int keyBits) =>
        RoleContext(algorithm, GlobalStageIndex, cipher, purpose, keyBits);

    /// <summary>
    /// The full 1024-bit role value, before any truncation.
    /// </summary>
    public static void DeriveRoleValue(ReadOnlySpan<byte> master, ReadOnlySpan<byte> roleContext, Span<byte> destination)
    {
        if (master.Length != MasterBytes)
        {
            throw new ArgumentException($"The container master must be {MasterBytes} bytes.", nameof(master));
        }

        if (destination.Length < RoleBytes)
        {
            throw new ArgumentException($"Destination must be at least {RoleBytes} bytes.", nameof(destination));
        }

        // Each half already carries 32 bytes from each Argon2id branch, because
        // the master was interleaved. Splitting here rather than de-interleaving
        // is what makes both HKDF halves depend on both branches.
        using var sha3Side = LockedSensitiveBuffer.Create(RoleBytes);
        using var skeinSide = LockedSensitiveBuffer.Create(RoleBytes);

        DeriveSha3Side(master, roleContext, sha3Side.Bytes);
        KeyedSkein1024.Compute(master, SkeinRoleDomain, roleContext, skeinSide.Bytes);

        if (sha3Side.Bytes.Length != RoleBytes || skeinSide.Bytes.Length != RoleBytes)
        {
            throw new CryptographicException("A role key branch returned the wrong width.");
        }

        for (int i = 0; i < RoleBytes; i++)
        {
            destination[i] = (byte)(sha3Side.Bytes[i] ^ skeinSide.Bytes[i]);
        }
    }

    public static byte[] DeriveRoleValue(ReadOnlySpan<byte> master, ReadOnlySpan<byte> roleContext)
    {
        byte[] result = new byte[RoleBytes];
        DeriveRoleValue(master, roleContext, result);
        return result;
    }

    private static void DeriveSha3Side(ReadOnlySpan<byte> master, ReadOnlySpan<byte> roleContext, Span<byte> destination)
    {
        if (destination.Length < RoleBytes)
        {
            throw new ArgumentException($"Destination must be at least {RoleBytes} bytes.", nameof(destination));
        }

        byte[] info0 = BuildSha3Info(roleContext, "Half-0");
        byte[] info1 = BuildSha3Info(roleContext, "Half-1");
        try
        {
            Sha3HkdfExpand.Expand(master[..64], info0, destination.Slice(0, 64));
            Sha3HkdfExpand.Expand(master[64..], info1, destination.Slice(64, 64));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(info0);
            CryptographicOperations.ZeroMemory(info1);
        }
    }

    private static byte[] BuildSha3Info(ReadOnlySpan<byte> roleContext, string halfLabel)
    {
        byte[] domainBytes = Encoding.UTF8.GetBytes(Sha3RoleDomain);
        byte[] labelBytes = Encoding.UTF8.GetBytes(halfLabel);
        int totalLength = (sizeof(int) + domainBytes.Length)
            + (sizeof(int) + roleContext.Length)
            + (sizeof(int) + labelBytes.Length);
        byte[] info = new byte[totalLength];
        int offset = 0;
        WriteLengthPrefixed(info, ref offset, domainBytes);
        WriteLengthPrefixed(info, ref offset, roleContext);
        WriteLengthPrefixed(info, ref offset, labelBytes);
        return info;
    }

    /// <summary>
    /// A role value truncated to the target primitive's key width.
    /// </summary>
    public static void DeriveRoleKey(
        ReadOnlySpan<byte> master,
        string algorithm,
        int stageIndex,
        string cipher,
        KeyRolePurpose purpose,
        Span<byte> destination)
    {
        if (destination.IsEmpty || destination.Length > RoleBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }

        byte[] context = RoleContext(algorithm, stageIndex, cipher, purpose, destination.Length * 8);
        using var roleValue = LockedSensitiveBuffer.Create(RoleBytes);
        try
        {
            DeriveRoleValue(master, context, roleValue.Bytes);
            roleValue.Bytes.AsSpan(0, destination.Length).CopyTo(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(context);
        }
    }

    public static byte[] DeriveRoleKey(
        ReadOnlySpan<byte> master,
        string algorithm,
        int stageIndex,
        string cipher,
        KeyRolePurpose purpose,
        int keyBytes)
    {
        byte[] result = new byte[keyBytes];
        DeriveRoleKey(master, algorithm, stageIndex, cipher, purpose, result);
        return result;
    }

    /// <summary>
    /// Fills the flat cascade encryption-key buffer the container already uses,
    /// one stage at a time, plus the two global MAC keys.
    /// </summary>
    /// <remarks>
    /// The flat buffer and its per-stage offsets stay exactly as they are —
    /// what changes is only how each slice is produced. Keeping the layout means
    /// <c>XCryptCascade</c> and every stage-slicing test remain valid.
    /// </remarks>
    public static RoleKeyMaterial DeriveSuiteKeys(
        ReadOnlySpan<byte> master,
        EncryptionSuiteParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var encryptionKey = LockedSensitiveBuffer.Create(parameters.EncryptionKeyBytes);
        LockedSensitiveBuffer? sha3MacKey = null;
        LockedSensitiveBuffer? skeinMacKey = null;
        try
        {
            int offset = 0;
            IReadOnlyList<CascadeStage> stages = StagesOf(parameters);
            for (int stageIndex = 0; stageIndex < stages.Count; stageIndex++)
            {
                CascadeStage stage = stages[stageIndex];
                DeriveRoleKey(
                    master,
                    parameters.Algorithm,
                    stageIndex,
                    CanonicalCipherString(stage.Cipher),
                    KeyRolePurpose.Encryption,
                    encryptionKey.Bytes.AsSpan(offset, stage.KeyBytes));

                offset += stage.KeyBytes;
            }

            if (offset != parameters.EncryptionKeyBytes)
            {
                throw new CryptographicException(
                    $"{parameters.Suite} stage keys filled {offset} of {parameters.EncryptionKeyBytes} bytes.");
            }

            sha3MacKey = LockedSensitiveBuffer.Create(parameters.Sha3MacKeyBytes);
            DeriveGlobalKey(
                master, parameters.Algorithm, "HMAC-SHA3-512",
                KeyRolePurpose.Sha3Mac, sha3MacKey.Bytes.AsSpan(0, parameters.Sha3MacKeyBytes));

            skeinMacKey = LockedSensitiveBuffer.Create(parameters.SkeinMacKeyBytes);
            DeriveGlobalKey(
                master, parameters.Algorithm, "Skein-MAC-1024-1024",
                KeyRolePurpose.SkeinMac, skeinMacKey.Bytes.AsSpan(0, parameters.SkeinMacKeyBytes));

            var result = new RoleKeyMaterial(encryptionKey, sha3MacKey, skeinMacKey);
            encryptionKey = null!;
            sha3MacKey = null;
            skeinMacKey = null;
            return result;
        }
        finally
        {
            encryptionKey?.Dispose();
            sha3MacKey?.Dispose();
            skeinMacKey?.Dispose();
        }
    }

    /// <summary>
    /// The stages a suite's encryption key is divided into.
    /// </summary>
    /// <remarks>
    /// A single-cipher suite has no cascade layout, because there is nothing to
    /// lay out. It still has exactly one stage, and treating it as one keeps a
    /// single code path here: the alternative is a branch that derives the
    /// cascade suites one way and the rest another, which is where this project
    /// has repeatedly gone wrong before.
    ///
    /// The synthetic stage's cipher label comes from the suite itself, so no two
    /// suites can produce the same role context.
    /// </remarks>
    private static IReadOnlyList<CascadeStage> StagesOf(EncryptionSuiteParameters parameters)
    {
        if (parameters.Cascade is { Stages.Count: > 0 } layout)
        {
            return layout.Stages;
        }

        CascadeCipher cipher = parameters.Suite switch
        {
            EncryptionSuite.Kalyna512_512 => CascadeCipher.Kalyna512_512,
            EncryptionSuite.Threefish1024 => CascadeCipher.Threefish1024,
            EncryptionSuite.Aes256 => CascadeCipher.Aes256,
            EncryptionSuite.Mars448 => CascadeCipher.Mars448,
            EncryptionSuite.Shacal2_512 => CascadeCipher.Shacal2_512,
            EncryptionSuite.ChaCha20Poly1305 => CascadeCipher.ChaCha20Poly1305,
            _ => throw new CryptographicException(
                $"{parameters.Suite} has neither a cascade layout nor a known single cipher."),
        };

        return [new CascadeStage(
            cipher,
            parameters.EncryptionKeyBytes,
            parameters.NonceBytes,
            parameters.BlockBytes)];
    }

    public static void DeriveGlobalKey(
        ReadOnlySpan<byte> master,
        string algorithm,
        string cipher,
        KeyRolePurpose purpose,
        Span<byte> destination)
    {
        if (destination.IsEmpty || destination.Length > RoleBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }

        byte[] context = GlobalRoleContext(algorithm, cipher, purpose, destination.Length * 8);
        using var roleValue = LockedSensitiveBuffer.Create(RoleBytes);
        try
        {
            DeriveRoleValue(master, context, roleValue.Bytes);
            roleValue.Bytes.AsSpan(0, destination.Length).CopyTo(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(context);
        }
    }

    public static byte[] DeriveGlobalKey(
        ReadOnlySpan<byte> master,
        string algorithm,
        string cipher,
        KeyRolePurpose purpose,
        int keyBytes)
    {
        byte[] result = new byte[keyBytes];
        DeriveGlobalKey(master, algorithm, cipher, purpose, result);
        return result;
    }
}

/// <summary>
/// The keys one suite needs, each in locked memory and owned by the caller.
/// </summary>
internal sealed class RoleKeyMaterial : IDisposable
{
    public RoleKeyMaterial(
        LockedSensitiveBuffer encryptionKey,
        LockedSensitiveBuffer sha3MacKey,
        LockedSensitiveBuffer skeinMacKey)
    {
        EncryptionKey = encryptionKey;
        Sha3MacKey = sha3MacKey;
        SkeinMacKey = skeinMacKey;
    }

    public LockedSensitiveBuffer EncryptionKey { get; }

    public LockedSensitiveBuffer Sha3MacKey { get; }

    public LockedSensitiveBuffer SkeinMacKey { get; }

    public void Dispose()
    {
        SkeinMacKey.Dispose();
        Sha3MacKey.Dispose();
        EncryptionKey.Dispose();
    }
}
