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
/// Turns the 1024-bit v10 master into the individual cipher, MAC and recovery
/// keys.
/// </summary>
/// <remarks>
/// v9 sliced one flat Argon2id output into cipher and MAC keys, so the same
/// cipher in two positions could end up sharing structure and every role's key
/// was a function of where it happened to sit in that buffer. v10 derives each
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

    private const string RoleDomain = "Kalyna-ZPAQ/v10/RoleKey";
    private const string Sha3RoleDomain = "Kalyna-ZPAQ/v10/RoleKey/HKDF-HMAC-SHA3-512";
    private const string SkeinRoleDomain = "Kalyna-ZPAQ/v10/RoleKey/Skein-MAC-1024-1024";

    /// <summary>
    /// The stage index reserved for keys that belong to the container as a
    /// whole rather than to one cascade stage.
    /// </summary>
    private const int GlobalStageIndex = unchecked((int)0xFFFFFFFF);

    /// <summary>
    /// The canonical context that makes one role distinct from every other.
    /// Format: LP(D_ROLE) || LE32(10) || LP(Algorithm) || LE32(StageIndex) || LP(Cipher) || LP(Purpose) || LE32(KeyBits)
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
        byte[] purposeBytes = Encoding.UTF8.GetBytes(purpose.ToString());

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
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset), 10);
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
    public static byte[] DeriveRoleValue(ReadOnlySpan<byte> master, ReadOnlySpan<byte> roleContext)
    {
        if (master.Length != MasterBytes)
        {
            throw new ArgumentException($"The v10 master must be {MasterBytes} bytes.", nameof(master));
        }

        // Each half already carries 32 bytes from each Argon2id branch, because
        // the master was interleaved. Splitting here rather than de-interleaving
        // is what makes both HKDF halves depend on both branches.
        byte[] sha3Side = DeriveSha3Side(master, roleContext);
        byte[] skeinSide = KeyedSkein1024.Compute(master, SkeinRoleDomain, roleContext);
        try
        {
            if (sha3Side.Length != RoleBytes || skeinSide.Length != RoleBytes)
            {
                throw new CryptographicException("A role key branch returned the wrong width.");
            }

            byte[] combined = new byte[RoleBytes];
            for (int i = 0; i < RoleBytes; i++)
            {
                combined[i] = (byte)(sha3Side[i] ^ skeinSide[i]);
            }

            return combined;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3Side);
            CryptographicOperations.ZeroMemory(skeinSide);
        }
    }

    private static byte[] DeriveSha3Side(ReadOnlySpan<byte> master, ReadOnlySpan<byte> roleContext)
    {
        byte[] info0 = BuildSha3Info(roleContext, "Half-0");
        byte[] info1 = BuildSha3Info(roleContext, "Half-1");
        byte[]? half0 = null;
        byte[]? half1 = null;
        try
        {
            half0 = Sha3HkdfExpand.Expand(master[..64], info0, 64);
            half1 = Sha3HkdfExpand.Expand(master[64..], info1, 64);
            byte[] result = new byte[RoleBytes];
            half0.CopyTo(result, 0);
            half1.CopyTo(result, 64);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(info0);
            CryptographicOperations.ZeroMemory(info1);
            if (half0 is not null) CryptographicOperations.ZeroMemory(half0);
            if (half1 is not null) CryptographicOperations.ZeroMemory(half1);
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
    public static byte[] DeriveRoleKey(
        ReadOnlySpan<byte> master,
        string algorithm,
        int stageIndex,
        string cipher,
        KeyRolePurpose purpose,
        int keyBytes)
    {
        if (keyBytes is <= 0 or > RoleBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(keyBytes));
        }

        byte[] context = RoleContext(algorithm, stageIndex, cipher, purpose, keyBytes * 8);
        byte[] roleValue = DeriveRoleValue(master, context);
        try
        {
            return roleValue[..keyBytes];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roleValue);
            CryptographicOperations.ZeroMemory(context);
        }
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
                byte[] stageKey = DeriveRoleKey(
                    master,
                    parameters.Algorithm,
                    stageIndex,
                    stage.Cipher.ToString(),
                    KeyRolePurpose.Encryption,
                    stage.KeyBytes);
                try
                {
                    stageKey.CopyTo(encryptionKey.Bytes, offset);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(stageKey);
                }

                offset += stage.KeyBytes;
            }

            if (offset != parameters.EncryptionKeyBytes)
            {
                throw new CryptographicException(
                    $"{parameters.Suite} stage keys filled {offset} of {parameters.EncryptionKeyBytes} bytes.");
            }

            sha3MacKey = LockedSensitiveBuffer.Create(parameters.Sha3MacKeyBytes);
            byte[] sha3Key = DeriveGlobalKey(
                master, parameters.Algorithm, "HMAC-SHA3-512",
                KeyRolePurpose.Sha3Mac, parameters.Sha3MacKeyBytes);
            try
            {
                sha3Key.CopyTo(sha3MacKey.Bytes, 0);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sha3Key);
            }

            skeinMacKey = LockedSensitiveBuffer.Create(parameters.SkeinMacKeyBytes);
            byte[] skeinKey = DeriveGlobalKey(
                master, parameters.Algorithm, "Skein-MAC-1024",
                KeyRolePurpose.SkeinMac, parameters.SkeinMacKeyBytes);
            try
            {
                skeinKey.CopyTo(skeinMacKey.Bytes, 0);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(skeinKey);
            }

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

    public static byte[] DeriveGlobalKey(
        ReadOnlySpan<byte> master,
        string algorithm,
        string cipher,
        KeyRolePurpose purpose,
        int keyBytes)
    {
        byte[] context = GlobalRoleContext(algorithm, cipher, purpose, keyBytes * 8);
        byte[] roleValue = DeriveRoleValue(master, context);
        try
        {
            return roleValue[..keyBytes];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roleValue);
            CryptographicOperations.ZeroMemory(context);
        }
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
