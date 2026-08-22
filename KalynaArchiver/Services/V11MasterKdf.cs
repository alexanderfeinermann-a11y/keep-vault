using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// Derives the 1024-bit v11 master from the four secret credentials with the
/// 512/512 factor split in the SHA3 credential path.
/// </summary>
/// <remarks>
/// The v11 shape is:
/// <code>
///   A1  = factorA[0..64), A2 = factorA[64..128)
///   B1  = factorB[0..64), B2 = factorB[64..128)
///   Q_S1 = SHA3-512(LP(D_S1, P, N, A1, B1))                          64 bytes
///   Q_S2 = SHA3-512(LP(D_S2, P, N, A2, B2))                          64 bytes
///   Q_S  = Q_S1 || Q_S2                                             128 bytes
///   Q_K  = Skein-MAC-1024-1024(key = A||B, pers = D_SK, msg = LP(P,N)) 128 bytes
///   PMI  = BE16(SHA3-512(LP(D_PMI, Q_S, Q_K, [M1,] S_sha3, S_skein))[0..1])
///   m    = 1 GiB + 16 * PMI KiB
///   L    = Argon2id(P = Q_S, S = S_sha3, X = X_S, [K = M1], m, 4, 4, 64)
///   R    = Argon2id(P = Q_K, S = S_skein, X = X_K, [K = M1], m, 4, 4, 64)
///   M    = Interleave(L, R)                                          128 bytes
/// </code>
///
/// Defense-in-depth guarantee of v11 SHA3 split:
/// If only one 1024-bit factor is compromised, every 512-bit SHA3 half still
/// depends on 512 uncompromised bits of the remaining factor.
/// </remarks>
internal static class V11MasterKdf
{
    public const int CredentialHashBytes = 128;
    public const int BranchOutputBytes = 64;
    public const int MasterBytes = 128;
    public const int FactorBytes = 128;
    public const int FactorHalfBytes = FactorBytes / 2; // 64 bytes = 512 bits

    public const uint MemoryMinKiB = 1_048_576;
    public const uint MemoryMaxKiB = 2_097_136;
    public const uint MemoryStepKiB = 16;
    public const uint Iterations = 4;
    public const uint Parallelism = 4;

    public const string KdfMode = "DualArgon2id-SplitSHA3+Skein1024-Sequential-Master1024";
    public const string KdfInputMode = "DualBranch-v11: SplitFactorsSHA3-512-1024 || KeyedSkeinMAC-1024-1024";
    public const string PasswordMode = "UserPassword24to256+PIN6to16+GeneratedHex1024x2";

    /// <summary>
    /// Q_S(v11): the SHA3 credential path with 512/512 factor split.
    /// </summary>
    public static void DeriveSha3CredentialHash(
        string algorithm,
        string userPassword,
        string pin,
        ReadOnlySpan<byte> factorA,
        ReadOnlySpan<byte> factorB,
        Span<byte> destination)
    {
        RequireFactor(factorA, nameof(factorA));
        RequireFactor(factorB, nameof(factorB));
        if (destination.Length < CredentialHashBytes)
        {
            throw new ArgumentException($"Destination must be at least {CredentialHashBytes} bytes.", nameof(destination));
        }

        ReadOnlySpan<byte> a1 = factorA[..FactorHalfBytes];
        ReadOnlySpan<byte> a2 = factorA[FactorHalfBytes..];
        ReadOnlySpan<byte> b1 = factorB[..FactorHalfBytes];
        ReadOnlySpan<byte> b2 = factorB[FactorHalfBytes..];

        byte[] domain1 = Encoding.UTF8.GetBytes($"Kalyna-ZPAQ/v11/{algorithm}/SHA3-512/User+PIN+Factors-A1+B1");
        byte[] domain2 = Encoding.UTF8.GetBytes($"Kalyna-ZPAQ/v11/{algorithm}/SHA3-512/User+PIN+Factors-A2+B2");

        int maxPassBytes = Encoding.UTF8.GetMaxByteCount(userPassword.Length);
        using var passBuf = LockedSensitiveBuffer.Create(maxPassBytes);
        int passLen = Encoding.UTF8.GetBytes(userPassword.AsSpan(), passBuf.Bytes);
        ReadOnlySpan<byte> passwordSpan = passBuf.Bytes.AsSpan(0, passLen);

        using var pinBuf = LockedSensitiveBuffer.Create(pin.Length);
        int pinLen = Encoding.ASCII.GetBytes(pin.AsSpan(), pinBuf.Bytes);
        ReadOnlySpan<byte> pinSpan = pinBuf.Bytes.AsSpan(0, pinLen);

        int len1 = (sizeof(int) + domain1.Length) + (sizeof(int) + passLen) + (sizeof(int) + pinLen) + (sizeof(int) + a1.Length) + (sizeof(int) + b1.Length);
        int len2 = (sizeof(int) + domain2.Length) + (sizeof(int) + passLen) + (sizeof(int) + pinLen) + (sizeof(int) + a2.Length) + (sizeof(int) + b2.Length);

        using var message1Buf = LockedSensitiveBuffer.Create(len1);
        using var message2Buf = LockedSensitiveBuffer.Create(len2);
        try
        {
            int offset1 = 0;
            WriteLengthPrefixed(message1Buf.Bytes, ref offset1, domain1);
            WriteLengthPrefixed(message1Buf.Bytes, ref offset1, passwordSpan);
            WriteLengthPrefixed(message1Buf.Bytes, ref offset1, pinSpan);
            WriteLengthPrefixed(message1Buf.Bytes, ref offset1, a1);
            WriteLengthPrefixed(message1Buf.Bytes, ref offset1, b1);

            int offset2 = 0;
            WriteLengthPrefixed(message2Buf.Bytes, ref offset2, domain2);
            WriteLengthPrefixed(message2Buf.Bytes, ref offset2, passwordSpan);
            WriteLengthPrefixed(message2Buf.Bytes, ref offset2, pinSpan);
            WriteLengthPrefixed(message2Buf.Bytes, ref offset2, a2);
            WriteLengthPrefixed(message2Buf.Bytes, ref offset2, b2);

            _ = Sha3_512Compat.HashData(message1Buf.Bytes, destination.Slice(0, 64));
            _ = Sha3_512Compat.HashData(message2Buf.Bytes, destination.Slice(64, 64));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(domain1);
            CryptographicOperations.ZeroMemory(domain2);
        }
    }

    public static byte[] DeriveSha3CredentialHash(
        string algorithm,
        string userPassword,
        string pin,
        ReadOnlySpan<byte> factorA,
        ReadOnlySpan<byte> factorB)
    {
        byte[] result = new byte[CredentialHashBytes];
        DeriveSha3CredentialHash(algorithm, userPassword, pin, factorA, factorB, result);
        return result;
    }

    /// <summary>
    /// Q_K(v11): the keyed Skein credential path with full factors A and B as key.
    /// </summary>
    public static void DeriveSkeinCredentialHash(
        string algorithm,
        string userPassword,
        string pin,
        ReadOnlySpan<byte> factorA,
        ReadOnlySpan<byte> factorB,
        Span<byte> destination)
    {
        RequireFactor(factorA, nameof(factorA));
        RequireFactor(factorB, nameof(factorB));
        if (destination.Length < CredentialHashBytes)
        {
            throw new ArgumentException($"Destination must be at least {CredentialHashBytes} bytes.", nameof(destination));
        }

        using var keyBuffer = LockedSensitiveBuffer.Create(FactorBytes * 2);

        int maxPassBytes = Encoding.UTF8.GetMaxByteCount(userPassword.Length);
        using var passBuf = LockedSensitiveBuffer.Create(maxPassBytes);
        int passLen = Encoding.UTF8.GetBytes(userPassword.AsSpan(), passBuf.Bytes);
        ReadOnlySpan<byte> passwordSpan = passBuf.Bytes.AsSpan(0, passLen);

        using var pinBuf = LockedSensitiveBuffer.Create(pin.Length);
        int pinLen = Encoding.ASCII.GetBytes(pin.AsSpan(), pinBuf.Bytes);
        ReadOnlySpan<byte> pinSpan = pinBuf.Bytes.AsSpan(0, pinLen);

        int msgLen = (sizeof(int) + passLen) + (sizeof(int) + pinLen);
        using var messageBuf = LockedSensitiveBuffer.Create(msgLen);

        factorA.CopyTo(keyBuffer.Bytes.AsSpan(0, FactorBytes));
        factorB.CopyTo(keyBuffer.Bytes.AsSpan(FactorBytes, FactorBytes));

        int offset = 0;
        WriteLengthPrefixed(messageBuf.Bytes, ref offset, passwordSpan);
        WriteLengthPrefixed(messageBuf.Bytes, ref offset, pinSpan);

        KeyedSkein1024.Compute(
            keyBuffer.Bytes,
            $"Kalyna-ZPAQ/v11/{algorithm}/Skein-MAC-1024-1024/User+PIN/Factors-A+B-Key",
            messageBuf.Bytes,
            destination);
    }

    public static byte[] DeriveSkeinCredentialHash(
        string algorithm,
        string userPassword,
        string pin,
        ReadOnlySpan<byte> factorA,
        ReadOnlySpan<byte> factorB)
    {
        byte[] result = new byte[CredentialHashBytes];
        DeriveSkeinCredentialHash(algorithm, userPassword, pin, factorA, factorB, result);
        return result;
    }

    /// <summary>
    /// Personal Memory Index for v11 round.
    /// </summary>
    public static (ushort Pmi, uint MemoryKiB) DerivePmi(
        string algorithm,
        int round,
        ReadOnlySpan<byte> sha3CredentialHash,
        ReadOnlySpan<byte> skeinCredentialHash,
        ReadOnlySpan<byte> previousMaster,
        ReadOnlySpan<byte> sha3Salt,
        ReadOnlySpan<byte> skeinSalt)
    {
        string domain = $"Kalyna-ZPAQ/v11/{algorithm}/SHA3-512/PMI/Round-{round}";
        byte[] domainBytes = Encoding.UTF8.GetBytes(domain);

        int total = (sizeof(int) + domainBytes.Length)
            + (sizeof(int) + sha3CredentialHash.Length)
            + (sizeof(int) + skeinCredentialHash.Length)
            + (previousMaster.IsEmpty ? 0 : sizeof(int) + previousMaster.Length)
            + (sizeof(int) + sha3Salt.Length)
            + (sizeof(int) + skeinSalt.Length);

        using LockedSensitiveBuffer messageBuf = LockedSensitiveBuffer.Create(total);
        using LockedSensitiveBuffer digestBuf = LockedSensitiveBuffer.Create(64);
        Span<byte> message = messageBuf.Bytes;
        Span<byte> digest = digestBuf.Bytes;
        try
        {
            int offset = 0;
            WriteLengthPrefixed(message, ref offset, domainBytes);
            WriteLengthPrefixed(message, ref offset, sha3CredentialHash);
            WriteLengthPrefixed(message, ref offset, skeinCredentialHash);
            if (!previousMaster.IsEmpty)
            {
                WriteLengthPrefixed(message, ref offset, previousMaster);
            }
            WriteLengthPrefixed(message, ref offset, sha3Salt);
            WriteLengthPrefixed(message, ref offset, skeinSalt);

            _ = Sha3_512Compat.HashData(message, digest);
            ushort pmi = BinaryPrimitives.ReadUInt16BigEndian(digest.Slice(0, 2));
            uint memory = MemoryMinKiB + (MemoryStepKiB * pmi);
            if (memory is < MemoryMinKiB or > MemoryMaxKiB)
            {
                throw new CryptographicException($"The derived Argon2id memory cost {memory} KiB is out of range.");
            }

            return (pmi, memory);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(domainBytes);
        }
    }

    public static byte[] AssociatedData(string algorithm, bool sha3Branch, int round) =>
        Encoding.UTF8.GetBytes(
            $"Kalyna-ZPAQ/v11/{algorithm}/Argon2id/{(sha3Branch ? "SHA3" : "Skein")}-Branch/Round-{round}");

    /// <summary>
    /// One complete v11 KDF round: two sequential Argon2id branches, interleaved.
    /// </summary>
    public static void DeriveRoundMaster(
        string algorithm,
        int round,
        ReadOnlySpan<byte> sha3CredentialHash,
        ReadOnlySpan<byte> skeinCredentialHash,
        ReadOnlySpan<byte> sha3Salt,
        ReadOnlySpan<byte> skeinSalt,
        ReadOnlySpan<byte> secret,
        uint memoryKiB,
        Span<byte> destination)
    {
        if (destination.Length < MasterBytes)
        {
            throw new ArgumentException($"Destination must be at least {MasterBytes} bytes.", nameof(destination));
        }

        if (memoryKiB is < MemoryMinKiB or > MemoryMaxKiB
            || (memoryKiB - MemoryMinKiB) % MemoryStepKiB != 0)
        {
            throw new CryptographicException(
                $"The Argon2id memory cost {memoryKiB} KiB is not a value the v11 PMI can produce.");
        }

        using LockedSensitiveBuffer left = LockedSensitiveBuffer.Create(BranchOutputBytes);
        using LockedSensitiveBuffer right = LockedSensitiveBuffer.Create(BranchOutputBytes);

        RunBranch(
            algorithm, round, sha3Branch: true,
            sha3CredentialHash, sha3Salt, secret, memoryKiB, left.Bytes);
        RunBranch(
            algorithm, round, sha3Branch: false,
            skeinCredentialHash, skeinSalt, secret, memoryKiB, right.Bytes);

        MasterInterleave.Interleave(left.Bytes, right.Bytes, destination);
    }

    public static byte[] DeriveRoundMaster(
        string algorithm,
        int round,
        ReadOnlySpan<byte> sha3CredentialHash,
        ReadOnlySpan<byte> skeinCredentialHash,
        ReadOnlySpan<byte> sha3Salt,
        ReadOnlySpan<byte> skeinSalt,
        byte[]? secret,
        uint memoryKiB)
    {
        byte[] master = new byte[MasterBytes];
        DeriveRoundMaster(
            algorithm, round, sha3CredentialHash, skeinCredentialHash,
            sha3Salt, skeinSalt, secret ?? ReadOnlySpan<byte>.Empty, memoryKiB, master);
        return master;
    }

    private static void RunBranch(
        string algorithm,
        int round,
        bool sha3Branch,
        ReadOnlySpan<byte> credentialHash,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret,
        uint memoryKiB,
        byte[] output)
    {
        if (output == null || output.Length != BranchOutputBytes)
        {
            throw new ArgumentException($"Output buffer must be exactly {BranchOutputBytes} bytes.", nameof(output));
        }

        // Both inputs are copied into fixed-width locked buffers, so a short
        // one would be silently zero-padded into a weaker Argon2id input
        // instead of failing. Argon2 would then run happily on the padding.
        if (credentialHash.Length != CredentialHashBytes)
        {
            throw new ArgumentException(
                $"A credential hash must be exactly {CredentialHashBytes} bytes.", nameof(credentialHash));
        }

        if (!secret.IsEmpty && secret.Length != MasterBytes)
        {
            throw new ArgumentException(
                $"The Argon2id secret must be the complete {MasterBytes}-byte master.", nameof(secret));
        }

        if (salt.Length != KdfSalts.SaltBytes)
        {
            throw new ArgumentException(
                $"An Argon2id branch salt must be exactly {KdfSalts.SaltBytes} bytes.", nameof(salt));
        }

        using LockedSensitiveBuffer passwordCopy = LockedSensitiveBuffer.Create(CredentialHashBytes);
        credentialHash.CopyTo(passwordCopy.Bytes);
        using LockedSensitiveBuffer? secretCopy = secret.IsEmpty
            ? null
            : LockedSensitiveBuffer.Create(MasterBytes);
        if (!secret.IsEmpty)
        {
            secret.CopyTo(secretCopy!.Bytes);
        }

        byte[] saltCopy = salt.ToArray();
        byte[] associatedData = AssociatedData(algorithm, sha3Branch, round);
        try
        {
            NativeArgon2id.HashRaw(
                Iterations,
                memoryKiB,
                Parallelism,
                passwordCopy.Bytes,
                saltCopy,
                secretCopy?.Bytes,
                associatedData,
                output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(saltCopy);
            CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    private static void WriteLengthPrefixed(Span<byte> destination, ref int offset, ReadOnlySpan<byte> data)
    {
        BinaryPrimitives.WriteInt32LittleEndian(destination.Slice(offset), data.Length);
        offset += sizeof(int);
        data.CopyTo(destination.Slice(offset));
        offset += data.Length;
    }

    private static void RequireFactor(ReadOnlySpan<byte> factor, string name)
    {
        if (factor.Length != FactorBytes)
        {
            throw new ArgumentException($"A factor must be {FactorBytes} bytes.", name);
        }
    }
}
