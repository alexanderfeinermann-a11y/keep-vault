using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// The four public salts a v10 key derivation consumes. Normal suites use the
/// round-1 pair; Paranoia uses all four.
/// </summary>
internal sealed record V10Salts(
    byte[] Sha3Round1,
    byte[] SkeinRound1,
    byte[]? Sha3Round2,
    byte[]? SkeinRound2)
{
    public const int SaltBytes = 64;

    /// <summary>
    /// Every salt that is actually present must be the right width and distinct
    /// from every other.
    /// </summary>
    /// <remarks>
    /// Two equal salts would put two Argon2id instances of the same round on
    /// the same initial hash input, which is the one thing the separate salt
    /// pools exist to prevent. It cannot happen by chance, so if it happens
    /// something is broken and no container should be written.
    /// </remarks>
    public void Validate(bool paranoia)
    {
        var present = new List<byte[]> { Sha3Round1, SkeinRound1 };
        if (paranoia)
        {
            present.Add(Sha3Round2 ?? throw new CryptographicException("Paranoia needs a round-2 SHA3 salt."));
            present.Add(SkeinRound2 ?? throw new CryptographicException("Paranoia needs a round-2 Skein salt."));
        }
        else if (Sha3Round2 is not null || SkeinRound2 is not null)
        {
            throw new CryptographicException("A single-round suite must not carry round-2 salts.");
        }

        foreach (byte[] salt in present)
        {
            if (salt.Length != SaltBytes)
            {
                throw new CryptographicException($"Every v10 salt must be {SaltBytes} bytes.");
            }
        }

        for (int i = 0; i < present.Count; i++)
        {
            for (int j = i + 1; j < present.Count; j++)
            {
                if (CryptographicOperations.FixedTimeEquals(present[i], present[j]))
                {
                    throw new CryptographicException("Two v10 salts are identical.");
                }
            }
        }
    }
}

/// <summary>
/// Derives the 1024-bit v10 master from the four secret credentials.
/// </summary>
/// <remarks>
/// The shape is:
/// <code>
///   Q_S = SHA3-512(LP(D_SA,P,N,A)) || SHA3-512(LP(D_SB,P,N,B))     128 bytes
///   Q_K = Skein-MAC-1024-1024(key = A||B, pers = D_SK, msg = LP(P,N))
///   PMI = BE16(SHA3-512(LP(D_PMI, Q_S, Q_K, [M1,] S_sha3, S_skein))[0..1])
///   m   = 1 GiB + 16 * PMI KiB
///   L   = Argon2id(P = Q_S, S = S_sha3, X = X_S, [K = M1], m, 4, 4, 64)
///   R   = Argon2id(P = Q_K, S = S_skein, X = X_K, [K = M1], m, 4, 4, 64)
///   M   = Interleave(L, R)                                          128 bytes
/// </code>
///
/// Two properties are load-bearing and easy to lose:
///
/// The branches run strictly one after the other, and each one's Argon2 matrix
/// is released before the next allocates. That keeps peak memory at one matrix
/// (1 GiB to just under 2 GiB) rather than two, and it is why no
/// <c>Task.WhenAll</c> appears anywhere in this file.
///
/// The master buffers are owned here and never handed to a native call. Each
/// call gets a fresh copy, because the native side clears what it is given.
/// v9 shared one prehash between two rounds and the second round consequently
/// ran over zero bytes.
///
/// What this does not claim: PMI adds no entropy — it is a deterministic
/// function of the credentials. Interleaving adds no entropy either; it is a
/// permutation. Two Argon2id calls do not become independent merely by using
/// different domains, and both branches share Argon2's BLAKE2b core.
/// </remarks>
internal static class V10MasterKdf
{
    public const int CredentialHashBytes = 128;
    public const int BranchOutputBytes = 64;
    public const int MasterBytes = 128;
    public const int FactorBytes = 128;

    public const uint MemoryMinKiB = 1_048_576;
    public const uint MemoryMaxKiB = 2_097_136;
    public const uint MemoryStepKiB = 16;
    public const uint Iterations = 4;
    public const uint Parallelism = 4;

    public const string KdfMode = "DualArgon2id-SHA3+Skein1024-Sequential-Master1024";
    public const string KdfInputMode = "DualBranch-v10: DualSHA3-512-1024 || KeyedSkeinMAC-1024-1024";
    public const string PasswordMode = "UserPassword24to256+PIN6to16+GeneratedHex1024x2";

    /// <summary>
    /// Q_S: the SHA3 credential path, one 512-bit digest per factor.
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

        byte[] password = Encoding.UTF8.GetBytes(userPassword);
        byte[] pinBytes = Encoding.ASCII.GetBytes(pin);
        byte[] domainA = Encoding.UTF8.GetBytes($"Kalyna-ZPAQ/v10/{algorithm}/SHA3-512/User+PIN+Factor-A");
        byte[] domainB = Encoding.UTF8.GetBytes($"Kalyna-ZPAQ/v10/{algorithm}/SHA3-512/User+PIN+Factor-B");

        int maxPassBytes = Encoding.UTF8.GetMaxByteCount(userPassword.Length);
        using var passBuf = LockedSensitiveBuffer.Create(maxPassBytes);
        int passLen = Encoding.UTF8.GetBytes(userPassword, passBuf.Bytes);
        byte[] passwordSlice = passBuf.Bytes.AsSpan(0, passLen).ToArray();

        using var pinBuf = LockedSensitiveBuffer.Create(pin.Length);
        int pinLen = Encoding.ASCII.GetBytes(pin, pinBuf.Bytes);
        byte[] pinSlice = pinBuf.Bytes.AsSpan(0, pinLen).ToArray();

        int lenA = (sizeof(int) + domainA.Length) + (sizeof(int) + passLen) + (sizeof(int) + pinLen) + (sizeof(int) + factorA.Length);
        int lenB = (sizeof(int) + domainB.Length) + (sizeof(int) + passLen) + (sizeof(int) + pinLen) + (sizeof(int) + factorB.Length);

        using var messageABuf = LockedSensitiveBuffer.Create(lenA);
        using var messageBBuf = LockedSensitiveBuffer.Create(lenB);
        try
        {
            int offsetA = 0;
            WriteLengthPrefixed(messageABuf.Bytes, ref offsetA, domainA);
            WriteLengthPrefixed(messageABuf.Bytes, ref offsetA, passwordSlice);
            WriteLengthPrefixed(messageABuf.Bytes, ref offsetA, pinSlice);
            WriteLengthPrefixed(messageABuf.Bytes, ref offsetA, factorA);

            int offsetB = 0;
            WriteLengthPrefixed(messageBBuf.Bytes, ref offsetB, domainB);
            WriteLengthPrefixed(messageBBuf.Bytes, ref offsetB, passwordSlice);
            WriteLengthPrefixed(messageBBuf.Bytes, ref offsetB, pinSlice);
            WriteLengthPrefixed(messageBBuf.Bytes, ref offsetB, factorB);

            _ = Sha3_512Compat.HashData(messageABuf.Bytes, destination.Slice(0, 64));
            _ = Sha3_512Compat.HashData(messageBBuf.Bytes, destination.Slice(64, 64));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordSlice);
            CryptographicOperations.ZeroMemory(pinSlice);
            CryptographicOperations.ZeroMemory(domainA);
            CryptographicOperations.ZeroMemory(domainB);
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
    /// Q_K: the keyed Skein credential path. Both factors form the MAC key; the
    /// password and PIN are the message.
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
        int passLen = Encoding.UTF8.GetBytes(userPassword, passBuf.Bytes);
        byte[] passwordSlice = passBuf.Bytes.AsSpan(0, passLen).ToArray();

        using var pinBuf = LockedSensitiveBuffer.Create(pin.Length);
        int pinLen = Encoding.ASCII.GetBytes(pin, pinBuf.Bytes);
        byte[] pinSlice = pinBuf.Bytes.AsSpan(0, pinLen).ToArray();

        int msgLen = (sizeof(int) + passLen) + (sizeof(int) + pinLen);
        using var messageBuf = LockedSensitiveBuffer.Create(msgLen);
        try
        {
            factorA.CopyTo(keyBuffer.Bytes.AsSpan(0, FactorBytes));
            factorB.CopyTo(keyBuffer.Bytes.AsSpan(FactorBytes, FactorBytes));

            int offset = 0;
            WriteLengthPrefixed(messageBuf.Bytes, ref offset, passwordSlice);
            WriteLengthPrefixed(messageBuf.Bytes, ref offset, pinSlice);

            KeyedSkein1024.Compute(
                keyBuffer.Bytes,
                $"Kalyna-ZPAQ/v10/{algorithm}/Skein-MAC-1024-1024/User+PIN/Factors-A+B-Key",
                messageBuf.Bytes,
                destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordSlice);
            CryptographicOperations.ZeroMemory(pinSlice);
        }
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
    /// The Personal Memory Index for one round, and the Argon2 memory cost it
    /// selects. One PMI is shared by both branches of a round.
    /// </summary>
    /// <remarks>
    /// Named an index, not a multiplier: it selects one of exactly 65,536
    /// memory profiles and changes nothing else. It is derived from secrets, so
    /// it is never stored — but it is deterministic, so it adds no entropy, and
    /// a local observer can still estimate the memory cost from runtime or RSS.
    /// </remarks>
    public static (ushort Pmi, uint MemoryKiB) DerivePmi(
        string algorithm,
        int round,
        ReadOnlySpan<byte> sha3CredentialHash,
        ReadOnlySpan<byte> skeinCredentialHash,
        ReadOnlySpan<byte> previousMaster,
        ReadOnlySpan<byte> sha3Salt,
        ReadOnlySpan<byte> skeinSalt)
    {
        string domain = $"Kalyna-ZPAQ/v10/{algorithm}/SHA3-512/PMI/Round-{round}";
        byte[] domainBytes = Encoding.UTF8.GetBytes(domain);

        int total = (sizeof(int) + domainBytes.Length)
            + (sizeof(int) + sha3CredentialHash.Length)
            + (sizeof(int) + skeinCredentialHash.Length)
            + (previousMaster.IsEmpty ? 0 : sizeof(int) + previousMaster.Length)
            + (sizeof(int) + sha3Salt.Length)
            + (sizeof(int) + skeinSalt.Length);

        byte[] message = new byte[total];
        byte[] digest = new byte[64];
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
            ushort pmi = BinaryPrimitives.ReadUInt16BigEndian(digest.AsSpan(0, 2));
            uint memory = MemoryMinKiB + (MemoryStepKiB * pmi);
            if (memory is < MemoryMinKiB or > MemoryMaxKiB)
            {
                throw new CryptographicException($"The derived Argon2id memory cost {memory} KiB is out of range.");
            }

            return (pmi, memory);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(domainBytes);
        }
    }

    public static byte[] AssociatedData(string algorithm, bool sha3Branch, int round) =>
        Encoding.UTF8.GetBytes(
            $"Kalyna-ZPAQ/v10/{algorithm}/Argon2id/{(sha3Branch ? "SHA3" : "Skein")}-Branch/Round-{round}");

    /// <summary>
    /// One complete KDF round: two sequential Argon2id branches, interleaved.
    /// </summary>
    /// <remarks>
    /// <paramref name="secret"/> is the previous round's full master for
    /// Paranoia round 2, and empty otherwise. Within a normal round the two
    /// branches stay cryptographically unlinked on purpose — chaining them
    /// would blur the two-path structure without buying anything.
    /// </remarks>
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

        using LockedSensitiveBuffer left = LockedSensitiveBuffer.Create(BranchOutputBytes);
        using LockedSensitiveBuffer right = LockedSensitiveBuffer.Create(BranchOutputBytes);

        // The SHA3 branch runs to completion, and its matrix is freed inside
        // the native call, before the Skein branch allocates its own.
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

        // Fresh one-call copies. The native call clears both of these; the
        // masters they came from stay intact for the branch that follows.
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
            NativeArgon2id.HashRawV10(
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
            throw new ArgumentException($"A v10 factor must be {FactorBytes} bytes.", name);
        }
    }
}
