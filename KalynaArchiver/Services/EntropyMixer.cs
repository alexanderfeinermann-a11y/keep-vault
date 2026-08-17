using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KalynaArchiver.Signing;
#if WINDOWS
using System.Windows.Input;
#endif

namespace KalynaArchiver.Services;

public static partial class EntropyMixer
{
    private const int BcryptUseSystemPreferredRng = 0x00000002;
    // Six pools: two factors, the salt, and three nonce parts. The third nonce
    // pool exists for the cascade, whose two layers each need their own nonce —
    // 64 bytes for Kalyna and 128 for Threefish. Deriving the second nonce from
    // the first would make one layer's keystream a function of the other's, and
    // the whole point of the cascade is that the two are independent.
    private const int PurposeCount = 6;
    public const long RequiredMouseSamplesPerPurpose = 512;
    private static readonly object Gate = new();
    private static readonly EntropyPurpose[] SamplePurposes =
    [
        EntropyPurpose.GeneratedPasswordFirst,
        EntropyPurpose.GeneratedPasswordSecond,
        EntropyPurpose.Salt,
        EntropyPurpose.NonceFirst,
        EntropyPurpose.NonceSecond,
        EntropyPurpose.NonceThird,
    ];
    private static readonly LockedSensitiveBuffer[] MousePools = CreateMousePools();
    private static readonly long[] PurposeSampleCounts = new long[PurposeCount];
    private static readonly ulong[] DerivationCounters = new ulong[PurposeCount];
    private static long _systemRandomCallCount;
    private static long _sampleSequence;
    private static int _lastSystemRandomRequestBytes;
    private static int _nextPurposeIndex;

    public static long SampleCount => GetPoolStatus().Total;
    public static long FirstGeneratedPasswordSampleCount => GetSampleCount(EntropyPurpose.GeneratedPasswordFirst);
    public static long SecondGeneratedPasswordSampleCount => GetSampleCount(EntropyPurpose.GeneratedPasswordSecond);
    public static long SaltSampleCount => GetSampleCount(EntropyPurpose.Salt);
    public static long NonceFirstSampleCount => GetSampleCount(EntropyPurpose.NonceFirst);
    public static long NonceSecondSampleCount => GetSampleCount(EntropyPurpose.NonceSecond);
    public static long NonceThirdSampleCount => GetSampleCount(EntropyPurpose.NonceThird);
    internal static long SystemRandomCallCountForTests => Interlocked.Read(ref _systemRandomCallCount);
    internal static int LastSystemRandomRequestBytesForTests => Volatile.Read(ref _lastSystemRandomRequestBytes);
    public static bool HasRequiredSamples(EntropyPurpose purpose) => GetSampleCount(purpose) >= RequiredMouseSamplesPerPurpose;
    public static long MissingSamples(EntropyPurpose purpose) => Math.Max(0, RequiredMouseSamplesPerPurpose - GetSampleCount(purpose));

    public static EntropyPoolStatus GetPoolStatus()
    {
        lock (Gate)
        {
            long total = 0;
            foreach (long count in PurposeSampleCounts)
            {
                total = checked(total + count);
            }

            return new EntropyPoolStatus(
                total,
                PurposeSampleCounts[(int)EntropyPurpose.GeneratedPasswordFirst],
                PurposeSampleCounts[(int)EntropyPurpose.GeneratedPasswordSecond],
                PurposeSampleCounts[(int)EntropyPurpose.Salt],
                PurposeSampleCounts[(int)EntropyPurpose.NonceFirst],
                PurposeSampleCounts[(int)EntropyPurpose.NonceSecond],
                PurposeSampleCounts[(int)EntropyPurpose.NonceThird]);
        }
    }

    public static long GetSampleCount(EntropyPurpose purpose)
    {
        int purposeIndex = (int)purpose;
        if (purposeIndex < 0 || purposeIndex >= PurposeCount)
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), "Unbekannter Entropiezweck.");
        }

        return Interlocked.Read(ref PurposeSampleCounts[purposeIndex]);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The next pool is transferred into MousePools only after successful hashing; every pre-transfer path disposes it, and all using declarations are compiler-generated finally blocks.")]
#if WINDOWS
    public static void AddMouseSample(
        double x,
        double y,
        int timestamp,
        MouseButtonState left,
        MouseButtonState right,
        MouseButtonState middle)
    {
        AddMouseSampleCore(x, y, timestamp, (int)left, (int)right, (int)middle);
    }
#endif

    public static void AddMouseSample(
        double x,
        double y,
        int timestamp,
        bool leftPressed,
        bool rightPressed,
        bool middlePressed)
    {
        AddMouseSampleCore(
            x,
            y,
            timestamp,
            leftPressed ? 1 : 0,
            rightPressed ? 1 : 0,
            middlePressed ? 1 : 0);
    }

    private static void AddMouseSampleCore(
        double x,
        double y,
        int timestamp,
        int left,
        int right,
        int middle)
    {
        using LockedSensitiveBuffer sample = LockedSensitiveBuffer.Create(80);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(0, 8), BitConverter.DoubleToInt64Bits(x));
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(8, 8), BitConverter.DoubleToInt64Bits(y));
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(16, 4), timestamp);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(20, 8), Environment.TickCount64);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(28, 8), DateTime.UtcNow.Ticks);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(36, 4), (int)left);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(40, 4), (int)right);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(44, 4), (int)middle);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(48, 4), Environment.CurrentManagedThreadId);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(52, 4), Environment.ProcessId);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(56, 8), Stopwatch.GetTimestamp());
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(64, 8), GC.GetTotalMemory(forceFullCollection: false));

        lock (Gate)
        {
            int selectedPurposeIndex = SelectNextPurposeIndex();
            EntropyPurpose purpose = SamplePurposes[selectedPurposeIndex];
            int purposeIndex = (int)purpose;
            long sampleSequence = _sampleSequence;
            long nextSampleSequence = checked(sampleSequence + 1);
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(72, 8), sampleSequence);
            using LockedSensitiveBuffer sampleCountBytes = LockedSensitiveBuffer.Create(sizeof(long));
            using LockedSensitiveBuffer purposeBytes = LockedSensitiveBuffer.Create(sizeof(int));
            BinaryPrimitives.WriteInt64LittleEndian(sampleCountBytes.Bytes, sampleSequence);
            BinaryPrimitives.WriteInt32LittleEndian(purposeBytes.Bytes, purposeIndex);
            using LockedSensitiveBuffer combined = LockedSensitiveBuffer.Create(
                MousePools[purposeIndex].Bytes.Length
                + sample.Bytes.Length
                + sampleCountBytes.Bytes.Length
                + purposeBytes.Bytes.Length);
            WriteCombined(
                combined.Bytes,
                MousePools[purposeIndex].Bytes,
                sample.Bytes,
                sampleCountBytes.Bytes,
                purposeBytes.Bytes);

            LockedSensitiveBuffer? nextPool = null;
            bool nextPoolTransferred = false;
            try
            {
                nextPool = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
                int written = Sha3_512Compat.HashData(combined.Bytes, nextPool.Bytes);
                if (written != Sha3_512Compat.HashSizeInBytes)
                {
                    throw new CryptographicException("SHA3-512 returned an invalid entropy-pool digest length.");
                }

                LockedSensitiveBuffer oldPool = MousePools[purposeIndex];
                MousePools[purposeIndex] = nextPool;
                nextPoolTransferred = true;
                PurposeSampleCounts[purposeIndex]++;
                _sampleSequence = nextSampleSequence;
                oldPool.Dispose();
            }
            finally
            {
                if (!nextPoolTransferred)
                {
                    nextPool?.Dispose();
                }
            }
        }
    }

    private static int SelectNextPurposeIndex()
    {
        long minimumCount = PurposeSampleCounts.Min();
        for (int offset = 0; offset < SamplePurposes.Length; offset++)
        {
            int index = (_nextPurposeIndex + offset) % SamplePurposes.Length;
            if (PurposeSampleCounts[index] != minimumCount)
            {
                continue;
            }

            _nextPurposeIndex = (index + 1) % SamplePurposes.Length;
            return index;
        }

        throw new InvalidOperationException("No mouse-entropy pool could be selected.");
    }

    /// <summary>
    /// Bytes drawn from each pool.
    /// </summary>
    /// <remarks>
    /// One digest per pool was enough while every suite's nonce fitted in three
    /// of them. The six-layer cascade needs a wider one, so the draw is sized
    /// from the catalogue: three pools have to cover the widest nonce any suite
    /// asks for. Every pool is expanded by the same amount because the
    /// expansion takes one size for all of them, and the extra bytes in the
    /// password and salt pools are simply not used.
    /// </remarks>
    private static readonly int PoolDrawBytes = Math.Max(
        Sha3_512Compat.HashSizeInBytes,
        (EncryptionSuiteCatalog.MaxNonceBytes + 2) / 3);

    internal static GeneratedArchiveEntropy CreateArchiveEntropy()
    {
        using LockedSensitiveBuffer mouseBytes = ExpandAndConsumeMousePools(
            PoolDrawBytes,
            SamplePurposes);
        using LockedSensitiveBuffer passwordBytes = LockedSensitiveBuffer.Create(2 * Sha3_512Compat.HashSizeInBytes);
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? fullNonce = null;
        try
        {
            FillSystemRandom(passwordBytes.Bytes);
            // Each password factor takes one digest from the front of its own
            // pool's draw; the rest of that draw is unused.
            XorInPlace(
                passwordBytes.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes),
                mouseBytes.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));
            XorInPlace(
                passwordBytes.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, Sha3_512Compat.HashSizeInBytes),
                mouseBytes.Bytes.AsSpan(PoolDrawBytes, Sha3_512Compat.HashSizeInBytes));

            salt = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(salt.Bytes);
            XorInPlace(
                salt.Bytes,
                mouseBytes.Bytes.AsSpan(2 * PoolDrawBytes, Sha3_512Compat.HashSizeInBytes));

            fullNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            FillSystemRandom(fullNonce.Bytes);
            XorInPlace(
                fullNonce.Bytes,
                mouseBytes.Bytes.AsSpan(3 * PoolDrawBytes, EncryptionSuiteCatalog.MaxNonceBytes));

            string firstPassword = Convert.ToHexString(
                passwordBytes.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));
            string secondPassword = Convert.ToHexString(
                passwordBytes.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, Sha3_512Compat.HashSizeInBytes));
            if (string.Equals(firstPassword, secondPassword, StringComparison.Ordinal))
            {
                throw new CryptographicException("The independently generated password factors unexpectedly match.");
            }

            var result = new GeneratedArchiveEntropy(firstPassword, secondPassword, salt, fullNonce);
            salt = null;
            fullNonce = null;
            return result;
        }
        finally
        {
            fullNonce?.Dispose();
            salt?.Dispose();
        }
    }

    /// <summary>
    /// Salt and nonce for both Argon2id rounds of a two-round suite.
    /// </summary>
    /// <remarks>
    /// Only the paranoia cascade needs this. Every other suite runs one round
    /// and keeps using <see cref="CreateEncryptionParameters"/>.
    ///
    /// Both rounds are drawn from a single pool consumption, because consuming
    /// the pools twice would mean asking the user to collect the whole mouse
    /// entropy a second time. The two rounds differ by the hash that expands
    /// the shared snapshot — SHA3-512 for the first, SHA-512 for the second —
    /// and each is XORed with its own independent draw from the system
    /// generator, so neither salt nor either nonce set can be derived from the
    /// other.
    ///
    /// Both salts and both nonce sets have to reach the container header. A v9
    /// archive whose header carries only the first round cannot be decrypted by
    /// anyone, including the machine that wrote it.
    /// </remarks>
    internal static TwoRoundEncryptionParameters CreateTwoRoundEncryptionParameters(EncryptionSuite suite)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }

        (LockedSensitiveBuffer firstMouse, LockedSensitiveBuffer secondMouse) = ExpandAndConsumeMousePoolsDual(
            Sha3_512Compat.HashSizeInBytes,
            [
                EntropyPurpose.Salt,
                EntropyPurpose.NonceFirst,
                EntropyPurpose.NonceSecond,
                EntropyPurpose.NonceThird,
            ]);

        LockedSensitiveBuffer? firstSalt = null;
        LockedSensitiveBuffer? firstNonce = null;
        LockedSensitiveBuffer? secondSalt = null;
        LockedSensitiveBuffer? secondNonce = null;
        try
        {
            (firstSalt, firstNonce) = SplitSaltAndNonce(firstMouse, suite);
            (secondSalt, secondNonce) = SplitSaltAndNonce(secondMouse, suite);

            // Two rounds that produced the same salt would mean the pools, the
            // two hashes and two independent system draws had all coincided.
            // That cannot happen by chance, so if it happens something is
            // broken badly enough that no archive should be written.
            if (CryptographicOperations.FixedTimeEquals(firstSalt.Bytes, secondSalt.Bytes))
            {
                throw new CryptographicException("Both Argon2id rounds produced the same salt.");
            }

            var result = new TwoRoundEncryptionParameters(firstSalt, firstNonce, secondSalt, secondNonce);
            firstSalt = null;
            firstNonce = null;
            secondSalt = null;
            secondNonce = null;
            return result;
        }
        finally
        {
            secondNonce?.Dispose();
            secondSalt?.Dispose();
            firstNonce?.Dispose();
            firstSalt?.Dispose();
            secondMouse.Dispose();
            firstMouse.Dispose();
        }
    }

    /// <summary>
    /// Turns one expanded pool block into a salt and a nonce, each XORed with
    /// its own draw from the system generator.
    /// </summary>
    private static (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) SplitSaltAndNonce(
        LockedSensitiveBuffer mouseBytes,
        EncryptionSuite suite)
    {
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? fullNonce = null;
        LockedSensitiveBuffer? selectedNonce = null;
        try
        {
            salt = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(salt.Bytes);
            XorInPlace(salt.Bytes, mouseBytes.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));

            fullNonce = LockedSensitiveBuffer.Create(3 * Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(fullNonce.Bytes);
            XorInPlace(
                fullNonce.Bytes,
                mouseBytes.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, 3 * Sha3_512Compat.HashSizeInBytes));

            int nonceBytes = EncryptionSuiteCatalog.Get(suite).NonceBytes;
            if (nonceBytes == fullNonce.Bytes.Length)
            {
                selectedNonce = fullNonce;
                fullNonce = null;
            }
            else
            {
                selectedNonce = LockedSensitiveBuffer.Create(nonceBytes);
                fullNonce.Bytes.AsSpan(0, nonceBytes).CopyTo(selectedNonce.Bytes);
            }

            (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) result = (salt, selectedNonce);
            salt = null;
            selectedNonce = null;
            return result;
        }
        finally
        {
            selectedNonce?.Dispose();
            fullNonce?.Dispose();
            salt?.Dispose();
        }
    }

    internal static (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) CreateEncryptionParameters(EncryptionSuite suite)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }

        using LockedSensitiveBuffer mouseBytes = ExpandAndConsumeMousePools(
            Sha3_512Compat.HashSizeInBytes,
            [
                EntropyPurpose.Salt,
                EntropyPurpose.NonceFirst,
                EntropyPurpose.NonceSecond,
                EntropyPurpose.NonceThird,
            ]);
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? fullNonce = null;
        LockedSensitiveBuffer? selectedNonce = null;
        try
        {
            salt = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(salt.Bytes);
            XorInPlace(
                salt.Bytes,
                mouseBytes.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));

            fullNonce = LockedSensitiveBuffer.Create(3 * Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(fullNonce.Bytes);
            XorInPlace(
                fullNonce.Bytes,
                mouseBytes.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, 3 * Sha3_512Compat.HashSizeInBytes));

            int nonceBytes = EncryptionSuiteCatalog.Get(suite).NonceBytes;
            if (nonceBytes == fullNonce.Bytes.Length)
            {
                selectedNonce = fullNonce;
                fullNonce = null;
            }
            else
            {
                selectedNonce = LockedSensitiveBuffer.Create(nonceBytes);
                fullNonce.Bytes.AsSpan(0, nonceBytes).CopyTo(selectedNonce.Bytes);
            }

            (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) result = (salt, selectedNonce);
            salt = null;
            selectedNonce = null;
            return result;
        }
        finally
        {
            selectedNonce?.Dispose();
            fullNonce?.Dispose();
            salt?.Dispose();
        }
    }

    private static void XorInPlace(Span<byte> destination, ReadOnlySpan<byte> source)
    {
        if (destination.Length != source.Length)
        {
            throw new ArgumentException("Entropy inputs must have identical lengths.", nameof(source));
        }

        for (int index = 0; index < destination.Length; index++)
        {
            destination[index] ^= source[index];
        }
    }

    private static LockedSensitiveBuffer ExpandAndConsumeMousePools(
        int byteCountPerPool,
        EntropyPurpose[] purposes)
        => ExpandAndConsumeMousePoolsCore(byteCountPerPool, purposes, secondRound: false).First;

    /// <summary>
    /// Expands the pools twice in one pass: once through SHA3-512 and once
    /// through SHA-512.
    /// </summary>
    /// <remarks>
    /// Container v9's paranoia suite runs Argon2id twice, and the second round
    /// needs its own salt and its own nonces. It cannot simply call the
    /// single-round expansion again: that call *consumes* the pools — it swaps
    /// in fresh buffers and resets every sample count to zero — so a second
    /// call would demand another <see cref="RequiredMouseSamplesPerPurpose"/>
    /// mouse samples per pool from a user who has already collected them once.
    ///
    /// Both rounds therefore come from the same snapshot, separated by the hash
    /// that expands it. SHA3-512 and SHA-512 are different constructions —
    /// Keccak against Merkle-Damgard — so neither output tells anything about
    /// the other, and no second pool has to be filled.
    /// </remarks>
    private static (LockedSensitiveBuffer First, LockedSensitiveBuffer Second) ExpandAndConsumeMousePoolsDual(
        int byteCountPerPool,
        EntropyPurpose[] purposes)
    {
        (LockedSensitiveBuffer first, LockedSensitiveBuffer? second) =
            ExpandAndConsumeMousePoolsCore(byteCountPerPool, purposes, secondRound: true);
        return (first, second!);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned outputs transfer ownership to the caller; all failure paths dispose them, replacement-pool transfer is guarded, and loop buffers use compiler-generated finally blocks.")]
    private static (LockedSensitiveBuffer First, LockedSensitiveBuffer? Second) ExpandAndConsumeMousePoolsCore(
        int byteCountPerPool,
        EntropyPurpose[] purposes,
        bool secondRound)
    {
        if (byteCountPerPool <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCountPerPool), "Die Byteanzahl muss positiv sein.");
        }

        ArgumentNullException.ThrowIfNull(purposes);
        if (purposes.Length == 0)
        {
            throw new ArgumentException("Mindestens ein Entropiepool ist erforderlich.", nameof(purposes));
        }

        var uniquePurposes = new HashSet<EntropyPurpose>();
        foreach (EntropyPurpose purpose in purposes)
        {
            int purposeIndex = (int)purpose;
            if (purposeIndex < 0 || purposeIndex >= PurposeCount)
            {
                throw new ArgumentOutOfRangeException(nameof(purposes), purpose, "Unbekannter Entropiezweck.");
            }

            if (!uniquePurposes.Add(purpose))
            {
                throw new ArgumentException("Jeder Entropiepool darf pro Ableitung nur einmal verwendet werden.", nameof(purposes));
            }
        }

        int totalByteCount = checked(byteCountPerPool * purposes.Length);
        LockedSensitiveBuffer output = LockedSensitiveBuffer.Create(totalByteCount);
        LockedSensitiveBuffer? secondOutput = secondRound ? LockedSensitiveBuffer.Create(totalByteCount) : null;
        var snapshots = new LockedSensitiveBuffer?[purposes.Length];
        var replacements = new LockedSensitiveBuffer?[PurposeCount];
        var oldPools = new LockedSensitiveBuffer?[PurposeCount];
        var baseCounters = new ulong[purposes.Length];
        var nextCounters = new ulong[PurposeCount];
        try
        {
            for (int index = 0; index < purposes.Length; index++)
            {
                snapshots[index] = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            }

            for (int index = 0; index < PurposeCount; index++)
            {
                replacements[index] = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            }

            lock (Gate)
            {
                foreach (EntropyPurpose purpose in purposes)
                {
                    long current = PurposeSampleCounts[(int)purpose];
                    if (current < RequiredMouseSamplesPerPurpose)
                    {
                        throw new InvalidOperationException($"Nicht genug Maus-Entropie-Samples fuer {purpose}: {current}/{RequiredMouseSamplesPerPurpose}.");
                    }
                }

                for (int index = 0; index < purposes.Length; index++)
                {
                    int purposeIndex = (int)purposes[index];
                    MousePools[purposeIndex].Bytes.CopyTo(snapshots[index]!.Bytes, 0);
                    baseCounters[index] = DerivationCounters[purposeIndex];
                }

                for (int purposeIndex = 0; purposeIndex < PurposeCount; purposeIndex++)
                {
                    nextCounters[purposeIndex] = checked(DerivationCounters[purposeIndex] + 1);
                }

                for (int purposeIndex = 0; purposeIndex < PurposeCount; purposeIndex++)
                {
                    oldPools[purposeIndex] = MousePools[purposeIndex];
                    MousePools[purposeIndex] = replacements[purposeIndex]!;
                    replacements[purposeIndex] = null;
                    DerivationCounters[purposeIndex] = nextCounters[purposeIndex];
                    PurposeSampleCounts[purposeIndex] = 0;
                }
            }

            for (int index = 0; index < oldPools.Length; index++)
            {
                oldPools[index]!.Dispose();
                oldPools[index] = null;
            }

            for (int poolIndex = 0; poolIndex < purposes.Length; poolIndex++)
            {
                int poolOffset = checked(poolIndex * byteCountPerPool);
                int localOffset = 0;
                int purposeIndex = (int)purposes[poolIndex];
                for (uint blockIndex = 0; localOffset < byteCountPerPool; blockIndex++)
                {
                    using LockedSensitiveBuffer baseCounterBytes = LockedSensitiveBuffer.Create(sizeof(ulong));
                    using LockedSensitiveBuffer blockIndexBytes = LockedSensitiveBuffer.Create(sizeof(uint));
                    using LockedSensitiveBuffer purposeBytes = LockedSensitiveBuffer.Create(sizeof(int));
                    BinaryPrimitives.WriteUInt64LittleEndian(baseCounterBytes.Bytes, baseCounters[poolIndex]);
                    BinaryPrimitives.WriteUInt32LittleEndian(blockIndexBytes.Bytes, blockIndex);
                    BinaryPrimitives.WriteInt32LittleEndian(purposeBytes.Bytes, purposeIndex);
                    using LockedSensitiveBuffer combined = LockedSensitiveBuffer.Create(
                        snapshots[poolIndex]!.Bytes.Length
                        + baseCounterBytes.Bytes.Length
                        + blockIndexBytes.Bytes.Length
                        + purposeBytes.Bytes.Length);
                    WriteCombined(
                        combined.Bytes,
                        snapshots[poolIndex]!.Bytes,
                        baseCounterBytes.Bytes,
                        blockIndexBytes.Bytes,
                        purposeBytes.Bytes);
                    using LockedSensitiveBuffer block = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
                    int written = Sha3_512Compat.HashData(combined.Bytes, block.Bytes);
                    if (written != Sha3_512Compat.HashSizeInBytes)
                    {
                        throw new CryptographicException("SHA3-512 returned an invalid mouse-entropy expansion length.");
                    }

                    int count = Math.Min(block.Bytes.Length, byteCountPerPool - localOffset);
                    Buffer.BlockCopy(block.Bytes, 0, output.Bytes, poolOffset + localOffset, count);
                    localOffset += count;

                    if (secondOutput is null)
                    {
                        continue;
                    }

                    // The same block input, expanded through the other hash.
                    // SHA3-512 is a sponge and SHA-512 is Merkle-Damgard, so
                    // knowing one output says nothing about the other, and the
                    // second round gets independent material without a second
                    // pool having to be collected.
                    using LockedSensitiveBuffer secondBlock = LockedSensitiveBuffer.Create(Sha512Compat.HashSizeInBytes);
                    int secondWritten = Sha512Compat.HashData(combined.Bytes, secondBlock.Bytes);
                    if (secondWritten != Sha512Compat.HashSizeInBytes)
                    {
                        throw new CryptographicException("SHA-512 returned an invalid mouse-entropy expansion length.");
                    }

                    Buffer.BlockCopy(
                        secondBlock.Bytes,
                        0,
                        secondOutput.Bytes,
                        poolOffset + localOffset - count,
                        count);
                }
            }

            return (output, secondOutput);
        }
        catch
        {
            secondOutput?.Dispose();
            output.Dispose();
            throw;
        }
        finally
        {
            foreach (LockedSensitiveBuffer? snapshot in snapshots)
            {
                snapshot?.Dispose();
            }

            foreach (LockedSensitiveBuffer? replacement in replacements)
            {
                replacement?.Dispose();
            }

            foreach (LockedSensitiveBuffer? oldPool in oldPools)
            {
                oldPool?.Dispose();
            }

            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(baseCounters.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(nextCounters.AsSpan()));
        }
    }

    private static void FillSystemRandom(byte[] buffer)
    {
        int status = OperatingSystem.IsWindows()
            ? BCryptGenRandom(0, buffer, buffer.Length, BcryptUseSystemPreferredRng)
            : OperatingSystem.IsMacOS()
                ? SecRandomCopyBytes(0, checked((nuint)buffer.Length), buffer)
                : throw new PlatformNotSupportedException("A reviewed operating-system CSPRNG adapter is required.");
        if (status != 0)
        {
            throw new CryptographicException($"The operating-system CSPRNG failed: 0x{status:X8}");
        }

        Volatile.Write(ref _lastSystemRandomRequestBytes, buffer.Length);
        Interlocked.Increment(ref _systemRandomCallCount);
    }

    private static void WriteCombined(byte[] destination, params byte[][] arrays)
    {
        int expectedLength = arrays.Sum(array => array.Length);
        if (destination.Length != expectedLength)
        {
            throw new ArgumentException("Combined entropy buffer has an invalid length.", nameof(destination));
        }

        int offset = 0;
        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, destination, offset, array.Length);
            offset += array.Length;
        }
    }

    private static LockedSensitiveBuffer[] CreateMousePools()
    {
        var pools = new List<LockedSensitiveBuffer>(PurposeCount);
        try
        {
            for (int index = 0; index < PurposeCount; index++)
            {
                pools.Add(LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes));
            }

            return [.. pools];
        }
        catch
        {
            foreach (LockedSensitiveBuffer pool in pools)
            {
                pool.Dispose();
            }

            throw;
        }
    }

    [LibraryImport("bcrypt.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int BCryptGenRandom(nint hAlgorithm, [Out] byte[] pbBuffer, int cbBuffer, int dwFlags);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security")]
    private static partial int SecRandomCopyBytes(nint random, nuint count, [Out] byte[] bytes);
}

public readonly record struct EntropyPoolStatus(
    long Total,
    long GeneratedPasswordFirst,
    long GeneratedPasswordSecond,
    long Salt,
    long NonceFirst,
    long NonceSecond,
    long NonceThird)
{
    public long Minimum => Math.Min(
        Math.Min(GeneratedPasswordFirst, GeneratedPasswordSecond),
        Math.Min(Salt, Math.Min(NonceFirst, Math.Min(NonceSecond, NonceThird))));

    public long Maximum => Math.Max(
        Math.Max(GeneratedPasswordFirst, GeneratedPasswordSecond),
        Math.Max(Salt, Math.Max(NonceFirst, Math.Max(NonceSecond, NonceThird))));

    public bool IsBalanced => Maximum - Minimum <= 1;
}

/// <summary>
/// Salt and nonce for each of the two Argon2id rounds of a two-round suite.
/// </summary>
/// <remarks>
/// Written out as four separate values rather than two concatenated blobs. An
/// off-by-one that handed round two round one's salt would still encrypt and
/// still decrypt on the same build, and would only surface as an unreadable
/// archive somewhere else — which, with no backward compatibility, is
/// unrecoverable.
/// </remarks>
internal sealed class TwoRoundEncryptionParameters : IDisposable
{
    internal TwoRoundEncryptionParameters(
        LockedSensitiveBuffer firstSalt,
        LockedSensitiveBuffer firstNonce,
        LockedSensitiveBuffer secondSalt,
        LockedSensitiveBuffer secondNonce)
    {
        FirstSalt = firstSalt;
        FirstNonce = firstNonce;
        SecondSalt = secondSalt;
        SecondNonce = secondNonce;
    }

    internal LockedSensitiveBuffer FirstSalt { get; }

    internal LockedSensitiveBuffer FirstNonce { get; }

    internal LockedSensitiveBuffer SecondSalt { get; }

    internal LockedSensitiveBuffer SecondNonce { get; }

    public void Dispose()
    {
        SecondNonce.Dispose();
        SecondSalt.Dispose();
        FirstNonce.Dispose();
        FirstSalt.Dispose();
    }
}

public enum EntropyPurpose
{
    GeneratedPasswordFirst = 0,
    GeneratedPasswordSecond = 1,
    Salt = 2,
    NonceFirst = 3,
    NonceSecond = 4,
    NonceThird = 5,
}

internal sealed class GeneratedArchiveEntropy : IDisposable
{
    private readonly object _gate = new();
    private LockedSensitiveBuffer? _salt;
    private LockedSensitiveBuffer? _fullNonce;
    private string? _firstPassword;
    private string? _secondPassword;

    internal GeneratedArchiveEntropy(
        string firstPassword,
        string secondPassword,
        LockedSensitiveBuffer salt,
        LockedSensitiveBuffer fullNonce)
    {
        _firstPassword = firstPassword ?? throw new ArgumentNullException(nameof(firstPassword));
        _secondPassword = secondPassword ?? throw new ArgumentNullException(nameof(secondPassword));
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        _fullNonce = fullNonce ?? throw new ArgumentNullException(nameof(fullNonce));
        // Three nonce parts: 64 bytes for the cascade's inner Kalyna layer and
        // 128 for its outer Threefish layer. The single-cipher suites take the
        // leading 64 or 128 bytes of the same material.
        if (_salt.Bytes.Length != Sha3_512Compat.HashSizeInBytes
            || _fullNonce.Bytes.Length != EncryptionSuiteCatalog.MaxNonceBytes)
        {
            throw new ArgumentException("Prepared archive entropy has an invalid length.");
        }
    }

    public string FirstPassword
    {
        get
        {
            lock (_gate)
            {
                return _firstPassword ?? throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            }
        }
    }

    public string SecondPassword
    {
        get
        {
            lock (_gate)
            {
                return _secondPassword ?? throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            }
        }
    }

    public bool HasPendingEncryptionParameters
    {
        get
        {
            lock (_gate)
            {
                return _salt is not null && _fullNonce is not null;
            }
        }
    }

    internal (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) ConsumeEncryptionParameters(
        EncryptionSuite suite,
        string firstPassword,
        string secondPassword)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }

        ArgumentNullException.ThrowIfNull(firstPassword);
        ArgumentNullException.ThrowIfNull(secondPassword);

        LockedSensitiveBuffer salt;
        LockedSensitiveBuffer fullNonce;
        lock (_gate)
        {
            if (!string.Equals(_firstPassword, firstPassword, StringComparison.Ordinal)
                || !string.Equals(_secondPassword, secondPassword, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Prepared salt and nonce parameters do not belong to the supplied generated password factors.");
            }

            salt = _salt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            fullNonce = _fullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            _salt = null;
            _fullNonce = null;
        }

        int nonceBytes = EncryptionSuiteCatalog.Get(suite).NonceBytes;
        if (nonceBytes == fullNonce.Bytes.Length)
        {
            return (salt, fullNonce);
        }

        LockedSensitiveBuffer? selectedNonce = null;
        try
        {
            selectedNonce = LockedSensitiveBuffer.Create(nonceBytes);
            fullNonce.Bytes.AsSpan(0, nonceBytes).CopyTo(selectedNonce.Bytes);
            fullNonce.Dispose();
            return (salt, selectedNonce);
        }
        catch
        {
            selectedNonce?.Dispose();
            fullNonce.Dispose();
            salt.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        LockedSensitiveBuffer? salt;
        LockedSensitiveBuffer? fullNonce;
        lock (_gate)
        {
            salt = _salt;
            fullNonce = _fullNonce;
            _salt = null;
            _fullNonce = null;
            _firstPassword = null;
            _secondPassword = null;
        }

        fullNonce?.Dispose();
        salt?.Dispose();
    }
}
