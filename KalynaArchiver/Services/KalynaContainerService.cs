using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

public sealed partial class KalynaContainerService
{
    private static readonly byte[] Magic = "KZPAQ1\0"u8.ToArray();
    private static readonly byte[] ThreefishTweakDomain = "Kalyna-ZPAQ/v9/Threefish-1024/CTR-Tweak"u8.ToArray();
    // Version 8 introduces the cascade suite and drops every earlier version.
    // There is deliberately no reader for v7: a format this app writes once and
    // reads years later is safer with one shape than with a compatibility path
    // that is exercised rarely and audited less.
    private const int CurrentVersion = 10;

    /// <summary>
    /// The width of the v10 master key. Every role key is cut from a value of
    /// this width, so it is what the header records instead of a per-suite
    /// Argon2id output length.
    /// </summary>
    private const int MasterKeyBits = 1024;
    private const int BufferSize = 16 * 1024 * 1024;
    private const int Sha3TagSize = 64;
    private const int SkeinTagSize = 128;
    private const int MaxHeaderSize = 16 * 1024;
    private readonly PasswordKeyService _passwords = new();

    public bool IsNativeKalynaAvailable => NativeKalyna.IsAvailable();
    public bool IsNativeThreefishAvailable => NativeThreefish.IsAvailable();
    public static string? NativeKalynaLoadError => NativeKalyna.LastLoadError;
    public static string? NativeThreefishLoadError => NativeThreefish.LastLoadError;

    public bool IsNativeSuiteAvailable(EncryptionSuite suite) => MissingNativeLibraries(suite).Count == 0;

    public Task EncryptZpaqStreamAsync(
        Stream plainZpaqStream,
        string encryptedPath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        string? hint,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return EncryptZpaqStreamAsync(
            plainZpaqStream,
            encryptedPath,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            EncryptionSuite.Kalyna512_512,
            hint,
            progress,
            cancellationToken);
    }

    internal Task EncryptZpaqStreamWithPreparedEntropyAsync(
        Stream plainZpaqStream,
        string encryptedPath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        EncryptionSuite suite,
        GeneratedArchiveEntropy preparedEntropy,
        string? hint,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(preparedEntropy);
        return EncryptZpaqStreamWithProfileAsync(
            plainZpaqStream,
            encryptedPath,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            suite,
            Argon2Profile.Default,
            hint,
            progress,
            cancellationToken,
            preparedEntropy);
    }

    public Task EncryptZpaqStreamAsync(
        Stream plainZpaqStream,
        string encryptedPath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        EncryptionSuite suite,
        string? hint,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return EncryptZpaqStreamWithProfileAsync(
            plainZpaqStream,
            encryptedPath,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            suite,
            Argon2Profile.Default,
            hint,
            progress,
            cancellationToken);
    }

    internal Task EncryptZpaqStreamWithProfileAsync(
        Stream plainZpaqStream,
        string encryptedPath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        Argon2Profile argon2Profile,
        string? hint,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return EncryptZpaqStreamWithProfileAsync(
            plainZpaqStream,
            encryptedPath,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            EncryptionSuite.Kalyna512_512,
            argon2Profile,
            hint,
            progress,
            cancellationToken);
    }

    internal async Task EncryptZpaqStreamWithProfileAsync(
        Stream plainZpaqStream,
        string encryptedPath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        EncryptionSuite suite,
        Argon2Profile argon2Profile,
        string? hint,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        GeneratedArchiveEntropy? preparedEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(plainZpaqStream);
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
        EnsureNativeAvailable(suite);
        PasswordKeyService.ValidateUserPasswordForCreation(userPassword, firstGeneratedPassword, secondGeneratedPassword);
        // Checked before any work starts. The derivation would refuse it too,
        // but only after the archive has been compressed and streamed.
        V10KeyDerivation.ValidatePinForCreation(pin);
        PasswordKeyService.ValidateArgon2Profile(argon2Profile);
        ValidateHintForCreation(hint);

        string fullEncryptedPath = Path.GetFullPath(encryptedPath);
        if (File.Exists(fullEncryptedPath) || Directory.Exists(fullEncryptedPath))
        {
            throw new IOException("The encrypted archive target already exists.");
        }

        string targetDirectory = Path.GetDirectoryName(fullEncryptedPath) ?? Environment.CurrentDirectory;
        if (!Directory.Exists(targetDirectory))
        {
            throw new DirectoryNotFoundException($"The encrypted archive target directory does not exist: {targetDirectory}");
        }

        // A two-round suite needs two salts and two nonces, and both halves have
        // to reach the header: an archive whose header carries only the first
        // round cannot be decrypted by anyone, including the machine that wrote
        // it.
        LockedSensitiveBuffer saltBuffer;
        LockedSensitiveBuffer nonceBuffer;
        TwoRoundEncryptionParameters? twoRound = null;
        if (parameters.UsesTwoKdfRounds)
        {
            twoRound = preparedEntropy is null
                ? EntropyMixer.CreateTwoRoundEncryptionParameters(suite)
                : preparedEntropy.ConsumeTwoRoundEncryptionParameters(
                    suite,
                    firstGeneratedPassword,
                    secondGeneratedPassword);
            saltBuffer = twoRound.FirstSalt;
            nonceBuffer = twoRound.FirstNonce;
        }
        else if (preparedEntropy is null)
        {
            (saltBuffer, nonceBuffer) = EntropyMixer.CreateEncryptionParameters(suite);
        }
        else
        {
            (saltBuffer, nonceBuffer) = preparedEntropy.ConsumeEncryptionParameters(
                suite,
                firstGeneratedPassword,
                secondGeneratedPassword);
        }

        byte[] salt = saltBuffer.Bytes;
        byte[] nonce = nonceBuffer.Bytes;
        byte[] secondSalt = twoRound?.SecondSalt.Bytes ?? [];
        byte[] secondNonce = twoRound?.SecondNonce.Bytes ?? [];
        byte[] chunkNonceBase = [];
        byte[] kdfSalt = [];
        byte[] kdfSecondSalt = [];
        SuiteKeyMaterial? keyMaterial = null;
        byte[] tweak = [];
        byte[] counter = [];
        Argon2Profile effectiveProfile;
        try
        {
            kdfSalt = (byte[])salt.Clone();
            kdfSecondSalt = secondSalt.Length == 0 ? [] : (byte[])secondSalt.Clone();
            try
            {
                keyMaterial = await DeriveV10KeyMaterialAsync(
                    parameters,
                    userPassword,
                    pin,
                    firstGeneratedPassword,
                    secondGeneratedPassword,
                    kdfSalt,
                    kdfSecondSalt,
                    progress,
                    cancellationToken).ConfigureAwait(false);
                effectiveProfile = argon2Profile;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kdfSalt);
                CryptographicOperations.ZeroMemory(kdfSecondSalt);
            }

            chunkNonceBase = BuildChunkNonceBase(nonce, secondNonce);

            tweak = CreateSuiteTweak(suite, nonce);
            counter = (byte[])nonce.Clone();
            using IDisposable nonceLock = SecureMemory.TryLock(nonce);
            using IDisposable tweakLock = SecureMemory.TryLock(tweak);
            using IDisposable counterLock = SecureMemory.TryLock(counter);

            var header = new ContainerHeader(
                CurrentVersion,
                parameters.Algorithm,
                parameters.BlockBytes * 8,
                EncryptionSuiteCatalog.CounterEndian,
                parameters.EncryptionKeyBytes * 8,
                parameters.Sha3MacKeyBytes * 8,
                Sha3TagSize * 8,
                parameters.SkeinMacKeyBytes * 8,
                SkeinTagSize * 8,
                EntropyMixer.SaltPairBytes * 8,
                Convert.ToBase64String(salt),
                parameters.NonceBytes * 8,
                Convert.ToBase64String(nonce),
                parameters.TweakBytes * 8,
                parameters.TweakBytes > 0 ? EncryptionSuiteCatalog.ThreefishTweakMode : "None",
                tweak.Length == 0 ? null : Convert.ToBase64String(tweak),
                hint,
                // Zero on purpose. v10 derives the Argon2id memory cost from
                // the credentials, so writing it here would publish the one
                // parameter the derivation keeps secret. Iterations and
                // parallelism are fixed constants and reveal nothing.
                0,
                effectiveProfile.Iterations,
                effectiveProfile.Parallelism,
                512,
                MasterKeyBits,
                "Sequential",
                "PMI16",
                V10MasterKdf.PasswordMode,
                V10MasterKdf.KdfInputMode,
                1024,
                2,
                V10MasterKdf.KdfMode,
                secondSalt.Length == 0 ? 0 : EntropyMixer.SaltPairBytes * 8,
                secondSalt.Length == 0 ? null : Convert.ToBase64String(secondSalt),
                secondNonce.Length == 0 ? 0 : parameters.NonceBytes * 8,
                secondNonce.Length == 0 ? null : Convert.ToBase64String(secondNonce));
            byte[] headerBytes = JsonSerializer.SerializeToUtf8Bytes(header, ContainerJsonContext.Default.ContainerHeader);
            if (headerBytes.Length > MaxHeaderSize)
            {
                throw new InvalidDataException("Container header exceeds the supported size.");
            }

            byte[] headerLengthBytes = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(headerLengthBytes, headerBytes.Length);
            byte[] sha3TagPlaceholder = new byte[Sha3TagSize];
            byte[] skeinTagPlaceholder = new byte[SkeinTagSize];

            string temporaryEncryptedPath = Path.Combine(
                targetDirectory,
                $".{Path.GetFileName(fullEncryptedPath)}.{Guid.NewGuid():N}.encrypted-part");

            try
            {
                try
                {
                    await using FileStream output = new(
                        temporaryEncryptedPath,
                        FileMode.CreateNew,
                        FileAccess.ReadWrite,
                        FileShare.None,
                        bufferSize: 1024 * 1024,
                        FileOptions.SequentialScan);
                    using var hmac = new HmacSha3_512(keyMaterial.Sha3MacKey);
                    using NativeSkein1024Mac skeinMac = NativeThreefish.CreateSkeinMac(keyMaterial.SkeinMacKey);
                    await output.WriteAsync(Magic, cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(headerLengthBytes, cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(sha3TagPlaceholder, cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(skeinTagPlaceholder, cancellationToken).ConfigureAwait(false);
                    AppendAuthentication(hmac, skeinMac, Magic);
                    AppendAuthentication(hmac, skeinMac, headerLengthBytes);
                    AppendAuthentication(hmac, skeinMac, headerBytes);

                    byte[] plainChunk = new byte[BufferSize];
                    byte[] cipherChunk = new byte[BufferSize];
                    using IDisposable plainChunkLock = SecureMemory.TryLock(plainChunk);
                    using IDisposable cipherChunkLock = SecureMemory.TryLock(cipherChunk);
                    try
                    {
                        int read;
                        long plaintextBytes = 0;
                        long chunkIndex = 0;
                        while ((read = await ReadChunkAsync(plainZpaqStream, plainChunk, cancellationToken).ConfigureAwait(false)) > 0)
                        {
                            plaintextBytes = checked(plaintextBytes + read);
                            DeriveChunkNonce(chunkNonceBase, chunkIndex, counter);
                            XCrypt(parameters, keyMaterial.EncryptionKey, tweak, counter, plainChunk, cipherChunk, read);

                            byte[]? chunkTag = null;
                            if (parameters.Cascade is { OutermostIsAead: true } aeadLayout)
                            {
                                // The tag follows its own chunk rather than
                                // collecting in a table, so a reader never has
                                // to hold unverified plaintext while it goes
                                // looking for the proof.
                                byte[] tag = new byte[NativeChaChaPoly.TagBytes];
                                (byte[] aeadKey, byte[] aeadNonce) =
                                    SplitAeadMaterial(aeadLayout, keyMaterial.EncryptionKey, counter);
                                byte[] associated =
                                    BuildChunkAssociatedData(parameters, chunkNonceBase, chunkIndex, read);
                                try
                                {
                                    NativeChaChaPoly.Encrypt(
                                        aeadKey, aeadNonce, associated, cipherChunk, cipherChunk, read, tag);
                                }
                                finally
                                {
                                    CryptographicOperations.ZeroMemory(aeadKey);
                                    CryptographicOperations.ZeroMemory(aeadNonce);
                                }

                                chunkTag = tag;
                            }

                            await output.WriteAsync(cipherChunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                            AppendAuthentication(hmac, skeinMac, cipherChunk.AsSpan(0, read));

                            if (chunkTag is not null)
                            {
                                await output.WriteAsync(chunkTag, cancellationToken).ConfigureAwait(false);
                                AppendAuthentication(hmac, skeinMac, chunkTag);
                            }
                            chunkIndex = checked(chunkIndex + 1);
                            CryptographicOperations.ZeroMemory(plainChunk.AsSpan(0, read));
                            CryptographicOperations.ZeroMemory(cipherChunk.AsSpan(0, read));
                        }

                        if (plaintextBytes == 0)
                        {
                            throw new InvalidDataException("An encrypted ZPAQ container cannot have an empty payload.");
                        }

                        byte[] sha3Tag = hmac.GetHashAndReset();
                        byte[] skeinTag = skeinMac.GetTag();
                        try
                        {
                            output.Position = Magic.Length + headerLengthBytes.Length + headerBytes.Length;
                            await output.WriteAsync(sha3Tag, cancellationToken).ConfigureAwait(false);
                            await output.WriteAsync(skeinTag, cancellationToken).ConfigureAwait(false);
                            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) makes the completed ciphertext durable before the atomic rename.
                            output.Flush(flushToDisk: true);
#pragma warning restore CA1849
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(sha3Tag);
                            CryptographicOperations.ZeroMemory(skeinTag);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plainChunk);
                        CryptographicOperations.ZeroMemory(cipherChunk);
                    }
                }
                catch
                {
                    File.Delete(temporaryEncryptedPath);
                    throw;
                }

                File.Move(temporaryEncryptedPath, fullEncryptedPath, overwrite: false);
                progress?.Report($"{parameters.DisplayName} container written.");
            }
            catch
            {
                if (File.Exists(temporaryEncryptedPath))
                {
                    File.Delete(temporaryEncryptedPath);
                }

                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(headerLengthBytes);
                CryptographicOperations.ZeroMemory(headerBytes);
                CryptographicOperations.ZeroMemory(sha3TagPlaceholder);
                CryptographicOperations.ZeroMemory(skeinTagPlaceholder);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kdfSalt);
            CryptographicOperations.ZeroMemory(kdfSecondSalt);
            CryptographicOperations.ZeroMemory(chunkNonceBase);
            keyMaterial?.Dispose();
            CryptographicOperations.ZeroMemory(counter);
            CryptographicOperations.ZeroMemory(tweak);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(salt);
            // A two-round set owns all four buffers, so disposing it covers the
            // salt and nonce aliases taken from it.
            if (twoRound is not null)
            {
                twoRound.Dispose();
            }
            else
            {
                nonceBuffer.Dispose();
                saltBuffer.Dispose();
            }
        }
    }

    public async Task DecryptToStreamAsync(
        string encryptedPath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        Stream plainZpaqDestination,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plainZpaqDestination);
#if KEEPVAULT_MACOS
        using MacPrivateFileSnapshot inputSnapshot = await MacPrivateFileSnapshot
            .CaptureAsync(encryptedPath, cancellationToken)
            .ConfigureAwait(false);
        FileStream input = inputSnapshot.Stream;
#else
        await using var input = File.OpenRead(encryptedPath);
#endif
        byte[] magic = new byte[Magic.Length];
        byte[] headerLengthBytes = new byte[sizeof(int)];
        byte[]? headerBytes = null;
        byte[]? expectedSha3Tag = null;
        byte[]? expectedSkeinTag = null;
        byte[]? salt = null;
        byte[]? nonce = null;
        byte[]? secondSalt = null;
        byte[]? secondNonce = null;
        byte[]? chunkNonceBase = null;
        byte[]? tweak = null;
        byte[]? actualSha3Tag = null;
        byte[]? actualSkeinTag = null;
        SuiteKeyMaterial? keyMaterial = null;
        byte[]? counter = null;

        try
        {
            await input.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(magic, Magic))
            {
                throw new InvalidDataException("The file is not an encrypted ZPAQ container.");
            }

            await input.ReadExactlyAsync(headerLengthBytes, cancellationToken).ConfigureAwait(false);
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(headerLengthBytes);
            if (headerLength is <= 0 or > MaxHeaderSize)
            {
                throw new InvalidDataException("Invalid container header length.");
            }

            headerBytes = new byte[headerLength];
            await input.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            ContainerHeader header = DeserializeAndValidateHeader(headerBytes);
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.FromAlgorithm(header.Algorithm);
            EnsureNativeAvailable(parameters.Suite);

            expectedSha3Tag = new byte[Sha3TagSize];
            expectedSkeinTag = new byte[SkeinTagSize];
            await input.ReadExactlyAsync(expectedSha3Tag, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(expectedSkeinTag, cancellationToken).ConfigureAwait(false);
            long cipherStart = input.Position;
            if (input.Length <= cipherStart)
            {
                throw new InvalidDataException("Encrypted container has no ciphertext payload.");
            }

            salt = Convert.FromBase64String(header.Salt);
            nonce = Convert.FromBase64String(header.Nonce);
            secondSalt = string.IsNullOrEmpty(header.SecondSalt) ? [] : Convert.FromBase64String(header.SecondSalt);
            secondNonce = string.IsNullOrEmpty(header.SecondNonce) ? [] : Convert.FromBase64String(header.SecondNonce);
            chunkNonceBase = BuildChunkNonceBase(nonce, secondNonce);
            tweak = string.IsNullOrEmpty(header.Tweak) ? [] : Convert.FromBase64String(header.Tweak);
            keyMaterial = await DeriveV10KeyMaterialAsync(
                parameters,
                userPassword,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                salt,
                secondSalt,
                progress,
                cancellationToken).ConfigureAwait(false);

            (actualSha3Tag, actualSkeinTag) = await ComputeCiphertextAuthenticationAsync(
                input,
                cipherStart,
                keyMaterial.Sha3MacKey,
                keyMaterial.SkeinMacKey,
                headerLengthBytes,
                headerBytes,
                cancellationToken).ConfigureAwait(false);

            bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3Tag, actualSha3Tag);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkeinTag, actualSkeinTag);
            if (!(sha3Matches & skeinMatches))
            {
                throw new CryptographicException("Wrong password or manipulated container.");
            }

            counter = (byte[])nonce.Clone();
            using IDisposable nonceLock = SecureMemory.TryLock(nonce);
            using IDisposable tweakLock = SecureMemory.TryLock(tweak);
            using IDisposable counterLock = SecureMemory.TryLock(counter);
            input.Position = cipherStart;
            // Sized to one written chunk: payload, plus the tag that follows
            // it when the suite has an authenticated outer layer. A single read
            // then lands exactly on a chunk boundary.
            //
            // The allowance must not be added unconditionally. For a suite
            // without a tag the writer emits BufferSize per chunk, and a reader
            // taking BufferSize + 16 would drift by a tag every chunk — the
            // chunk indices on the two sides would diverge, and the per-chunk
            // nonces with them.
            int chunkTagAllowance = parameters.Cascade is { OutermostIsAead: true }
                ? NativeChaChaPoly.TagBytes
                : 0;
            byte[] cipherChunk = new byte[BufferSize + chunkTagAllowance];
            byte[] plainChunk = new byte[BufferSize];
            using IDisposable cipherChunkLock = SecureMemory.TryLock(cipherChunk);
            using IDisposable plainChunkLock = SecureMemory.TryLock(plainChunk);
            try
            {
                int read;
                long chunkIndex = 0;
                while ((read = await ReadChunkAsync(input, cipherChunk, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    DeriveChunkNonce(chunkNonceBase, chunkIndex, counter);

                    if (parameters.Cascade is { OutermostIsAead: true } aeadLayout)
                    {
                        // The chunk and its tag were written together, so the
                        // tag sits in the last bytes of what was just read.
                        // Verification happens before the inner layers run: a
                        // reader must never hand out plaintext it has not
                        // authenticated, not even to the next cipher.
                        int tagBytes = NativeChaChaPoly.TagBytes;
                        if (read < tagBytes)
                        {
                            throw new InvalidDataException("The container ends inside an authentication tag.");
                        }

                        int payload = read - tagBytes;
                        byte[] tag = cipherChunk.AsSpan(payload, tagBytes).ToArray();
                        (byte[] aeadKey, byte[] aeadNonce) =
                            SplitAeadMaterial(aeadLayout, keyMaterial.EncryptionKey, counter);
                        byte[] associated =
                            BuildChunkAssociatedData(parameters, chunkNonceBase, chunkIndex, payload);
                        try
                        {
                            NativeChaChaPoly.Decrypt(
                                aeadKey, aeadNonce, associated, cipherChunk, cipherChunk, payload, tag);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(aeadKey);
                            CryptographicOperations.ZeroMemory(aeadNonce);
                            CryptographicOperations.ZeroMemory(tag);
                        }

                        read = payload;
                    }

                    XCrypt(parameters, keyMaterial.EncryptionKey, tweak, counter, cipherChunk, plainChunk, read);
                    await plainZpaqDestination.WriteAsync(plainChunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    chunkIndex = checked(chunkIndex + 1);
                    CryptographicOperations.ZeroMemory(cipherChunk.AsSpan(0, read));
                    CryptographicOperations.ZeroMemory(plainChunk.AsSpan(0, read));
                }

                await plainZpaqDestination.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cipherChunk);
                CryptographicOperations.ZeroMemory(plainChunk);
            }

            progress?.Report($"{parameters.DisplayName} container decrypted.");
        }
        finally
        {
            keyMaterial?.Dispose();
            ZeroIfNotNull(actualSha3Tag);
            ZeroIfNotNull(actualSkeinTag);
            ZeroIfNotNull(expectedSha3Tag);
            ZeroIfNotNull(expectedSkeinTag);
            ZeroIfNotNull(counter);
            ZeroIfNotNull(tweak);
            ZeroIfNotNull(nonce);
            ZeroIfNotNull(secondSalt);
            ZeroIfNotNull(secondNonce);
            ZeroIfNotNull(chunkNonceBase);
            ZeroIfNotNull(salt);
            ZeroIfNotNull(magic);
            ZeroIfNotNull(headerLengthBytes);
            ZeroIfNotNull(headerBytes);
        }
    }

    public async Task<bool> LooksEncryptedAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path) || new FileInfo(path).Length < Magic.Length)
        {
            return false;
        }

        byte[] magic = new byte[Magic.Length];
#if KEEPVAULT_MACOS
        await using FileStream input = MacSafeFileSystem.OpenReadNoSymlinks(path);
#else
        await using FileStream input = File.OpenRead(path);
#endif
        try
        {
            await input.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
            return CryptographicOperations.FixedTimeEquals(magic, Magic);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(magic);
        }
    }

    internal async Task VerifyAuthenticationAsync(
        Stream input,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead || !input.CanSeek)
        {
            throw new ArgumentException("The encrypted container stream must be readable and seekable.", nameof(input));
        }

        input.Position = 0;
        byte[] magic = new byte[Magic.Length];
        byte[] headerLengthBytes = new byte[sizeof(int)];
        byte[]? headerBytes = null;
        byte[]? expectedSha3Tag = null;
        byte[]? expectedSkeinTag = null;
        byte[]? actualSha3Tag = null;
        byte[]? actualSkeinTag = null;
        byte[]? salt = null;
        SuiteKeyMaterial? keyMaterial = null;
        try
        {
            await input.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(magic, Magic))
            {
                throw new InvalidDataException("The file is not an encrypted ZPAQ container.");
            }

            await input.ReadExactlyAsync(headerLengthBytes, cancellationToken).ConfigureAwait(false);
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(headerLengthBytes);
            if (headerLength is <= 0 or > MaxHeaderSize)
            {
                throw new InvalidDataException("Invalid container header length.");
            }

            headerBytes = new byte[headerLength];
            await input.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            ContainerHeader header = DeserializeAndValidateHeader(headerBytes);
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.FromAlgorithm(header.Algorithm);
            EnsureNativeAvailable(parameters.Suite);

            expectedSha3Tag = new byte[Sha3TagSize];
            expectedSkeinTag = new byte[SkeinTagSize];
            await input.ReadExactlyAsync(expectedSha3Tag, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(expectedSkeinTag, cancellationToken).ConfigureAwait(false);
            long cipherStart = input.Position;
            if (input.Length <= cipherStart)
            {
                throw new InvalidDataException("Encrypted container has no ciphertext payload.");
            }

            salt = Convert.FromBase64String(header.Salt);
            byte[] verifySecondSalt = string.IsNullOrEmpty(header.SecondSalt)
                ? []
                : Convert.FromBase64String(header.SecondSalt);
            try
            {
                keyMaterial = await DeriveV10KeyMaterialAsync(
                    parameters,
                    userPassword,
                    pin,
                    firstGeneratedPassword,
                    secondGeneratedPassword,
                    salt,
                    verifySecondSalt,
                    progress: null,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(verifySecondSalt);
            }

            (actualSha3Tag, actualSkeinTag) = await ComputeCiphertextAuthenticationAsync(
                input,
                cipherStart,
                keyMaterial.Sha3MacKey,
                keyMaterial.SkeinMacKey,
                headerLengthBytes,
                headerBytes,
                cancellationToken).ConfigureAwait(false);
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3Tag, actualSha3Tag);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkeinTag, actualSkeinTag);
            if (!(sha3Matches & skeinMatches))
            {
                throw new CryptographicException("Wrong password or manipulated container.");
            }
        }
        finally
        {
            keyMaterial?.Dispose();
            ZeroIfNotNull(actualSha3Tag);
            ZeroIfNotNull(actualSkeinTag);
            ZeroIfNotNull(expectedSha3Tag);
            ZeroIfNotNull(expectedSkeinTag);
            ZeroIfNotNull(salt);
            ZeroIfNotNull(magic);
            ZeroIfNotNull(headerLengthBytes);
            ZeroIfNotNull(headerBytes);
        }
    }

    public async Task<KalynaContainerInfo> ReadContainerInfoAsync(string encryptedPath, CancellationToken cancellationToken)
    {
#if KEEPVAULT_MACOS
        await using FileStream input = MacSafeFileSystem.OpenReadNoSymlinks(encryptedPath);
#else
        await using var input = File.OpenRead(encryptedPath);
#endif
        return await ReadContainerInfoAsync(input, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<KalynaContainerInfo> ReadContainerInfoAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead || !input.CanSeek)
        {
            throw new ArgumentException("The encrypted container stream must be readable and seekable.", nameof(input));
        }

        input.Position = 0;
        byte[] magic = new byte[Magic.Length];
        byte[] headerLengthBytes = new byte[sizeof(int)];
        byte[]? headerBytes = null;
        try
        {
            await input.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(magic, Magic))
            {
                throw new InvalidDataException("The file is not an encrypted ZPAQ container.");
            }

            await input.ReadExactlyAsync(headerLengthBytes, cancellationToken).ConfigureAwait(false);
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(headerLengthBytes);
            if (headerLength is <= 0 or > MaxHeaderSize)
            {
                throw new InvalidDataException("Invalid container header length.");
            }

            headerBytes = new byte[headerLength];
            await input.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            ContainerHeader header = DeserializeAndValidateHeader(headerBytes);
            if (input.Length - input.Position <= Sha3TagSize + SkeinTagSize)
            {
                throw new InvalidDataException("Encrypted container is truncated before its ciphertext payload.");
            }

            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.FromAlgorithm(header.Algorithm);
            return new KalynaContainerInfo(
                header.Version,
                header.Algorithm,
                parameters.Suite,
                header.PasswordMode,
                header.KdfInputMode,
                header.Hint,
                header.GeneratedPasswordBits,
                header.GeneratedPasswordFactorCount,
                header.SaltBits,
                header.NonceBits,
                true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(magic);
            CryptographicOperations.ZeroMemory(headerLengthBytes);
            ZeroIfNotNull(headerBytes);
        }
    }

    internal async Task<ContainerRecoveryKdfInfo> ReadRecoveryKdfInfoAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead || !input.CanSeek)
        {
            throw new ArgumentException("The encrypted container stream must be readable and seekable.", nameof(input));
        }

        input.Position = 0;
        byte[] magic = new byte[Magic.Length];
        byte[] headerLengthBytes = new byte[sizeof(int)];
        byte[]? headerBytes = null;
        byte[]? salt = null;
        try
        {
            await input.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(magic, Magic))
            {
                throw new InvalidDataException("The file is not an encrypted ZPAQ container.");
            }

            await input.ReadExactlyAsync(headerLengthBytes, cancellationToken).ConfigureAwait(false);
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(headerLengthBytes);
            if (headerLength is <= 0 or > MaxHeaderSize)
            {
                throw new InvalidDataException("Invalid container header length.");
            }

            headerBytes = new byte[headerLength];
            await input.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            ContainerHeader header = DeserializeAndValidateHeader(headerBytes);
            if (input.Length - input.Position <= Sha3TagSize + SkeinTagSize)
            {
                throw new InvalidDataException("Encrypted container is truncated before its ciphertext payload.");
            }

            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.FromAlgorithm(header.Algorithm);
            // Every salt pair the container's own derivation uses, in order.
            // KPAR2 has to reproduce the same key schedule, and for the
            // two-round suite that means both rounds — running one round there
            // would give recovery a cheaper credential oracle than the
            // container itself offers.
            byte[] firstPair = Convert.FromBase64String(header.Salt);
            byte[] secondPair = string.IsNullOrEmpty(header.SecondSalt)
                ? []
                : Convert.FromBase64String(header.SecondSalt);
            salt = new byte[firstPair.Length + secondPair.Length];
            try
            {
                firstPair.CopyTo(salt, 0);
                secondPair.CopyTo(salt, firstPair.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(firstPair);
                CryptographicOperations.ZeroMemory(secondPair);
            }

            var result = new ContainerRecoveryKdfInfo(
                parameters.Suite,
                header.Algorithm,
                salt,
                Argon2Profile.Default);
            salt = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(magic);
            CryptographicOperations.ZeroMemory(headerLengthBytes);
            ZeroIfNotNull(headerBytes);
            ZeroIfNotNull(salt);
        }
    }

    private static ContainerHeader DeserializeAndValidateHeader(byte[] headerBytes)
    {
        try
        {
            ContainerHeader header = JsonSerializer.Deserialize(headerBytes, ContainerJsonContext.Default.ContainerHeader)
                ?? throw new InvalidDataException("Container header could not be read.");
            byte[] canonicalHeader = JsonSerializer.SerializeToUtf8Bytes(header, ContainerJsonContext.Default.ContainerHeader);
            try
            {
                if (!headerBytes.AsSpan().SequenceEqual(canonicalHeader))
                {
                    throw new InvalidDataException("Container header is not in the unique canonical v9 JSON representation.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonicalHeader);
            }

            if (header.Version != CurrentVersion)
            {
                throw new InvalidDataException(
                    header.Version < CurrentVersion
                        ? $"This archive uses container version {header.Version}. Keep Vault {CurrentVersion} "
                          + "derives its keys from four credentials including a PIN and cannot open it. "
                          + "Open it with the version that wrote it and create a new archive."
                        : $"Only encrypted container version {CurrentVersion} is supported.");
            }

            ValidateHeader(header);
            return header;
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Container header is not valid canonical v9 JSON.", ex);
        }
    }

    private static async Task<(byte[] Sha3Tag, byte[] SkeinTag)> ComputeCiphertextAuthenticationAsync(
        Stream input,
        long cipherStart,
        byte[] sha3MacKey,
        byte[] skeinMacKey,
        byte[] headerLengthBytes,
        byte[] headerBytes,
        CancellationToken cancellationToken)
    {
        using var hmac = new HmacSha3_512(sha3MacKey);
        using NativeSkein1024Mac skeinMac = NativeThreefish.CreateSkeinMac(skeinMacKey);
        AppendAuthentication(hmac, skeinMac, Magic);
        AppendAuthentication(hmac, skeinMac, headerLengthBytes);
        AppendAuthentication(hmac, skeinMac, headerBytes);

        input.Position = cipherStart;
        byte[] buffer = new byte[BufferSize];
        byte[]? sha3Tag = null;
        try
        {
            int read;
            while ((read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                AppendAuthentication(hmac, skeinMac, buffer.AsSpan(0, read));
            }

            sha3Tag = hmac.GetHashAndReset();
            byte[] skeinTag = skeinMac.GetTag();
            return (sha3Tag, skeinTag);
        }
        catch
        {
            ZeroIfNotNull(sha3Tag);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static void AppendAuthentication(
        HmacSha3_512 hmac,
        NativeSkein1024Mac skeinMac,
        ReadOnlySpan<byte> data)
    {
        hmac.AppendData(data);
        skeinMac.AppendData(data);
    }

    private static async ValueTask<int> ReadChunkAsync(Stream source, byte[] buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await source.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static long BlocksForLength(int length, int blockBytes)
    {
        return (length + (long)blockBytes - 1) / blockBytes;
    }

    private static void IncrementCounter(byte[] counter, long blocks)
    {
        IncrementCounter(counter.AsSpan(), blocks);
    }

    private static void IncrementCounter(Span<byte> counter, long blocks)
    {
        if (blocks < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(blocks), "Block count cannot be negative.");
        }

        ulong carry = (ulong)blocks;
        for (int index = counter.Length - 1; index >= 0 && carry != 0; index--)
        {
            ulong sum = counter[index] + (carry & 0xffUL);
            counter[index] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }

        if (carry != 0)
        {
            throw new CryptographicException("CTR counter is exhausted.");
        }
    }

    /// <summary>
    /// Applies the suite's keystream to <paramref name="length"/> bytes.
    /// </summary>
    /// <remarks>
    /// Every suite here is a counter-mode keystream, so this one routine both
    /// encrypts and decrypts. The cascade runs the inner layer into the output
    /// buffer and then the outer layer over that buffer in place; the reference
    /// cores read each byte before writing the same index and never declare
    /// their buffers restricted, so the aliasing is defined.
    /// </remarks>
    private static readonly byte[] ChunkNonceDomain = "Kalyna-ZPAQ/v9/chunk-nonce"u8.ToArray();

    /// <summary>
    /// Gives every chunk its own nonce instead of running one counter across
    /// the whole archive.
    /// </summary>
    /// <remarks>
    /// A single CTR stream over an archive of unbounded size is the case where
    /// counter blocks eventually repeat, and a repeated counter block under the
    /// same key hands an observer the XOR of two plaintexts. Re-deriving the
    /// nonce for every chunk keeps each chunk's counter space to one chunk, so
    /// archive size stops being what decides whether that is reachable.
    ///
    /// The per-chunk value is derived, not drawn. Fresh randomness per chunk
    /// could not be reproduced when reading unless it were stored per chunk,
    /// which is exactly the overhead an arbitrarily large archive cannot carry.
    /// The chunk index is bound into the hash, so the nonces are independent of
    /// each other while both sides compute the same sequence.
    ///
    /// SHA3-512 does this for every suite, including the two-round paranoia
    /// cascade. The two hashes separate the *key derivation* rounds, where two
    /// independent expansions of one entropy snapshot are the whole point;
    /// chunk nonces need no such separation, because the base nonce they hang
    /// off is already per-archive and per-suite. Using one hash here keeps the
    /// sequence identical for every suite and removes a branch that could put
    /// a reader and a writer on different derivations.
    /// </remarks>
    /// <summary>
    /// The material every chunk nonce hangs off.
    /// </summary>
    /// <remarks>
    /// One-round suites use their single nonce. A two-round suite uses both,
    /// laid end to end, so each chunk nonce depends on the entropy of both
    /// rounds and neither of the two stored nonces is dead weight in the header.
    /// </remarks>
    private static byte[] BuildChunkNonceBase(byte[] nonce, byte[] secondNonce)
    {
        if (secondNonce.Length == 0)
        {
            return (byte[])nonce.Clone();
        }

        byte[] combined = new byte[checked(nonce.Length + secondNonce.Length)];
        nonce.CopyTo(combined, 0);
        secondNonce.CopyTo(combined, nonce.Length);
        return combined;
    }

    private static void DeriveChunkNonce(
        byte[] baseNonce,
        long chunkIndex,
        byte[] destination)
    {
        Span<byte> indexBytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(indexBytes, chunkIndex);
        Span<byte> blockBytes = stackalloc byte[sizeof(uint)];
        Span<byte> digest = stackalloc byte[Sha3_512Compat.HashSizeInBytes];

        int messageLength = ChunkNonceDomain.Length + baseNonce.Length + indexBytes.Length + blockBytes.Length;
        byte[] message = new byte[messageLength];
        try
        {
            ChunkNonceDomain.CopyTo(message, 0);
            baseNonce.CopyTo(message, ChunkNonceDomain.Length);
            indexBytes.CopyTo(message.AsSpan(ChunkNonceDomain.Length + baseNonce.Length));
            int blockOffset = ChunkNonceDomain.Length + baseNonce.Length + indexBytes.Length;

            int written = 0;
            for (uint block = 0; written < destination.Length; block++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(blockOffset, sizeof(uint)), block);
                _ = Sha3_512Compat.HashData(message, digest);

                int count = Math.Min(digest.Length, destination.Length - written);
                digest[..count].CopyTo(destination.AsSpan(written));
                written += count;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static void XCrypt(
        EncryptionSuiteParameters parameters,
        byte[] encryptionKey,
        byte[] tweak,
        byte[] counter,
        byte[] input,
        byte[] output,
        int length)
    {
        // A suite is a cascade exactly when the catalogue gave it a layer list.
        // Routing on that rather than on suite names means a new cascade is
        // driven correctly the moment it is declared, instead of falling
        // through to an exception that only shows up at run time.
        if (parameters.Cascade is { } layout)
        {
            XCryptCascade(layout, encryptionKey, tweak, counter, input, output, length);
            return;
        }

        switch (parameters.Suite)
        {
            case EncryptionSuite.Kalyna512_512:
                NativeKalyna.XCryptCtr512(encryptionKey, counter, input, output, length);
                break;
            case EncryptionSuite.Threefish1024:
                NativeThreefish.XCryptCtr1024(encryptionKey, tweak, counter, input, output, length);
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(parameters),
                    parameters.Suite,
                    "Unknown encryption suite.");
        }
    }

    private static CascadeLayout RequireCascade(EncryptionSuiteParameters parameters)
    {
        return parameters.Cascade
            ?? throw new CryptographicException("The cascade suite is missing its layer layout.");
    }

    /// <summary>
    /// Runs the plaintext through every layer of a cascade, innermost first.
    /// </summary>
    /// <remarks>
    /// Each stage owns a slice of the key and a slice of the nonce, taken in
    /// the order the stages are declared, and works in place on the buffer the
    /// previous stage produced.
    ///
    /// There is no direction parameter, and that is not an oversight. Every
    /// stage here is CTR, so each one XORs a keystream that depends on its key
    /// and nonce alone and never on the data. The layers therefore commute:
    /// the result is the plaintext XORed with all five keystreams, whichever
    /// order they are applied in, and encryption and decryption are the same
    /// walk. Introducing a direction flag would imply a dependency that does
    /// not exist and would be one more thing to get backwards.
    ///
    /// The authenticated stage, if there is one, is not handled here. It sits
    /// outside the CTR stack because it also produces a tag, and a function
    /// that returned ciphertext for five layers and ciphertext-plus-tag for the
    /// sixth would hide that difference from its callers.
    /// </remarks>
    private static void XCryptCascade(
        CascadeLayout layout,
        byte[] encryptionKey,
        byte[] tweak,
        byte[] counter,
        byte[] input,
        byte[] output,
        int length)
    {
        if (encryptionKey.Length != layout.TotalKeyBytes || counter.Length != layout.TotalNonceBytes)
        {
            throw new CryptographicException("The cascade received key or counter material of the wrong length.");
        }

        IReadOnlyList<CascadeStage> stages = layout.Stages;
        int ctrStageCount = layout.OutermostIsAead ? stages.Count - 1 : stages.Count;

        // Where each stage's key and nonce begin. Computed once so a stage
        // cannot be handed the neighbouring layer's material by an arithmetic
        // slip at the call site.
        int[] keyOffsets = new int[stages.Count];
        int[] nonceOffsets = new int[stages.Count];
        int keyCursor = 0;
        int nonceCursor = 0;
        for (int index = 0; index < stages.Count; index++)
        {
            keyOffsets[index] = keyCursor;
            nonceOffsets[index] = nonceCursor;
            keyCursor += stages[index].KeyBytes;
            nonceCursor += stages[index].NonceBytes;
        }

        if (!ReferenceEquals(input, output))
        {
            input.AsSpan(0, length).CopyTo(output);
        }

        for (int index = 0; index < ctrStageCount; index++)
        {
            CascadeStage stage = stages[index];

            byte[] stageKey = new byte[stage.KeyBytes];
            byte[] stageCounter = new byte[stage.NonceBytes];
            using IDisposable stageKeyLock = SecureMemory.TryLock(stageKey);
            using IDisposable stageCounterLock = SecureMemory.TryLock(stageCounter);
            try
            {
                encryptionKey.AsSpan(keyOffsets[index], stage.KeyBytes).CopyTo(stageKey);
                counter.AsSpan(nonceOffsets[index], stage.NonceBytes).CopyTo(stageCounter);
                ApplyCtrStage(stage, stageKey, tweak, stageCounter, output, length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stageKey);
                CryptographicOperations.ZeroMemory(stageCounter);
            }
        }
    }


    /// <summary>
    /// Associated data binding one chunk to its place in one archive.
    /// </summary>
    /// <remarks>
    /// Poly1305 proves a chunk was not altered. On its own it does not prove
    /// the chunk belongs where it was found: an attacker holding two archives,
    /// or two positions in one archive, could move a chunk and every tag would
    /// still verify. Binding the format version, the suite, the archive's own
    /// identity, the chunk's index and its length into the tag is what closes
    /// that, and it costs nothing because the AEAD authenticates associated
    /// data it never has to store.
    ///
    /// The archive identity is the header nonce, which is unique per archive
    /// and already authenticated by the container's own MACs.
    /// </remarks>
    private static byte[] BuildChunkAssociatedData(
        EncryptionSuiteParameters parameters,
        ReadOnlySpan<byte> archiveNonce,
        long chunkIndex,
        int length)
    {
        // The archive identity is a digest of the whole base nonce, not its
        // first bytes: nonces range from 12 bytes for ChaCha20-Poly1305 alone to
        // 536 for the two-round paranoia cascade, and slicing a fixed prefix
        // both overruns the short ones and ignores most of the long ones.
        const int identityBytes = 16;
        Span<byte> identityDigest = stackalloc byte[Sha3_512Compat.HashSizeInBytes];
        _ = Sha3_512Compat.HashData(archiveNonce, identityDigest);

        byte[] associated = new byte[4 + 4 + identityBytes + sizeof(long) + sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(associated.AsSpan(0), CurrentVersion);
        BinaryPrimitives.WriteInt32BigEndian(associated.AsSpan(4), (int)parameters.Suite);
        identityDigest[..identityBytes].CopyTo(associated.AsSpan(8));
        BinaryPrimitives.WriteInt64BigEndian(associated.AsSpan(8 + identityBytes), chunkIndex);
        BinaryPrimitives.WriteInt32BigEndian(associated.AsSpan(8 + identityBytes + sizeof(long)), length);
        return associated;
    }

    /// <summary>
    /// The slice of the derived key and of the chunk nonce that belong to the
    /// authenticated outermost layer.
    /// </summary>
    private static (byte[] Key, byte[] Nonce) SplitAeadMaterial(
        CascadeLayout layout,
        byte[] encryptionKey,
        byte[] counter)
    {
        CascadeStage stage = layout.Stages[^1];
        int keyOffset = layout.TotalKeyBytes - stage.KeyBytes;
        int nonceOffset = layout.TotalNonceBytes - stage.NonceBytes;
        return (
            encryptionKey.AsSpan(keyOffset, stage.KeyBytes).ToArray(),
            counter.AsSpan(nonceOffset, stage.NonceBytes).ToArray());
    }

    private static void ApplyCtrStage(
        CascadeStage stage,
        byte[] key,
        byte[] tweak,
        byte[] counter,
        byte[] buffer,
        int length)
    {
        switch (stage.Cipher)
        {
            case CascadeCipher.Aes256:
                NativeAes.XCryptCtr256(key, counter, buffer, buffer, length);
                break;
            case CascadeCipher.Mars448:
                NativeMars.XCryptCtr448(key, counter, buffer, buffer, length);
                break;
            case CascadeCipher.Shacal2_512:
                NativeShacal2.XCryptCtr512(key, counter, buffer, buffer, length);
                break;
            case CascadeCipher.Kalyna512_512:
                NativeKalyna.XCryptCtr512(key, counter, buffer, buffer, length);
                break;
            case CascadeCipher.Threefish1024:
                NativeThreefish.XCryptCtr1024(key, tweak, counter, buffer, buffer, length);
                break;
            default:
                throw new CryptographicException(
                    $"{stage.Cipher} is not a counter-mode stage and cannot be applied here.");
        }
    }

    /// <summary>
    /// Derives the Threefish tweak for the suites that use one.
    /// </summary>
    /// <remarks>
    /// The tweak is bound to the whole nonce, so for the cascade it commits to
    /// both layers' nonces at once. Deriving it rather than storing an
    /// independent value keeps the header from carrying a parameter an attacker
    /// could vary on its own.
    /// </remarks>
    private static byte[] CreateSuiteTweak(EncryptionSuite suite, byte[] nonce)
    {
        // Driven by the catalogue rather than by a list of suite names. A suite
        // needs a tweak exactly when it contains a Threefish layer, and that is
        // already recorded as its tweak size; keeping a second list in step with
        // the first is how the next suite gets forgotten here.
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite.");
        }

        if (EncryptionSuiteCatalog.Get(suite).TweakBytes == 0)
        {
            return [];
        }

        byte[] material = new byte[sizeof(int) + ThreefishTweakDomain.Length + sizeof(int) + nonce.Length];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(material.AsSpan(offset, sizeof(int)), ThreefishTweakDomain.Length);
        offset += sizeof(int);
        ThreefishTweakDomain.CopyTo(material, offset);
        offset += ThreefishTweakDomain.Length;
        BinaryPrimitives.WriteInt32LittleEndian(material.AsSpan(offset, sizeof(int)), nonce.Length);
        offset += sizeof(int);
        nonce.CopyTo(material, offset);
        byte[] hash = Sha3_512Compat.HashData(material);
        try
        {
            return hash[..16];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    /// <summary>
    /// The reference libraries a suite needs that are not loadable.
    /// </summary>
    /// <remarks>
    /// Derived from the suite's layer list rather than from its name. Every
    /// time a suite was added, one of these gates was the thing that got
    /// forgotten, and the failure does not appear where the mistake is — it
    /// appears the first time somebody picks that suite. A suite is usable
    /// exactly when every cipher it names can be loaded, and that question the
    /// catalogue can already answer.
    ///
    /// threefish_ref is always required because it also provides Skein for the
    /// second MAC, whichever ciphers the suite itself uses.
    /// </remarks>
    private static IReadOnlyList<string> MissingNativeLibraries(EncryptionSuite suite)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            return ["an unknown encryption suite"];
        }

        var missing = new List<string>();
        if (!NativeThreefish.IsAvailable())
        {
            missing.Add("threefish_ref.dll");
        }

        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
        IEnumerable<CascadeCipher> ciphers = parameters.Cascade is { } layout
            ? layout.Stages.Select(stage => stage.Cipher)
            : [
                suite == EncryptionSuite.Kalyna512_512
                    ? CascadeCipher.Kalyna512_512
                    : CascadeCipher.Threefish1024,
            ];

        foreach (CascadeCipher cipher in ciphers.Distinct())
        {
            (bool available, string library) = cipher switch
            {
                CascadeCipher.Aes256 => (NativeAes.IsAvailable(), "aes_ref.dll"),
                CascadeCipher.Mars448 => (NativeMars.IsAvailable(), "mars_ref.dll"),
                CascadeCipher.Shacal2_512 => (NativeShacal2.IsAvailable(), "shacal2_ref.dll"),
                CascadeCipher.Kalyna512_512 => (NativeKalyna.IsAvailable(), "kalyna_ref.dll"),
                CascadeCipher.Threefish1024 => (NativeThreefish.IsAvailable(), "threefish_ref.dll"),
                CascadeCipher.ChaCha20Poly1305 => (NativeChaChaPoly.IsAvailable(), "chachapoly_ref.dll"),
                _ => (false, "an unknown cipher"),
            };
            if (!available && !missing.Contains(library))
            {
                missing.Add(library);
            }
        }

        return missing;
    }

    private static void EnsureNativeAvailable(EncryptionSuite suite)
    {
        IReadOnlyList<string> missing = MissingNativeLibraries(suite);
        if (missing.Count == 0)
        {
            return;
        }

        throw new PlatformNotSupportedException(
            "The signed and dual-manifest-verified reference library "
            + string.Join(", ", missing)
            + " is unavailable.");
    }

    private static void ValidateHeader(ContainerHeader header)
    {
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.FromAlgorithm(header.Algorithm);
        if (header.Version != CurrentVersion
            || header.BlockBits != parameters.BlockBytes * 8
            || !string.Equals(header.CounterEndian, EncryptionSuiteCatalog.CounterEndian, StringComparison.Ordinal)
            || header.EncryptionKeyBits != parameters.EncryptionKeyBytes * 8
            || header.Sha3MacKeyBits != parameters.Sha3MacKeyBytes * 8
            || header.Sha3TagBits != Sha3TagSize * 8
            || header.SkeinMacKeyBits != parameters.SkeinMacKeyBytes * 8
            || header.SkeinTagBits != SkeinTagSize * 8
            || header.SaltBits != EntropyMixer.SaltPairBytes * 8
            || header.NonceBits != parameters.NonceBytes * 8
            || header.TweakBits != parameters.TweakBytes * 8
            || !string.Equals(
                header.TweakMode,
                parameters.TweakBytes > 0 ? EncryptionSuiteCatalog.ThreefishTweakMode : "None",
                StringComparison.Ordinal)
            || header.KdfBranchOutputBits != 512
            || header.MasterKeyBits != MasterKeyBits
            || !string.Equals(header.KdfExecutionMode, "Sequential", StringComparison.Ordinal)
            || !string.Equals(header.KdfMemoryMode, "PMI16", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Container header contains invalid v10 suite parameters.");
        }

        ValidatePasswordMode(header);
        if (header.Argon2MemoryKiB != 0
            || header.Argon2Iterations != (int)V10MasterKdf.Iterations
            || header.Argon2Parallelism != (int)V10MasterKdf.Parallelism)
        {
            throw new InvalidDataException("Container header does not use the fixed v10 Argon2id profile.");
        }

        if (header.Hint is { Length: > 180 } || header.Hint?.Any(char.IsControl) == true)
        {
            throw new InvalidDataException("Container header contains an invalid public password hint.");
        }

        if (string.IsNullOrWhiteSpace(header.Salt) || string.IsNullOrWhiteSpace(header.Nonce))
        {
            throw new InvalidDataException("Container header contains no salt or nonce.");
        }

        ValidateSecondRound(header, parameters);

        byte[]? salt = null;
        byte[]? nonce = null;
        byte[]? tweak = null;
        byte[]? expectedTweak = null;
        try
        {
            salt = Convert.FromBase64String(header.Salt);
            nonce = Convert.FromBase64String(header.Nonce);
            tweak = string.IsNullOrEmpty(header.Tweak) ? [] : Convert.FromBase64String(header.Tweak);
            if (salt.Length != EntropyMixer.SaltPairBytes
                || nonce.Length != parameters.NonceBytes
                || tweak.Length != parameters.TweakBytes)
            {
                throw new InvalidDataException("Container header contains invalid salt, nonce, or tweak lengths.");
            }

            expectedTweak = CreateSuiteTweak(parameters.Suite, nonce);
            if (!CryptographicOperations.FixedTimeEquals(tweak, expectedTweak))
            {
                throw new InvalidDataException("Container header contains a non-canonical Threefish tweak.");
            }
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Container header contains invalid Base64 parameters.", ex);
        }
        finally
        {
            ZeroIfNotNull(salt);
            ZeroIfNotNull(nonce);
            ZeroIfNotNull(tweak);
            ZeroIfNotNull(expectedTweak);
        }
    }

    /// <summary>
    /// Checks the second Argon2id round's salt and nonce against the suite.
    /// </summary>
    /// <remarks>
    /// Whether a second round exists is a property of the suite, not something
    /// the header may assert on its own: a header claiming a second round for a
    /// single-round suite would derive a key nobody can reproduce, and a
    /// two-round suite missing either value cannot be opened at all — not even
    /// by the machine that wrote it, because neither the second salt nor the
    /// second nonce is derivable from the first.
    ///
    /// Both are therefore required together and refused together, and the
    /// second salt is rejected if it repeats the first: that can only mean the
    /// writer used one round's material for both, which silently collapses the
    /// second round back onto the first.
    /// </remarks>
    private static void ValidateSecondRound(ContainerHeader header, EncryptionSuiteParameters parameters)
    {
        bool expected = parameters.UsesTwoKdfRounds;
        bool present = header.SecondSalt is not null || header.SecondNonce is not null;

        if (!expected)
        {
            if (present || header.SecondSaltBits != 0 || header.SecondNonceBits != 0)
            {
                throw new InvalidDataException(
                    "Container header carries second-round key material for a suite that derives one round.");
            }

            return;
        }

        if (string.IsNullOrWhiteSpace(header.SecondSalt) || string.IsNullOrWhiteSpace(header.SecondNonce))
        {
            throw new InvalidDataException(
                "Container header is missing the second Argon2id round's salt or nonce.");
        }

        if (header.SecondSaltBits != EntropyMixer.SaltPairBytes * 8
            || header.SecondNonceBits != parameters.NonceBytes * 8)
        {
            throw new InvalidDataException("Container header contains invalid second-round parameter lengths.");
        }

        byte[]? secondSalt = null;
        byte[]? secondNonce = null;
        byte[]? firstSalt = null;
        try
        {
            secondSalt = Convert.FromBase64String(header.SecondSalt);
            secondNonce = Convert.FromBase64String(header.SecondNonce);
            firstSalt = Convert.FromBase64String(header.Salt!);

            if (secondSalt.Length != EntropyMixer.SaltPairBytes
                || secondNonce.Length != parameters.NonceBytes)
            {
                throw new InvalidDataException("Container header contains invalid second-round lengths.");
            }

            if (CryptographicOperations.FixedTimeEquals(firstSalt, secondSalt))
            {
                throw new InvalidDataException("Container header reuses the first round's salt for the second.");
            }
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Container header contains invalid Base64 second-round parameters.", ex);
        }
        finally
        {
            ZeroIfNotNull(secondSalt);
            ZeroIfNotNull(secondNonce);
            ZeroIfNotNull(firstSalt);
        }
    }

    private static void ValidatePasswordMode(ContainerHeader header)
    {
        if (header.GeneratedPasswordFactorCount != 2
            || header.GeneratedPasswordBits != 1024
            || !string.Equals(header.PasswordMode, V10MasterKdf.PasswordMode, StringComparison.Ordinal)
            || !string.Equals(header.KdfInputMode, V10MasterKdf.KdfInputMode, StringComparison.Ordinal)
            || !string.Equals(header.KdfMode, V10MasterKdf.KdfMode, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Container header contains no valid v10 four-credential KDF model.");
        }
    }

    private static void ValidateHintForCreation(string? hint)
    {
        if (hint is { Length: > 180 } || hint?.Any(char.IsControl) == true)
        {
            throw new ArgumentOutOfRangeException(nameof(hint), "The public password hint must contain at most 180 non-control characters.");
        }
    }

    private static void ZeroIfNotNull(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    /// <summary>
    /// Turns the header's salt pairs and the four credentials into the suite's
    /// keys.
    /// </summary>
    /// <remarks>
    /// A v10 salt field is a pair — the SHA3 branch's 512-bit salt followed by
    /// the Skein branch's — because every path that carries one carries the
    /// other. Splitting them here, at the one place that talks to the KDF,
    /// keeps the container plumbing to a single salt per round.
    ///
    /// The work runs on a worker thread: two or four Argon2id calls of at least
    /// a gibibyte each would otherwise block whichever thread called in, which
    /// on the desktop is the interface thread.
    /// </remarks>
    private static Task<SuiteKeyMaterial> DeriveV10KeyMaterialAsync(
        EncryptionSuiteParameters parameters,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] salt,
        byte[] secondSalt,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(salt);
        V10Salts salts = SplitSaltPairs(salt, secondSalt, parameters.UsesTwoKdfRounds);
        return Task.Run(
            () =>
            {
                using RoleKeyMaterial roles = V10KeyDerivation.DeriveSuiteKeys(
                    parameters,
                    userPassword,
                    pin,
                    firstGeneratedPassword,
                    secondGeneratedPassword,
                    salts,
                    progress,
                    cancellationToken);
                return SuiteKeyMaterial.FromRoleKeys(roles, parameters);
            },
            cancellationToken);
    }

    private static V10Salts SplitSaltPairs(byte[] salt, byte[]? secondSalt, bool paranoia)
    {
        if (salt.Length != EntropyMixer.SaltPairBytes)
        {
            throw new InvalidDataException(
                $"A v10 salt field must be {EntropyMixer.SaltPairBytes} bytes.");
        }

        byte[] sha3Round1 = salt[..V10Salts.SaltBytes];
        byte[] skeinRound1 = salt[V10Salts.SaltBytes..];
        byte[]? sha3Round2 = null;
        byte[]? skeinRound2 = null;
        if (paranoia)
        {
            if (secondSalt is null || secondSalt.Length != EntropyMixer.SaltPairBytes)
            {
                throw new InvalidDataException(
                    "The two-round suite is missing its second v10 salt pair.");
            }

            sha3Round2 = secondSalt[..V10Salts.SaltBytes];
            skeinRound2 = secondSalt[V10Salts.SaltBytes..];
        }
        else if (secondSalt is { Length: > 0 })
        {
            throw new InvalidDataException("A single-round suite must not carry a second salt pair.");
        }

        var salts = new V10Salts(sha3Round1, skeinRound1, sha3Round2, skeinRound2);
        salts.Validate(paranoia);
        return salts;
    }

    private sealed class SuiteKeyMaterial : IDisposable
    {
        private IDisposable? _encryptionKeyLock;
        private IDisposable? _sha3MacKeyLock;
        private IDisposable? _skeinMacKeyLock;
        private bool _disposed;

        private SuiteKeyMaterial(EncryptionSuiteParameters parameters)
        {
            EncryptionKey = new byte[parameters.EncryptionKeyBytes];
            Sha3MacKey = new byte[parameters.Sha3MacKeyBytes];
            SkeinMacKey = new byte[parameters.SkeinMacKeyBytes];
        }

        public byte[] EncryptionKey { get; }

        public byte[] Sha3MacKey { get; }

        public byte[] SkeinMacKey { get; }

        /// <summary>
        /// Takes over the keys the v10 role schedule derived.
        /// </summary>
        /// <remarks>
        /// v10 derives each role from its own domain-separated context rather
        /// than slicing one flat Argon2id output, so there is nothing to slice
        /// here — only three finished keys to copy into locked storage.
        /// </remarks>
        public static SuiteKeyMaterial FromRoleKeys(RoleKeyMaterial roles, EncryptionSuiteParameters parameters)
        {
            ArgumentNullException.ThrowIfNull(roles);
            if (roles.EncryptionKey.Bytes.Length != parameters.EncryptionKeyBytes
                || roles.Sha3MacKey.Bytes.Length != parameters.Sha3MacKeyBytes
                || roles.SkeinMacKey.Bytes.Length != parameters.SkeinMacKeyBytes)
            {
                throw new CryptographicException("The v10 role schedule returned an invalid key length.");
            }

            var material = new SuiteKeyMaterial(parameters);
            try
            {
                material._encryptionKeyLock = SecureMemory.TryLock(material.EncryptionKey);
                material._sha3MacKeyLock = SecureMemory.TryLock(material.Sha3MacKey);
                material._skeinMacKeyLock = SecureMemory.TryLock(material.SkeinMacKey);
                roles.EncryptionKey.Bytes.CopyTo(material.EncryptionKey, 0);
                roles.Sha3MacKey.Bytes.CopyTo(material.Sha3MacKey, 0);
                roles.SkeinMacKey.Bytes.CopyTo(material.SkeinMacKey, 0);
                return material;
            }
            catch
            {
                material.Dispose();
                throw;
            }
        }

        public static SuiteKeyMaterial Create(ReadOnlySpan<byte> derivedKey, EncryptionSuiteParameters parameters)
        {
            if (derivedKey.Length != parameters.DerivedKeyBytes)
            {
                throw new CryptographicException("Argon2id returned an invalid suite key length.");
            }

            var material = new SuiteKeyMaterial(parameters);
            try
            {
                material._encryptionKeyLock = SecureMemory.TryLock(material.EncryptionKey);
                material._sha3MacKeyLock = SecureMemory.TryLock(material.Sha3MacKey);
                material._skeinMacKeyLock = SecureMemory.TryLock(material.SkeinMacKey);

                int encryptionKeyEnd = parameters.EncryptionKeyBytes;
                int sha3MacKeyEnd = encryptionKeyEnd + parameters.Sha3MacKeyBytes;
                derivedKey.Slice(0, encryptionKeyEnd).CopyTo(material.EncryptionKey);
                derivedKey.Slice(encryptionKeyEnd, parameters.Sha3MacKeyBytes).CopyTo(material.Sha3MacKey);
                derivedKey.Slice(sha3MacKeyEnd, parameters.SkeinMacKeyBytes).CopyTo(material.SkeinMacKey);
                return material;
            }
            catch
            {
                material.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            CryptographicOperations.ZeroMemory(EncryptionKey);
            CryptographicOperations.ZeroMemory(Sha3MacKey);
            CryptographicOperations.ZeroMemory(SkeinMacKey);
            _skeinMacKeyLock?.Dispose();
            _sha3MacKeyLock?.Dispose();
            _encryptionKeyLock?.Dispose();
        }
    }

    private sealed record ContainerHeader(
        int Version,
        string Algorithm,
        int BlockBits,
        string CounterEndian,
        int EncryptionKeyBits,
        int Sha3MacKeyBits,
        int Sha3TagBits,
        int SkeinMacKeyBits,
        int SkeinTagBits,
        int SaltBits,
        string Salt,
        int NonceBits,
        string Nonce,
        int TweakBits,
        string TweakMode,
        string? Tweak,
        string? Hint,
        int Argon2MemoryKiB,
        int Argon2Iterations,
        int Argon2Parallelism,
        int KdfBranchOutputBits,
        int MasterKeyBits,
        string? KdfExecutionMode,
        string? KdfMemoryMode,
        string? PasswordMode,
        string? KdfInputMode,
        int GeneratedPasswordBits,
        int GeneratedPasswordFactorCount = 0,

        // How the master is built. Named separately from KdfInputMode because
        // the two answer different questions: the input mode says what goes
        // into Argon2id, this says what happens around it.
        string? KdfMode = null,

        // The second Argon2id round, present only for suites that run one.
        //
        // Both values have to survive into the header or the archive cannot be
        // opened by anybody, including the machine that wrote it: the second
        // round's salt is not derivable from the first, and its nonce is not
        // derivable from the first either. They are nullable rather than absent
        // because the header is compared against its own canonical
        // re-serialization — a field that disappeared for single-round suites
        // would change the byte layout and the reader would reject containers
        // this app had just written.
        int SecondSaltBits = 0,
        string? SecondSalt = null,
        int SecondNonceBits = 0,
        string? SecondNonce = null);

    [JsonSourceGenerationOptions(
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        GenerationMode = JsonSourceGenerationMode.Metadata)]
    [JsonSerializable(typeof(ContainerHeader))]
    private sealed partial class ContainerJsonContext : JsonSerializerContext;
}

public sealed record KalynaContainerInfo(
    int Version,
    string Algorithm,
    EncryptionSuite Suite,
    string? PasswordMode,
    string? KdfInputMode,
    string? Hint,
    int GeneratedPasswordBits,
    int GeneratedPasswordFactorCount,
    int SaltBits,
    int NonceBits,
    bool RequiresGeneratedPassword);

internal sealed class ContainerRecoveryKdfInfo : IDisposable
{
    private bool _disposed;

    public ContainerRecoveryKdfInfo(
        EncryptionSuite suite,
        string algorithm,
        byte[] salt,
        Argon2Profile argon2Profile)
    {
        Suite = suite;
        Algorithm = algorithm;
        Salt = salt;
        Argon2Profile = argon2Profile;
    }

    public EncryptionSuite Suite { get; }

    public string Algorithm { get; }

    public byte[] Salt { get; }

    public Argon2Profile Argon2Profile { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(Salt);
    }
}

internal static unsafe class NativeKalyna
{
    private const string DllName = "kalyna_ref.dll";
    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int> _xcryptCtr;

    /// <summary>
    /// Why the last <see cref="IsAvailable"/> probe failed, or null when the
    /// library is loaded. A security tool that reports a reference library as
    /// unavailable has to be able to say why, otherwise a signing, integrity
    /// or platform fault is indistinguishable from a missing file.
    /// </summary>
    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void XCryptCtr512(byte[] key, byte[] nonce, byte[] input, byte[] output)
    {
        XCryptCtr512(key, nonce, input, output, input.Length);
    }

    public static void XCryptCtr512(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != 64 || nonce.Length != 64 || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException("Kalyna-512/512 requires a 64-byte key, 64-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length);
        }

        if (result != 0)
        {
            throw new CryptographicException(result switch
            {
                1 => "Kalyna reference library received invalid buffers.",
                2 => "Kalyna reference library could not initialize a cipher context.",
                3 => "Kalyna reference library could not start CTR worker threads.",
                4 => "Kalyna CTR counter is exhausted or overflowed.",
                _ => $"Kalyna reference library returned error {result}.",
            });
        }
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle == 0)
            {
                nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
                try
                {
                    _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int>)
                        NativeLibrary.GetExport(handle, "kalyna_512_512_ctr_xcrypt");
                    _libraryHandle = handle;
                }
                catch
                {
                    NativeLibrary.Free(handle);
                    _xcryptCtr = null;
                    throw;
                }
            }
        }
    }
}

internal static unsafe class NativeThreefish
{
    private const string DllName = "threefish_ref.dll";
    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, int> _encryptBlock;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, byte*, nuint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, nint> _skeinMacCreate;
    private static delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _skeinUpdate;
    private static delegate* unmanaged[Cdecl]<nint, byte*, nuint, int> _skeinFinal;
    private static delegate* unmanaged[Cdecl]<nint, void> _skeinDestroy;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, int> _skeinHash;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, int> _skeinMac;

    /// <summary>
    /// Why the last <see cref="IsAvailable"/> probe failed, or null when the
    /// library is loaded. A security tool that reports a reference library as
    /// unavailable has to be able to say why, otherwise a signing, integrity
    /// or platform fault is indistinguishable from a missing file.
    /// </summary>
    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void EncryptBlock1024(byte[] key, byte[] tweak, byte[] input, byte[] output)
    {
        if (key.Length != 128 || tweak.Length != 16 || input.Length != 128 || output.Length != 128)
        {
            throw new ArgumentException("Threefish-1024 requires a 128-byte key/block and a 16-byte tweak.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* tweakPointer = tweak)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, tweakPointer, inputPointer, outputPointer);
        }

        if (result != 0)
        {
            throw new CryptographicException($"Threefish reference block function returned error {result}.");
        }
    }

    public static void XCryptCtr1024(byte[] key, byte[] tweak, byte[] nonce, byte[] input, byte[] output)
    {
        XCryptCtr1024(key, tweak, nonce, input, output, input.Length);
    }

    public static void XCryptCtr1024(byte[] key, byte[] tweak, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != 128
            || tweak.Length != 16
            || nonce.Length != 128
            || length < 0
            || input.Length < length
            || output.Length < length)
        {
            throw new ArgumentException("Threefish-1024 CTR requires a 128-byte key/nonce, 16-byte tweak, and sufficiently large buffers.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* tweakPointer = tweak)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, tweakPointer, noncePointer, inputPointer, outputPointer, (nuint)length);
        }

        if (result != 0)
        {
            throw new CryptographicException(result switch
            {
                1 => "Threefish reference library received invalid buffers.",
                3 => "Threefish reference library could not start CTR worker threads.",
                4 => "Threefish CTR counter is exhausted or overflowed.",
                _ => $"Threefish reference library returned error {result}.",
            });
        }
    }

    public static NativeSkein1024Mac CreateSkeinMac(byte[] key)
    {
        if (key.Length != Skein1024Digest.MacKeySize)
        {
            throw new ArgumentException("Skein-1024 keyed mode requires a 128-byte key.", nameof(key));
        }

        EnsureLoaded();
        nint handle;
        fixed (byte* keyPointer = key)
        {
            handle = _skeinMacCreate(keyPointer, (nuint)key.Length);
        }

        if (handle == 0)
        {
            throw new CryptographicException("Skein-1024 could not initialize a locked keyed state.");
        }

        return new NativeSkein1024Mac(handle);
    }

    internal static byte[] HashSkein1024Reference(byte[] input)
    {
        EnsureLoaded();
        byte[] output = new byte[Skein1024Digest.DigestSize];
        int result;
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _skeinHash(inputPointer, (nuint)input.Length, outputPointer);
        }

        if (result != 0)
        {
            CryptographicOperations.ZeroMemory(output);
            throw new CryptographicException($"Skein-1024 reference hash returned error {result}.");
        }

        return output;
    }

    internal static byte[] MacSkein1024Reference(byte[] key, byte[] input)
    {
        if (key.Length != Skein1024Digest.MacKeySize)
        {
            throw new ArgumentException("Skein-1024 keyed mode requires a 128-byte key.", nameof(key));
        }

        EnsureLoaded();
        byte[] output = new byte[Skein1024Digest.DigestSize];
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _skeinMac(
                keyPointer,
                (nuint)key.Length,
                inputPointer,
                (nuint)input.Length,
                outputPointer);
        }

        if (result != 0)
        {
            CryptographicOperations.ZeroMemory(output);
            throw new CryptographicException($"Skein-1024 reference MAC returned error {result}.");
        }

        return output;
    }

    internal static void UpdateSkein(nint handle, ReadOnlySpan<byte> data)
    {
        EnsureLoaded();
        int result;
        fixed (byte* dataPointer = data)
        {
            result = _skeinUpdate(handle, dataPointer, (nuint)data.Length);
        }

        if (result != 0)
        {
            throw new CryptographicException($"Skein-1024 reference update returned error {result}.");
        }
    }

    internal static byte[] FinalizeSkein(nint handle)
    {
        EnsureLoaded();
        byte[] output = new byte[Skein1024Digest.DigestSize];
        int result;
        fixed (byte* outputPointer = output)
        {
            result = _skeinFinal(handle, outputPointer, (nuint)output.Length);
        }

        if (result != 0)
        {
            CryptographicOperations.ZeroMemory(output);
            throw new CryptographicException($"Skein-1024 reference finalization returned error {result}.");
        }

        return output;
    }

    internal static void DestroySkein(nint handle)
    {
        if (handle == 0 || _libraryHandle == 0 || _skeinDestroy == null)
        {
            return;
        }

        _skeinDestroy(handle);
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle == 0)
            {
                nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
                try
                {
                    _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, int>)
                        NativeLibrary.GetExport(handle, "threefish_1024_encrypt_block");
                    _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, byte*, nuint, int>)
                        NativeLibrary.GetExport(handle, "threefish_1024_ctr_xcrypt");
                    _skeinMacCreate = (delegate* unmanaged[Cdecl]<byte*, nuint, nint>)
                        NativeLibrary.GetExport(handle, "skein_1024_mac_create");
                    _skeinUpdate = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)
                        NativeLibrary.GetExport(handle, "skein_1024_update");
                    _skeinFinal = (delegate* unmanaged[Cdecl]<nint, byte*, nuint, int>)
                        NativeLibrary.GetExport(handle, "skein_1024_final");
                    _skeinDestroy = (delegate* unmanaged[Cdecl]<nint, void>)
                        NativeLibrary.GetExport(handle, "skein_1024_destroy");
                    _skeinHash = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, int>)
                        NativeLibrary.GetExport(handle, "skein_1024_hash");
                    _skeinMac = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, int>)
                        NativeLibrary.GetExport(handle, "skein_1024_mac");
                    _libraryHandle = handle;
                }
                catch
                {
                    NativeLibrary.Free(handle);
                    _encryptBlock = null;
                    _xcryptCtr = null;
                    _skeinMacCreate = null;
                    _skeinUpdate = null;
                    _skeinFinal = null;
                    _skeinDestroy = null;
                    _skeinHash = null;
                    _skeinMac = null;
                    throw;
                }
            }
        }
    }
}

internal sealed class NativeSkein1024Mac : IDisposable
{
    private nint _handle;
    private bool _finalized;

    internal NativeSkein1024Mac(nint handle)
    {
        _handle = handle != 0 ? handle : throw new ArgumentOutOfRangeException(nameof(handle));
    }

    ~NativeSkein1024Mac()
    {
        Dispose(disposing: false);
    }

    public void AppendData(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_handle == 0, this);
        if (_finalized)
        {
            throw new InvalidOperationException("Skein-1024 MAC has already been finalized.");
        }

        NativeThreefish.UpdateSkein(_handle, data);
    }

    public byte[] GetTag()
    {
        ObjectDisposedException.ThrowIf(_handle == 0, this);
        if (_finalized)
        {
            throw new InvalidOperationException("Skein-1024 MAC has already been finalized.");
        }

        byte[] tag = NativeThreefish.FinalizeSkein(_handle);
        _finalized = true;
        return tag;
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        _ = disposing;
        nint handle = Interlocked.Exchange(ref _handle, 0);
        if (handle != 0)
        {
            NativeThreefish.DestroySkein(handle);
        }
    }
}
