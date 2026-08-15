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
    private static readonly byte[] ThreefishTweakDomain = "Kalyna-ZPAQ/v7/Threefish-1024/CTR-Tweak"u8.ToArray();
    private const int CurrentVersion = 7;
    private const int BufferSize = 16 * 1024 * 1024;
    private const int Sha3TagSize = 64;
    private const int SkeinTagSize = 128;
    private const int MaxHeaderSize = 16 * 1024;
    private readonly PasswordKeyService _passwords = new();

    public bool IsNativeKalynaAvailable => NativeKalyna.IsAvailable();
    public bool IsNativeThreefishAvailable => NativeThreefish.IsAvailable();

    public bool IsNativeSuiteAvailable(EncryptionSuite suite)
    {
        return suite switch
        {
            EncryptionSuite.Kalyna512_512 => IsNativeKalynaAvailable && IsNativeThreefishAvailable,
            EncryptionSuite.Threefish1024 => IsNativeThreefishAvailable,
            _ => false,
        };
    }

    public Task EncryptZpaqStreamAsync(
        Stream plainZpaqStream,
        string encryptedPath,
        string userPassword,
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

        LockedSensitiveBuffer saltBuffer;
        LockedSensitiveBuffer nonceBuffer;
        if (preparedEntropy is null)
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
        byte[] kdfSalt = [];
        SuiteKeyMaterial? keyMaterial = null;
        byte[] tweak = [];
        byte[] counter = [];
        Argon2Profile effectiveProfile;
        try
        {
            kdfSalt = (byte[])salt.Clone();
            try
            {
                using DerivedKey key = await _passwords.DeriveAsync(
                    userPassword,
                    firstGeneratedPassword,
                    secondGeneratedPassword,
                    kdfSalt,
                    suite,
                    argon2Profile,
                    cancellationToken).ConfigureAwait(false);
                keyMaterial = SuiteKeyMaterial.Create(key.Bytes, parameters);
                effectiveProfile = key.Profile;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kdfSalt);
            }

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
                PasswordKeyService.SaltSize * 8,
                Convert.ToBase64String(salt),
                parameters.NonceBytes * 8,
                Convert.ToBase64String(nonce),
                parameters.TweakBytes * 8,
                suite == EncryptionSuite.Threefish1024 ? EncryptionSuiteCatalog.ThreefishTweakMode : "None",
                tweak.Length == 0 ? null : Convert.ToBase64String(tweak),
                hint,
                effectiveProfile.MemoryKiB,
                effectiveProfile.Iterations,
                effectiveProfile.Parallelism,
                parameters.DerivedKeyBytes * 8,
                "UserPassword+GeneratedHex512x2",
                EncryptionSuiteCatalog.KdfInputMode,
                1024,
                2);
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
                        while ((read = await ReadChunkAsync(plainZpaqStream, plainChunk, cancellationToken).ConfigureAwait(false)) > 0)
                        {
                            plaintextBytes = checked(plaintextBytes + read);
                            XCrypt(suite, keyMaterial.EncryptionKey, tweak, counter, plainChunk, cipherChunk, read);
                            await output.WriteAsync(cipherChunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                            AppendAuthentication(hmac, skeinMac, cipherChunk.AsSpan(0, read));
                            IncrementCounter(counter, BlocksForLength(read, parameters.BlockBytes));
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
            keyMaterial?.Dispose();
            CryptographicOperations.ZeroMemory(counter);
            CryptographicOperations.ZeroMemory(tweak);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(salt);
            nonceBuffer.Dispose();
            saltBuffer.Dispose();
        }
    }

    public async Task DecryptToStreamAsync(
        string encryptedPath,
        string userPassword,
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
            tweak = string.IsNullOrEmpty(header.Tweak) ? [] : Convert.FromBase64String(header.Tweak);
            Argon2Profile argon2Profile = GetArgon2Profile(header);
            using (DerivedKey key = await _passwords.DeriveAsync(
                userPassword,
                firstGeneratedPassword,
                secondGeneratedPassword,
                salt,
                parameters.Suite,
                argon2Profile,
                cancellationToken).ConfigureAwait(false))
            {
                keyMaterial = SuiteKeyMaterial.Create(key.Bytes, parameters);
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

            counter = (byte[])nonce.Clone();
            using IDisposable nonceLock = SecureMemory.TryLock(nonce);
            using IDisposable tweakLock = SecureMemory.TryLock(tweak);
            using IDisposable counterLock = SecureMemory.TryLock(counter);
            input.Position = cipherStart;
            byte[] cipherChunk = new byte[BufferSize];
            byte[] plainChunk = new byte[BufferSize];
            using IDisposable cipherChunkLock = SecureMemory.TryLock(cipherChunk);
            using IDisposable plainChunkLock = SecureMemory.TryLock(plainChunk);
            try
            {
                int read;
                while ((read = await ReadChunkAsync(input, cipherChunk, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    XCrypt(parameters.Suite, keyMaterial.EncryptionKey, tweak, counter, cipherChunk, plainChunk, read);
                    await plainZpaqDestination.WriteAsync(plainChunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    IncrementCounter(counter, BlocksForLength(read, parameters.BlockBytes));
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
            using (DerivedKey key = await _passwords.DeriveAsync(
                userPassword,
                firstGeneratedPassword,
                secondGeneratedPassword,
                salt,
                parameters.Suite,
                GetArgon2Profile(header),
                cancellationToken).ConfigureAwait(false))
            {
                salt = null;
                keyMaterial = SuiteKeyMaterial.Create(key.Bytes, parameters);
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
            salt = Convert.FromBase64String(header.Salt);
            var result = new ContainerRecoveryKdfInfo(
                parameters.Suite,
                header.Algorithm,
                salt,
                GetArgon2Profile(header));
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
                    throw new InvalidDataException("Container header is not in the unique canonical v7 JSON representation.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonicalHeader);
            }

            if (header.Version != CurrentVersion)
            {
                throw new InvalidDataException($"Only encrypted container version {CurrentVersion} is supported.");
            }

            ValidateHeader(header);
            return header;
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Container header is not valid canonical v7 JSON.", ex);
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

    private static void XCrypt(
        EncryptionSuite suite,
        byte[] encryptionKey,
        byte[] tweak,
        byte[] counter,
        byte[] input,
        byte[] output,
        int length)
    {
        switch (suite)
        {
            case EncryptionSuite.Kalyna512_512:
                NativeKalyna.XCryptCtr512(encryptionKey, counter, input, output, length);
                break;
            case EncryptionSuite.Threefish1024:
                NativeThreefish.XCryptCtr1024(encryptionKey, tweak, counter, input, output, length);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite.");
        }
    }

    private static byte[] CreateSuiteTweak(EncryptionSuite suite, byte[] nonce)
    {
        if (suite == EncryptionSuite.Kalyna512_512)
        {
            return [];
        }

        if (suite != EncryptionSuite.Threefish1024)
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite.");
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

    private static void EnsureNativeAvailable(EncryptionSuite suite)
    {
        bool available = suite switch
        {
            EncryptionSuite.Kalyna512_512 => NativeKalyna.IsAvailable() && NativeThreefish.IsAvailable(),
            EncryptionSuite.Threefish1024 => NativeThreefish.IsAvailable(),
            _ => false,
        };
        if (!available)
        {
            string library = suite == EncryptionSuite.Threefish1024
                ? "threefish_ref.dll"
                : "kalyna_ref.dll and the Skein provider threefish_ref.dll";
            throw new PlatformNotSupportedException($"The signed and dual-manifest-verified reference library {library} is unavailable.");
        }
    }

    private static Argon2Profile GetArgon2Profile(ContainerHeader header)
    {
        var profile = new Argon2Profile(header.Argon2MemoryKiB, header.Argon2Iterations, header.Argon2Parallelism);
        try
        {
            PasswordKeyService.ValidateArgon2Profile(profile);
            return profile;
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw new InvalidDataException("Container header contains an invalid Argon2id profile.", ex);
        }
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
            || header.SaltBits != PasswordKeyService.SaltSize * 8
            || header.NonceBits != parameters.NonceBytes * 8
            || header.TweakBits != parameters.TweakBytes * 8
            || !string.Equals(
                header.TweakMode,
                parameters.Suite == EncryptionSuite.Threefish1024 ? EncryptionSuiteCatalog.ThreefishTweakMode : "None",
                StringComparison.Ordinal)
            || header.Argon2OutputBits != parameters.DerivedKeyBytes * 8)
        {
            throw new InvalidDataException("Container header contains invalid v7 suite parameters.");
        }

        ValidatePasswordMode(header);
        Argon2Profile profile = GetArgon2Profile(header);
        if (profile != Argon2Profile.Default)
        {
            throw new InvalidDataException("Container header does not use the fixed v7 Argon2id profile.");
        }

        if (header.Hint is { Length: > 180 } || header.Hint?.Any(char.IsControl) == true)
        {
            throw new InvalidDataException("Container header contains an invalid public password hint.");
        }

        if (string.IsNullOrWhiteSpace(header.Salt) || string.IsNullOrWhiteSpace(header.Nonce))
        {
            throw new InvalidDataException("Container header contains no salt or nonce.");
        }

        byte[]? salt = null;
        byte[]? nonce = null;
        byte[]? tweak = null;
        byte[]? expectedTweak = null;
        try
        {
            salt = Convert.FromBase64String(header.Salt);
            nonce = Convert.FromBase64String(header.Nonce);
            tweak = string.IsNullOrEmpty(header.Tweak) ? [] : Convert.FromBase64String(header.Tweak);
            if (salt.Length != PasswordKeyService.SaltSize
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

    private static void ValidatePasswordMode(ContainerHeader header)
    {
        if (header.GeneratedPasswordFactorCount != 2
            || header.GeneratedPasswordBits != 1024
            || !string.Equals(header.PasswordMode, "UserPassword+GeneratedHex512x2", StringComparison.Ordinal)
            || !string.Equals(header.KdfInputMode, EncryptionSuiteCatalog.KdfInputMode, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Container header contains no valid v7 dual-factor KDF model.");
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
        int Argon2OutputBits,
        string? PasswordMode,
        string? KdfInputMode,
        int GeneratedPasswordBits,
        int GeneratedPasswordFactorCount = 0);

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

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            return true;
        }
        catch
        {
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

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            return true;
        }
        catch
        {
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
