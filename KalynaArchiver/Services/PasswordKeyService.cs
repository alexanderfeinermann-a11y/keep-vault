using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

public sealed class PasswordKeyService
{
    public const int MinPasswordLength = 24;
    public const int MaxPasswordLength = 256;
    public const int MinPasswordCharacterClasses = 3;
    public const int MinDistinctPasswordCharacters = 12;
    public const int MinNonHexPasswordCharacters = 12;
    public const int MaxHexadecimalRunLength = 7;
    public const double MinimumConservativeEntropyBits = 128.0;
    /// <summary>
    /// A v10 factor is 1024 bits, written as 256 uppercase hexadecimal
    /// characters on the key sheet and in the interface.
    /// </summary>
    public const int GeneratedPasswordLength = 256;
    public const int SaltSize = 64;
    public const int Argon2PasswordInputSize = 128;
    public const int KalynaDerivedKeySize = 256;
    public const int ThreefishDerivedKeySize = 320;

    /// <summary>
    /// 192 bytes of cipher key — 64 for the inner Kalyna layer, 128 for the
    /// outer Threefish layer — plus the two MAC keys.
    /// </summary>
    public const int CascadeDerivedKeySize = 384;

    /// <summary>
    /// The paranoia cascade: 376 bytes of cipher key across six layers, plus the
    /// two MAC keys.
    /// </summary>
    private const int ParanoiaDerivedKeySize = 568;
    public const int KeySize = KalynaDerivedKeySize;

    private const double EntropySafetyFactor = 0.72;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);



    private static readonly string[] CommonPasswordTerms =
    [
        "PASSWORD", "PASSWORT", "LETMEIN", "WELCOME", "ADMIN", "CORRECTHORSEBATTERY",
        "QWERTY", "ASDF", "ZXCV", "KALYNA", "ZPAQ",
    ];

    public async Task<DerivedKey> DeriveAsync(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] salt,
        CancellationToken cancellationToken)
    {
        return await DeriveAsync(
            userPassword,
            firstGeneratedPassword,
            secondGeneratedPassword,
            salt,
            EncryptionSuite.Kalyna512_512,
            Argon2Profile.Default,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DerivedKey> DeriveAsync(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] salt,
        Argon2Profile profile,
        CancellationToken cancellationToken)
    {
        return await DeriveAsync(
            userPassword,
            firstGeneratedPassword,
            secondGeneratedPassword,
            salt,
            EncryptionSuite.Kalyna512_512,
            profile,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DerivedKey> DeriveAsync(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] salt,
        EncryptionSuite suite,
        CancellationToken cancellationToken)
    {
        return await DeriveAsync(
            userPassword,
            firstGeneratedPassword,
            secondGeneratedPassword,
            salt,
            suite,
            Argon2Profile.Default,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DerivedKey> DeriveAsync(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] salt,
        EncryptionSuite suite,
        Argon2Profile profile,
        CancellationToken cancellationToken)
    {
        string normalizedFirst = NormalizeGeneratedPassword(firstGeneratedPassword);
        string normalizedSecond = NormalizeGeneratedPassword(secondGeneratedPassword);
        ValidateUserPasswordForCreation(userPassword, normalizedFirst, normalizedSecond);
        return await DeriveDualSha3Async(
            userPassword,
            normalizedFirst,
            normalizedSecond,
            salt,
            suite,
            profile,
            cancellationToken).ConfigureAwait(false);
    }

    public static string NormalizeGeneratedPassword(string generatedPassword)
    {
        ArgumentNullException.ThrowIfNull(generatedPassword);
        string normalized = new(generatedPassword.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.Length != GeneratedPasswordLength || normalized.Any(c => !IsAsciiHexDigit(c)))
        {
            throw new ArgumentOutOfRangeException(nameof(generatedPassword), $"Das generierte Passwort muss aus {GeneratedPasswordLength} Hexadezimalzeichen bestehen.");
        }

        return normalized.ToUpperInvariant();
    }

    public static void ValidateUserPasswordForCreation(string userPassword, string firstGeneratedPassword, string secondGeneratedPassword)
    {
        string normalizedFirst = NormalizeGeneratedPassword(firstGeneratedPassword);
        string normalizedSecond = NormalizeGeneratedPassword(secondGeneratedPassword);
        if (string.Equals(normalizedFirst, normalizedSecond, StringComparison.Ordinal))
        {
            throw new ArgumentException("Die beiden generierten Passwortfaktoren müssen verschieden sein.", nameof(secondGeneratedPassword));
        }

        ValidateUserPasswordAnalysis(AnalyzeUserPassword(userPassword, firstGeneratedPassword, secondGeneratedPassword));
    }

    public static PasswordPolicyAnalysis AnalyzeUserPassword(string? userPassword, params string?[] generatedPasswords)
    {
        string password = userPassword ?? string.Empty;
        var violations = new List<PasswordPolicyViolation>();
        int characterClasses = CountCharacterClasses(password);
        int distinctCharacters = password.Distinct().Count();
        int nonHexCharacters = password.Count(c => !IsAsciiHexDigit(c));
        int longestHexRun = FindLongestHexRun(password);

        if (password.Length < MinPasswordLength)
        {
            violations.Add(PasswordPolicyViolation.TooShort);
        }

        if (password.Length > MaxPasswordLength)
        {
            violations.Add(PasswordPolicyViolation.TooLong);
        }

        if (password.Any(char.IsControl))
        {
            violations.Add(PasswordPolicyViolation.ControlCharacter);
        }

        if (!IsWellFormedUtf16(password))
        {
            violations.Add(PasswordPolicyViolation.InvalidUnicode);
        }

        if (characterClasses < MinPasswordCharacterClasses)
        {
            violations.Add(PasswordPolicyViolation.NotEnoughCharacterClasses);
        }

        if (distinctCharacters < MinDistinctPasswordCharacters)
        {
            violations.Add(PasswordPolicyViolation.NotEnoughDistinctCharacters);
        }

        if (nonHexCharacters < MinNonHexPasswordCharacters)
        {
            violations.Add(PasswordPolicyViolation.NotEnoughNonHexCharacters);
        }

        if (longestHexRun > MaxHexadecimalRunLength)
        {
            violations.Add(PasswordPolicyViolation.HexadecimalRunTooLong);
        }

        if (UserPasswordMatchesAnyGeneratedPassword(password, generatedPasswords))
        {
            violations.Add(PasswordPolicyViolation.MatchesGeneratedPassword);
        }

        double entropyBits = EstimateConservativeEntropyBits(password, characterClasses, distinctCharacters);
        if (entropyBits < MinimumConservativeEntropyBits)
        {
            violations.Add(PasswordPolicyViolation.InsufficientConservativeEntropy);
        }

        return new PasswordPolicyAnalysis(
            password.Length,
            characterClasses,
            distinctCharacters,
            nonHexCharacters,
            longestHexRun,
            entropyBits,
            violations);
    }

    public static bool UserPasswordMatchesAnyGeneratedPassword(string? userPassword, params string?[] generatedPasswords)
    {
        ArgumentNullException.ThrowIfNull(generatedPasswords);
        if (string.IsNullOrEmpty(userPassword))
        {
            return false;
        }

        string normalizedUser = new(userPassword.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalizedUser.Length != GeneratedPasswordLength || normalizedUser.Any(c => !IsAsciiHexDigit(c)))
        {
            return false;
        }

        foreach (string? generatedPassword in generatedPasswords)
        {
            if (string.IsNullOrWhiteSpace(generatedPassword))
            {
                continue;
            }

            try
            {
                if (string.Equals(normalizedUser, NormalizeGeneratedPassword(generatedPassword), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch (ArgumentOutOfRangeException)
            {
                // A malformed generated factor is handled by the caller; it cannot match a
                // valid generated factor for this policy check.
            }
        }

        return false;
    }

    public static void ValidateArgon2Profile(Argon2Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile != Argon2Profile.Default)
        {
            throw new ArgumentOutOfRangeException(
                nameof(profile),
                $"Argon2id must use the fixed v9 profile: {Argon2Profile.DefaultMemoryKiB} KiB, "
                + $"{Argon2Profile.DefaultIterations} iterations, parallelism {Argon2Profile.DefaultParallelism}.");
        }
    }

    /// <summary>
    /// Derives a two-round suite's key from two Argon2id passes over the same
    /// password input with two different salts.
    /// </summary>
    /// <remarks>
    /// The paranoia cascade needs 568 bytes and one Argon2id call is kept at
    /// 384, so the material comes from two rounds laid end to end and truncated.
    /// Both rounds use the same password and the same two factors — only the
    /// salt differs, which is what makes the second round independent without
    /// asking the user for more entropy.
    ///
    /// Truncating rather than sizing the second round to the remainder keeps
    /// both calls identical in shape, so a reader cannot end up running a
    /// differently parameterised second round than the writer did.
    /// </remarks>
    public async Task<DerivedKey> DeriveTwoRoundAsync(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] firstSalt,
        byte[] secondSalt,
        EncryptionSuite suite,
        Argon2Profile profile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(firstSalt);
        ArgumentNullException.ThrowIfNull(secondSalt);
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
        if (!parameters.UsesTwoKdfRounds)
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "This suite derives a single Argon2id round.");
        }

        if (CryptographicOperations.FixedTimeEquals(firstSalt, secondSalt))
        {
            throw new CryptographicException("Both Argon2id rounds were given the same salt.");
        }

        string normalizedFirst = NormalizeGeneratedPassword(firstGeneratedPassword);
        string normalizedSecond = NormalizeGeneratedPassword(secondGeneratedPassword);
        ValidateUserPasswordForCreation(userPassword, normalizedFirst, normalizedSecond);

        using LockedSensitiveBuffer masterArgon2PasswordInput = CreateLockedArgon2PasswordInput(
            userPassword,
            normalizedFirst,
            normalizedSecond,
            suite);

        using DerivedKey round1 = await DeriveFromMasterPreHashAsync(
            masterArgon2PasswordInput.Bytes, firstSalt, CascadeDerivedKeySize, profile, cancellationToken)
            .ConfigureAwait(false);
        using DerivedKey round2 = await DeriveFromMasterPreHashAsync(
            masterArgon2PasswordInput.Bytes, secondSalt, CascadeDerivedKeySize, round1.Profile, cancellationToken)
            .ConfigureAwait(false);

        int required = parameters.DerivedKeyBytes;
        if (required > round1.Bytes.Length + round2.Bytes.Length)
        {
            throw new CryptographicException("Two Argon2id rounds do not cover this suite's key length.");
        }

        byte[] combined = new byte[required];
        byte[] reportedSalt = (byte[])firstSalt.Clone();
        IDisposable? combinedLock = null;
        IDisposable? saltLock = null;
        try
        {
            combinedLock = SecureMemory.TryLock(combined);
            saltLock = SecureMemory.TryLock(reportedSalt);

            int fromFirst = Math.Min(round1.Bytes.Length, required);
            round1.Bytes[..fromFirst].CopyTo(combined);
            if (required > fromFirst)
            {
                round2.Bytes[..(required - fromFirst)].CopyTo(combined.AsSpan(fromFirst));
            }

            return new DerivedKey(combined, reportedSalt, round1.Profile, combinedLock, saltLock);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(combined);
            CryptographicOperations.ZeroMemory(reportedSalt);
            combinedLock?.Dispose();
            saltLock?.Dispose();
            throw;
        }
    }

    private static async Task<DerivedKey> DeriveDualSha3Async(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        byte[] salt,
        EncryptionSuite suite,
        Argon2Profile profile,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using LockedSensitiveBuffer argon2PasswordInput = CreateLockedArgon2PasswordInput(
            userPassword,
            firstGeneratedPassword,
            secondGeneratedPassword,
            suite);
        int outputLength = EncryptionSuiteCatalog.Get(suite).DerivedKeyBytes;
        return await DeriveFromPreHashAsync(argon2PasswordInput.Bytes, salt, outputLength, profile, cancellationToken).ConfigureAwait(false);
    }

    internal static byte[] CreateArgon2PasswordInput(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        EncryptionSuite suite)
    {
        using LockedSensitiveBuffer lockedInput = CreateLockedArgon2PasswordInput(
            userPassword,
            firstGeneratedPassword,
            secondGeneratedPassword,
            suite);
        return lockedInput.Bytes.ToArray();
    }

    private static LockedSensitiveBuffer CreateLockedArgon2PasswordInput(
        string userPassword,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        EncryptionSuite suite)
    {
        ArgumentNullException.ThrowIfNull(userPassword);
        string normalizedFirst = NormalizeGeneratedPassword(firstGeneratedPassword);
        string normalizedSecond = NormalizeGeneratedPassword(secondGeneratedPassword);
        using LockedSensitiveBuffer userPasswordBytes = EncodeLocked(userPassword, StrictUtf8);
        using LockedSensitiveBuffer firstGeneratedBytes = EncodeLocked(normalizedFirst, Encoding.ASCII);
        using LockedSensitiveBuffer secondGeneratedBytes = EncodeLocked(normalizedSecond, Encoding.ASCII);
        using LockedSensitiveBuffer firstMessage = BuildLockedLengthPrefixedMessage(
            GetFactorDomain(suite, first: true),
            userPasswordBytes.Bytes,
            firstGeneratedBytes.Bytes);
        using LockedSensitiveBuffer secondMessage = BuildLockedLengthPrefixedMessage(
            GetFactorDomain(suite, first: false),
            userPasswordBytes.Bytes,
            secondGeneratedBytes.Bytes);
        using LockedSensitiveBuffer firstHash = HashSha3Locked(firstMessage.Bytes);
        using LockedSensitiveBuffer secondHash = HashSha3Locked(secondMessage.Bytes);
        LockedSensitiveBuffer result = CreateLockedBuffer(Argon2PasswordInputSize);
        try
        {
            Buffer.BlockCopy(firstHash.Bytes, 0, result.Bytes, 0, firstHash.Bytes.Length);
            Buffer.BlockCopy(secondHash.Bytes, 0, result.Bytes, firstHash.Bytes.Length, secondHash.Bytes.Length);
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    private static LockedSensitiveBuffer EncodeLocked(string value, Encoding encoding)
    {
        LockedSensitiveBuffer buffer = CreateLockedBuffer(encoding.GetByteCount(value));
        try
        {
            int written = encoding.GetBytes(value.AsSpan(), buffer.Bytes);
            if (written != buffer.Bytes.Length)
            {
                throw new CryptographicException("Sensitive UTF-8 input was not encoded completely.");
            }

            return buffer;
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    private static LockedSensitiveBuffer BuildLockedLengthPrefixedMessage(
        byte[] domain,
        byte[] userPasswordBytes,
        byte[] generatedPasswordBytes)
    {
        int length = checked(
            sizeof(int) + domain.Length
            + sizeof(int) + userPasswordBytes.Length
            + sizeof(int) + generatedPasswordBytes.Length);
        LockedSensitiveBuffer message = CreateLockedBuffer(length);
        try
        {
            int offset = 0;
            WriteLengthAndBytes(message.Bytes, ref offset, domain);
            WriteLengthAndBytes(message.Bytes, ref offset, userPasswordBytes);
            WriteLengthAndBytes(message.Bytes, ref offset, generatedPasswordBytes);
            return message;
        }
        catch
        {
            message.Dispose();
            throw;
        }
    }

    private static LockedSensitiveBuffer HashSha3Locked(byte[] message)
    {
        LockedSensitiveBuffer hash = CreateLockedBuffer(Sha3_512Compat.HashSizeInBytes);
        try
        {
            int written = Sha3_512Compat.HashData(message, hash.Bytes);
            if (written != Sha3_512Compat.HashSizeInBytes)
            {
                throw new CryptographicException("SHA3-512 returned an invalid digest length.");
            }

            return hash;
        }
        catch
        {
            hash.Dispose();
            throw;
        }
    }

    private static LockedSensitiveBuffer CreateLockedBuffer(int length)
    {
        return LockedSensitiveBuffer.Create(length);
    }

    /// <summary>
    /// Gives one Argon2id invocation its own locked copy of the credential
    /// prehash while leaving the locked master available to later rounds.
    /// </summary>
    /// <remarks>
    /// The native PHC adapter intentionally uses
    /// <c>ARGON2_FLAG_CLEAR_PASSWORD</c>, and <see cref="DeriveFromPreHashAsync"/>
    /// also clears the buffer on every exit. Passing the master directly would
    /// therefore turn every later round into Argon2id over an all-zero password.
    /// The one-call copy is consumed and released before this method returns;
    /// its caller owns and eventually clears the master.
    /// </remarks>
    private static async Task<DerivedKey> DeriveFromMasterPreHashAsync(
        byte[] masterArgon2PasswordInput,
        byte[] salt,
        int outputLength,
        Argon2Profile profile,
        CancellationToken cancellationToken)
    {
        if (masterArgon2PasswordInput.Length != Argon2PasswordInputSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(masterArgon2PasswordInput),
                $"Der Argon2id-Master-Passworteingang muss {Argon2PasswordInputSize} Byte lang sein.");
        }

        using LockedSensitiveBuffer oneCallInput = CreateLockedBuffer(Argon2PasswordInputSize);
        masterArgon2PasswordInput.CopyTo(oneCallInput.Bytes, 0);
        return await DeriveFromPreHashAsync(
            oneCallInput.Bytes,
            salt,
            outputLength,
            profile,
            cancellationToken).ConfigureAwait(false);
    }

    private static void ZeroIfNotNull(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The lock leases are transferred to DerivedKey on success and disposed in this method on every failure path.")]
    private static async Task<DerivedKey> DeriveFromPreHashAsync(
        byte[] argon2PasswordInput,
        byte[] salt,
        int outputLength,
        Argon2Profile profile,
        CancellationToken cancellationToken)
    {
        if (salt.Length != SaltSize)
        {
            throw new ArgumentOutOfRangeException(nameof(salt), $"Der Salt muss {SaltSize} Byte lang sein.");
        }

        if (argon2PasswordInput.Length != Argon2PasswordInputSize)
        {
            throw new ArgumentOutOfRangeException(nameof(argon2PasswordInput), $"Der Argon2id-Passworteingang muss {Argon2PasswordInputSize} Byte lang sein.");
        }

        // Checked against what the catalogue actually publishes rather than
        // against a written list. Every time a suite was added, this list was
        // the thing that got forgotten, and a missing entry does not fail at
        // the point of the mistake — it fails on the first archive.
        if (!EncryptionSuiteCatalog.IsSupportedDerivedKeyLength(outputLength))
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength), "Unsupported suite key length.");
        }

        ValidateArgon2Profile(profile);
        byte[] key = new byte[outputLength];
        IDisposable? keyLock = null;
        IDisposable? saltLock = null;
        try
        {
            keyLock = SecureMemory.TryLock(key);
            saltLock = SecureMemory.TryLock(salt);
            await Task.Run(
                () => NativeArgon2id.HashRaw((uint)profile.Iterations, (uint)profile.MemoryKiB, (uint)profile.Parallelism, argon2PasswordInput, salt, key),
                CancellationToken.None).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            var derived = new DerivedKey(key, salt, profile, keyLock, saltLock);
            keyLock = null;
            saltLock = null;
            return derived;
        }
        finally
        {
            if (keyLock is not null)
            {
                CryptographicOperations.ZeroMemory(key);
                keyLock.Dispose();
            }

            if (saltLock is not null)
            {
                CryptographicOperations.ZeroMemory(salt);
                saltLock.Dispose();
            }

            CryptographicOperations.ZeroMemory(argon2PasswordInput);
        }
    }

    private static void ValidateUserPasswordAnalysis(PasswordPolicyAnalysis analysis)
    {
        if (!analysis.IsAccepted)
        {
            throw new PasswordPolicyException(analysis);
        }
    }

    private static int CountCharacterClasses(string password)
    {
        int classes = 0;
        if (password.Any(char.IsUpper))
        {
            classes++;
        }

        if (password.Any(char.IsLower))
        {
            classes++;
        }

        if (password.Any(char.IsDigit))
        {
            classes++;
        }

        if (password.Any(c => !char.IsLetterOrDigit(c) && !char.IsControl(c)))
        {
            classes++;
        }

        return classes;
    }

    private static int FindLongestHexRun(string password)
    {
        int longest = 0;
        int current = 0;
        foreach (char character in password)
        {
            if (IsAsciiHexDigit(character))
            {
                current++;
                longest = Math.Max(longest, current);
            }
            else
            {
                current = 0;
            }
        }

        return longest;
    }

    private static bool IsAsciiHexDigit(char character)
    {
        return character is >= '0' and <= '9'
            or >= 'A' and <= 'F'
            or >= 'a' and <= 'f';
    }

    private static bool IsWellFormedUtf16(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if (char.IsHighSurrogate(character))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index]))
                {
                    return false;
                }
            }
            else if (char.IsLowSurrogate(character))
            {
                return false;
            }
        }

        return true;
    }

    private static double EstimateConservativeEntropyBits(string password, int characterClasses, int distinctCharacters)
    {
        if (password.Length == 0 || characterClasses == 0 || distinctCharacters == 0)
        {
            return 0;
        }

        int effectiveAlphabet = 0;
        if (password.Any(char.IsUpper))
        {
            effectiveAlphabet += 26;
        }

        if (password.Any(char.IsLower))
        {
            effectiveAlphabet += 26;
        }

        if (password.Any(char.IsDigit))
        {
            effectiveAlphabet += 10;
        }

        if (password.Any(c => !char.IsLetterOrDigit(c) && !char.IsControl(c)))
        {
            // Printable-symbol space is deliberately capped below the full ASCII symbol
            // range so that uncommon Unicode and whitespace never receive optimistic credit.
            effectiveAlphabet += 16;
        }

        effectiveAlphabet = Math.Max(effectiveAlphabet, distinctCharacters);
        int uniqueCount = Math.Min(distinctCharacters, effectiveAlphabet);
        double diversityBits = Log2Permutation(effectiveAlphabet, uniqueCount)
            + ((password.Length - uniqueCount) * Math.Log2(Math.Max(2, uniqueCount)));
        double penaltyBits = (password.Length - distinctCharacters) * 1.5;
        penaltyBits += FindLongestRepeatedRun(password) > 2 ? 8 : 0;
        penaltyBits += CountSequentialRuns(password) * 12;
        penaltyBits += CountKeyboardPatternHits(password) * 12;
        penaltyBits += CountCommonTermHits(password) * 32;

        double estimate = Math.Max(0, (diversityBits * EntropySafetyFactor) - penaltyBits);
        return Math.Floor(estimate * 10.0) / 10.0;
    }

    private static double Log2Permutation(int alphabetSize, int selectedCount)
    {
        double result = 0;
        for (int index = 0; index < selectedCount; index++)
        {
            result += Math.Log2(alphabetSize - index);
        }

        return result;
    }

    private static int FindLongestRepeatedRun(string password)
    {
        int longest = 0;
        int current = 0;
        char previous = '\0';
        foreach (char character in password)
        {
            current = character == previous ? current + 1 : 1;
            longest = Math.Max(longest, current);
            previous = character;
        }

        return longest;
    }

    private static int CountSequentialRuns(string password)
    {
        string normalized = password.ToUpperInvariant();
        int runs = 0;
        int index = 0;
        while (index <= normalized.Length - 3)
        {
            int first = normalized[index];
            int second = normalized[index + 1];
            int step = second - first;
            if (step is not (1 or -1))
            {
                index++;
                continue;
            }

            int end = index + 2;
            while (end < normalized.Length && normalized[end] - normalized[end - 1] == step)
            {
                end++;
            }

            if (end - index >= 3)
            {
                runs++;
                index = end;
            }
            else
            {
                index++;
            }
        }

        return runs;
    }

    private static int CountKeyboardPatternHits(string password)
    {
        string normalized = password.ToUpperInvariant();
        string[] patterns = ["QWERTY", "ASDF", "ZXCV", "1234", "9876"];
        return patterns.Count(pattern => normalized.Contains(pattern, StringComparison.Ordinal));
    }

    private static int CountCommonTermHits(string password)
    {
        string normalized = password.ToUpperInvariant();
        return CommonPasswordTerms.Count(term => normalized.Contains(term, StringComparison.Ordinal));
    }

    /// <summary>
    /// The domain separator that binds a factor to one suite.
    /// </summary>
    /// <remarks>
    /// Built from the suite's algorithm string instead of a hand-written table.
    /// Two suites must never derive the same key from the same password and
    /// factors, or a weakness found in one would carry straight over to the
    /// other — and a table is exactly the kind of thing that gets forgotten
    /// when a suite is added. Unlike a missing availability gate, that omission
    /// would not crash: it would quietly produce a colliding key.
    ///
    /// The algorithm string already names the whole construction and is part of
    /// the authenticated header, so it is both unique per suite and stable for
    /// the life of the format.
    /// </remarks>
    private static byte[] GetFactorDomain(EncryptionSuite suite, bool first)
    {
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
        string domain = $"Kalyna-ZPAQ/v9/{parameters.Algorithm}/SHA3-512/User+Factor-{(first ? "A" : "B")}";
        return Encoding.ASCII.GetBytes(domain);
    }

    private static void WriteLengthAndBytes(byte[] destination, ref int offset, byte[] source)
    {
        BinaryPrimitives.WriteInt32LittleEndian(destination.AsSpan(offset, sizeof(int)), source.Length);
        offset += sizeof(int);
        Buffer.BlockCopy(source, 0, destination, offset, source.Length);
        offset += source.Length;
    }
}

public enum PasswordPolicyViolation
{
    TooShort,
    TooLong,
    ControlCharacter,
    InvalidUnicode,
    NotEnoughCharacterClasses,
    NotEnoughDistinctCharacters,
    NotEnoughNonHexCharacters,
    HexadecimalRunTooLong,
    MatchesGeneratedPassword,
    InsufficientConservativeEntropy,
}

public sealed record PasswordPolicyAnalysis(
    int Length,
    int CharacterClassCount,
    int DistinctCharacterCount,
    int NonHexCharacterCount,
    int LongestHexadecimalRun,
    double ConservativeEntropyBits,
    IReadOnlyList<PasswordPolicyViolation> Violations)
{
    public bool IsAccepted => Violations.Count == 0;
}

public sealed class PasswordPolicyException : ArgumentException
{
    public PasswordPolicyException(PasswordPolicyAnalysis analysis)
        : base("Das Userpasswort erfüllt die Sicherheitsrichtlinie nicht.", nameof(analysis))
    {
        Analysis = analysis;
    }

    public PasswordPolicyAnalysis Analysis { get; }
}

public sealed record Argon2Profile(int MemoryKiB, int Iterations, int Parallelism)
{
    public const int DefaultMemoryKiB = 1024 * 1024;
    public const int DefaultIterations = 4;
    public const int DefaultParallelism = 4;
    public const int MinMemoryKiB = DefaultMemoryKiB;
    public const int MaxMemoryKiB = DefaultMemoryKiB;
    public const int MinIterations = DefaultIterations;
    public const int MaxIterations = DefaultIterations;
    public const int MinParallelism = DefaultParallelism;
    public const int MaxParallelism = DefaultParallelism;

    public static Argon2Profile Default => new(DefaultMemoryKiB, DefaultIterations, DefaultParallelism);
}

public sealed class DerivedKey : IDisposable
{
    private readonly byte[] _bytes;
    private readonly byte[] _salt;

    internal DerivedKey(byte[] bytes, byte[] salt, Argon2Profile profile, IDisposable bytesLock, IDisposable saltLock)
    {
        _bytes = bytes;
        _salt = salt;
        Profile = profile;
        _bytesLock = bytesLock;
        _saltLock = saltLock;
    }

    public ReadOnlySpan<byte> Bytes => _bytes;
    public ReadOnlySpan<byte> Salt => _salt;
    public Argon2Profile Profile { get; }
    private readonly IDisposable _bytesLock;
    private readonly IDisposable _saltLock;

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_bytes);
        CryptographicOperations.ZeroMemory(_salt);
        _bytesLock.Dispose();
        _saltLock.Dispose();
    }
}
