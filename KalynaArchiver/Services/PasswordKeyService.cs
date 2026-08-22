using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

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
    /// A factor is 1024 bits, written as 256 uppercase hexadecimal
    /// characters on the key sheet and in the interface.
    /// </summary>
    public const int GeneratedPasswordLength = 256;
    public const int SaltSize = 64;
    public const int Argon2PasswordInputSize = 128;
    public const int KalynaDerivedKeySize = 256;
    public const int ThreefishDerivedKeySize = 320;
    public const int CascadeDerivedKeySize = 384;
    public const int KeySize = KalynaDerivedKeySize;

    private const double EntropySafetyFactor = 0.70;

    private static readonly string[] CommonPasswordTerms =
    [
        "PASSWORD", "PASSWORT", "LETMEIN", "WELCOME", "ADMIN", "CORRECTHORSEBATTERY",
        "QWERTY", "ASDF", "ZXCV", "KALYNA", "ZPAQ", "KEEPVAULT", "MASTERKEY",
    ];

    public static void ValidateArgon2Profile(Argon2Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile != Argon2Profile.Default)
        {
            throw new ArgumentOutOfRangeException(
                nameof(profile),
                $"Argon2id must use the fixed profile: {Argon2Profile.DefaultMemoryKiB} KiB, "
                + $"{Argon2Profile.DefaultIterations} iterations, parallelism {Argon2Profile.DefaultParallelism}.");
        }
    }

    public static string NormalizeGeneratedPassword(string generatedPassword)
    {
        ArgumentNullException.ThrowIfNull(generatedPassword);
        int count = 0;
        for (int i = 0; i < generatedPassword.Length; i++)
        {
            char c = generatedPassword[i];
            if (!char.IsWhiteSpace(c))
            {
                if (!IsAsciiHexDigit(c))
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(generatedPassword),
                        $"Das generierte Passwort muss aus {GeneratedPasswordLength} Hexadezimalzeichen bestehen.");
                }
                count++;
            }
        }

        if (count != GeneratedPasswordLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(generatedPassword),
                $"Das generierte Passwort muss aus {GeneratedPasswordLength} Hexadezimalzeichen bestehen.");
        }

        return string.Create(GeneratedPasswordLength, generatedPassword, static (span, src) =>
        {
            int destIdx = 0;
            for (int i = 0; i < src.Length; i++)
            {
                char c = src[i];
                if (!char.IsWhiteSpace(c))
                {
                    span[destIdx++] = char.ToUpperInvariant(c);
                }
            }
        });
    }

    public static void ValidateUserPasswordForCreation(string userPassword, string firstGeneratedPassword, string secondGeneratedPassword)
    {
        ArgumentNullException.ThrowIfNull(firstGeneratedPassword);
        ArgumentNullException.ThrowIfNull(secondGeneratedPassword);

        using (var firstBuf = ContainerKeyDerivation.ParseFactor(firstGeneratedPassword, nameof(firstGeneratedPassword)))
        using (var secondBuf = ContainerKeyDerivation.ParseFactor(secondGeneratedPassword, nameof(secondGeneratedPassword)))
        {
            if (CryptographicOperations.FixedTimeEquals(firstBuf.Bytes, secondBuf.Bytes))
            {
                throw new ArgumentException("Die beiden generierten Passwortfaktoren müssen verschieden sein.", nameof(secondGeneratedPassword));
            }
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

        LockedSensitiveBuffer? userBuf = null;
        try
        {
            try
            {
                userBuf = ContainerKeyDerivation.ParseFactor(userPassword, nameof(userPassword));
            }
            catch (ArgumentException)
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
                    using var genBuf = ContainerKeyDerivation.ParseFactor(generatedPassword, nameof(generatedPassword));
                    if (CryptographicOperations.FixedTimeEquals(userBuf.Bytes, genBuf.Bytes))
                    {
                        return true;
                    }
                }
                catch (ArgumentException)
                {
                    // A malformed generated factor cannot match
                }
            }

            return false;
        }
        finally
        {
            userBuf?.Dispose();
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
        penaltyBits += CountRepeatedNgrams(password) * 10;

        double estimate = Math.Max(0, (diversityBits * EntropySafetyFactor) - penaltyBits);
        return Math.Floor(estimate * 10.0) / 10.0;
    }

    private static int CountRepeatedNgrams(string password)
    {
        int count = 0;
        for (int n = 3; n <= 5 && n * 2 <= password.Length; n++)
        {
            for (int i = 0; i <= password.Length - (2 * n); i++)
            {
                string gram = password.Substring(i, n);
                if (password.IndexOf(gram, i + n, StringComparison.Ordinal) >= 0)
                {
                    count++;
                }
            }
        }

        return count;
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
        string[] patterns = ["QWERTY", "ASDF", "ZXCV", "1234", "9876", "QWERTZ", "AZERTY"];
        return patterns.Count(pattern => normalized.Contains(pattern, StringComparison.Ordinal));
    }

    private static int CountCommonTermHits(string password)
    {
        string normalized = password.ToUpperInvariant();
        return CommonPasswordTerms.Count(term => normalized.Contains(term, StringComparison.Ordinal));
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
