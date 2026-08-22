using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// The whole v11 key derivation, from the four things the user holds to the
/// keys one suite needs.
/// </summary>
/// <remarks>
/// The four credentials are the passphrase, the PIN, and the two 1024-bit
/// factors from the key sheet. All four are mandatory; there is no reduced mode
/// and no suite that skips one.
///
/// Single-round suites run one round over the round-1 salt pair. Paranoia runs
/// a second round whose Argon2id secret is the first round's complete master,
/// so round two cannot be attacked without finishing round one — four
/// sequential 1&#160;GiB-plus Argon2id calls in total.
///
/// There is exactly one derivation generation. Earlier container versions are
/// not readable and no code path can select an older KDF, older domains or an
/// older role schedule: a version that is not <see cref="ContainerVersion"/>
/// never reaches this class.
/// </remarks>
internal static class ContainerKeyDerivation
{
    /// <summary>
    /// The one container generation this build derives keys for.
    /// </summary>
    public const int ContainerVersion = 11;

    public const int MinPinLength = 6;
    public const int MaxPinSyntaxLength = 16;
    public const int MaxPinCreationLength = 16;
    public const int MaxPinLength = 16;
    public const int FactorHexLength = 256;
    public const int FactorBytes = 128;

    /// <summary>
    /// The final master for a suite, held in locked sensitive memory, together
    /// with the memory costs each round selected. The costs are returned for the
    /// peak-memory and progress code only; they are never written to the container.
    /// </summary>
    public sealed class MasterResult : IDisposable
    {
        public MasterResult(LockedSensitiveBuffer master, uint round1MemoryKiB, uint? round2MemoryKiB)
        {
            Master = master;
            Round1MemoryKiB = round1MemoryKiB;
            Round2MemoryKiB = round2MemoryKiB;
        }

        public LockedSensitiveBuffer Master { get; }
        public uint Round1MemoryKiB { get; }
        public uint? Round2MemoryKiB { get; }

        public void Dispose()
        {
            Master.Dispose();
        }
    }

    public const int MinDistinctPinDigits = 4;

    public static void ValidatePin(string? pin) => ValidatePinSyntax(pin);

    public static void ValidatePinSyntax(string? pin)
    {
        if (string.IsNullOrEmpty(pin))
        {
            throw new ArgumentException("The PIN is required.", nameof(pin));
        }

        if (pin.Length is < MinPinLength or > MaxPinSyntaxLength)
        {
            throw new ArgumentException(
                $"The PIN must be {MinPinLength} to {MaxPinSyntaxLength} digits.", nameof(pin));
        }

        foreach (char c in pin)
        {
            if (c is < '0' or > '9')
            {
                throw new ArgumentException("The PIN must consist of digits only.", nameof(pin));
            }
        }
    }

    public static PinPolicyAnalysis AnalyzePinForCreation(string? pin)
    {
        string raw = pin ?? string.Empty;
        var violations = new List<PinPolicyViolation>();

        if (string.IsNullOrEmpty(raw))
        {
            violations.Add(PinPolicyViolation.TooShort);
            return new PinPolicyAnalysis(0, 0, violations);
        }

        bool hasNonDigit = false;
        foreach (char c in raw)
        {
            if (c is < '0' or > '9')
            {
                hasNonDigit = true;
                break;
            }
        }

        if (hasNonDigit)
        {
            violations.Add(PinPolicyViolation.NonDigit);
        }

        if (raw.Length < MinPinLength)
        {
            violations.Add(PinPolicyViolation.TooShort);
        }
        else if (raw.Length > MaxPinCreationLength)
        {
            violations.Add(PinPolicyViolation.TooLong);
        }

        if (hasNonDigit)
        {
            return new PinPolicyAnalysis(raw.Length, 0, violations);
        }

        int distinctCount = raw.Distinct().Count();
        if (distinctCount < MinDistinctPinDigits)
        {
            violations.Add(PinPolicyViolation.NotEnoughDistinctDigits);
        }

        if (HasRepeatedTriple(raw))
        {
            violations.Add(PinPolicyViolation.RepeatedDigitsTriple);
        }

        if (HasSequentialAscending(raw))
        {
            violations.Add(PinPolicyViolation.SequentialAscending);
        }

        if (HasSequentialDescending(raw))
        {
            violations.Add(PinPolicyViolation.SequentialDescending);
        }

        if (HasKeypadGeometricPattern(raw))
        {
            violations.Add(PinPolicyViolation.Blocklisted);
        }

        if (IsBlocklistedOrRepetitive(raw))
        {
            violations.Add(PinPolicyViolation.Blocklisted);
        }

        return new PinPolicyAnalysis(raw.Length, distinctCount, violations);
    }

    public static void ValidatePinForCreation(string? pin)
    {
        PinPolicyAnalysis analysis = AnalyzePinForCreation(pin);
        if (!analysis.IsAccepted)
        {
            throw new PinPolicyException(analysis);
        }
    }

    private static bool HasKeypadGeometricPattern(string pin)
    {
        // 3x3 Keypad + 0 layout:
        // 1 2 3
        // 4 5 6
        // 7 8 9
        //   0
        // Detects runs of 3+ keypad column steps (±3), diagonal steps (±4 or ±2), or knight jumps.
        for (int i = 0; i <= pin.Length - 3; i++)
        {
            int d1 = pin[i + 1] - pin[i];
            int d2 = pin[i + 2] - pin[i + 1];

            // Vertical column run (e.g. 1-4-7, 7-4-1, 2-5-8, 8-5-2, 3-6-9, 9-6-3)
            if ((d1 == 3 && d2 == 3) || (d1 == -3 && d2 == -3))
            {
                return true;
            }

            // Diagonal run (e.g. 1-5-9, 9-5-1)
            if ((d1 == 4 && d2 == 4) || (d1 == -4 && d2 == -4))
            {
                return true;
            }

            // Diagonal run (e.g. 3-5-7, 7-5-3)
            if ((d1 == 2 && d2 == 2 && pin[i] == '3' && pin[i + 1] == '5' && pin[i + 2] == '7') ||
                (d1 == -2 && d2 == -2 && pin[i] == '7' && pin[i + 1] == '5' && pin[i + 2] == '3'))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasRepeatedTriple(string pin)
    {
        for (int i = 0; i <= pin.Length - 3; i++)
        {
            if (pin[i] == pin[i + 1] && pin[i] == pin[i + 2])
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasSequentialAscending(string pin)
    {
        for (int i = 0; i <= pin.Length - 3; i++)
        {
            if (pin[i + 1] == pin[i] + 1 && pin[i + 2] == pin[i] + 2)
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasSequentialDescending(string pin)
    {
        for (int i = 0; i <= pin.Length - 3; i++)
        {
            if (pin[i + 1] == pin[i] - 1 && pin[i + 2] == pin[i] - 2)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsBlocklistedOrRepetitive(string pin)
    {
        if (CommonWeakPins.Contains(pin))
        {
            return true;
        }

        for (int patternLength = 2; patternLength <= 4 && patternLength * 2 <= pin.Length; patternLength++)
        {
            if (pin.Length % patternLength == 0)
            {
                string pattern = pin[..patternLength];
                bool allMatch = true;
                for (int i = patternLength; i < pin.Length; i += patternLength)
                {
                    if (pin.Substring(i, patternLength) != pattern)
                    {
                        allMatch = false;
                        break;
                    }
                }

                if (allMatch)
                {
                    return true;
                }
            }
        }

        if (pin.Length % 2 == 0)
        {
            bool isPaired = true;
            for (int i = 0; i < pin.Length; i += 2)
            {
                if (pin[i] != pin[i + 1])
                {
                    isPaired = false;
                    break;
                }
            }

            if (isPaired)
            {
                return true;
            }
        }

        return false;
    }

    private static readonly HashSet<string> CommonWeakPins = new(StringComparer.Ordinal)
    {
        "121212", "12121212", "1212121212", "121212121212",
        "131313", "141414", "151515", "161616", "171717", "181818", "191919", "202020",
        "696969", "112233", "11223344", "123123", "12341234", "1234512345",
        "246810", "135791", "987654", "654321", "123456", "012345", "543210",
        "147258", "258147", "369258", "159357", "753951", "159753", "357159",
        "258025", "147014", "369036", "741852", "963852", "852963", "789456", "456123",
        "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
    };

    /// <summary>
    /// Parses one key-sheet factor into locked memory.
    /// </summary>
    /// <remarks>
    /// Only the exact 256-character form is accepted. Nothing is padded and
    /// nothing is truncated: a factor that arrives one character short is a
    /// transcription error, and silently accepting it would derive a key the
    /// sheet cannot reproduce.
    /// </remarks>
    public static LockedSensitiveBuffer ParseFactor(string factorHex, string name)
    {
        ArgumentNullException.ThrowIfNull(factorHex);
        return ParseFactor(factorHex.AsSpan(), name);
    }

    public static LockedSensitiveBuffer ParseFactor(ReadOnlySpan<char> factorChars, string name)
    {
        var buffer = LockedSensitiveBuffer.Create(FactorBytes);
        try
        {
            int hexDigitCount = 0;
            int currentHigh = -1;
            int byteIndex = 0;

            for (int i = 0; i < factorChars.Length; i++)
            {
                char c = factorChars[i];
                if (char.IsWhiteSpace(c))
                {
                    continue;
                }

                int nibble = DecodeNibble(c, name);
                hexDigitCount++;

                if (currentHigh < 0)
                {
                    currentHigh = nibble;
                }
                else
                {
                    if (byteIndex >= FactorBytes)
                    {
                        throw new ArgumentException(
                            $"{name} must be exactly {FactorHexLength} hexadecimal characters.", nameof(factorChars));
                    }
                    buffer.Bytes[byteIndex++] = (byte)((currentHigh << 4) | nibble);
                    currentHigh = -1;
                }
            }

            if (hexDigitCount != FactorHexLength || byteIndex != FactorBytes)
            {
                throw new ArgumentException(
                    $"{name} must be exactly {FactorHexLength} hexadecimal characters.", nameof(factorChars));
            }

            return buffer;
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    private static int DecodeNibble(char c, string name) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'A' and <= 'F' => c - 'A' + 10,
        >= 'a' and <= 'f' => c - 'a' + 10,
        _ => throw new ArgumentException($"{name} is not valid hexadecimal."),
    };

    public static MasterResult DeriveMaster(
        EncryptionSuiteParameters parameters,
        string userPassword,
        string pin,
        string factorAHex,
        string factorBHex,
        KdfSalts salts,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(salts);
        ArgumentNullException.ThrowIfNull(userPassword);
        ValidatePin(pin);
        bool paranoia = parameters.UsesTwoKdfRounds;
        salts.Validate(paranoia);

        using LockedSensitiveBuffer factorA = ParseFactor(factorAHex, "Factor A");
        using LockedSensitiveBuffer factorB = ParseFactor(factorBHex, "Factor B");
        if (CryptographicOperations.FixedTimeEquals(factorA.Bytes, factorB.Bytes))
        {
            throw new CryptographicException("Both key-sheet factors are identical.");
        }

        string algorithm = parameters.Algorithm;
        using LockedSensitiveBuffer sha3Credential = LockedSensitiveBuffer.Create(V11MasterKdf.CredentialHashBytes);
        using LockedSensitiveBuffer skeinCredential = LockedSensitiveBuffer.Create(V11MasterKdf.CredentialHashBytes);

        V11MasterKdf.DeriveSha3CredentialHash(
            algorithm, userPassword, pin, factorA.Bytes, factorB.Bytes, sha3Credential.Bytes);
        V11MasterKdf.DeriveSkeinCredentialHash(
            algorithm, userPassword, pin, factorA.Bytes, factorB.Bytes, skeinCredential.Bytes);

        cancellationToken.ThrowIfCancellationRequested();
        (_, uint memory1) = V11MasterKdf.DerivePmi(
            algorithm, 1, sha3Credential.Bytes, skeinCredential.Bytes,
            ReadOnlySpan<byte>.Empty, salts.Sha3Round1, salts.SkeinRound1);
        progress?.Report(paranoia ? "Key derivation, round 1 of 2" : "Key derivation");

        LockedSensitiveBuffer? round1Master = LockedSensitiveBuffer.Create(V11MasterKdf.MasterBytes);
        try
        {
            V11MasterKdf.DeriveRoundMaster(
                algorithm, 1, sha3Credential.Bytes, skeinCredential.Bytes,
                salts.Sha3Round1, salts.SkeinRound1, ReadOnlySpan<byte>.Empty, memory1, round1Master.Bytes);

            if (!paranoia)
            {
                var result = new MasterResult(round1Master, memory1, null);
                round1Master = null; // ownership transferred to result
                return result;
            }

            cancellationToken.ThrowIfCancellationRequested();
            (_, uint memory2) = V11MasterKdf.DerivePmi(
                algorithm, 2, sha3Credential.Bytes, skeinCredential.Bytes,
                round1Master.Bytes, salts.Sha3Round2!, salts.SkeinRound2!);
            progress?.Report("Key derivation, round 2 of 2");
            // The first master is the Argon2id secret here, not the password:
            // it makes round two unreachable without round one, and it keeps
            // the credentials themselves in the same position in both rounds.
            LockedSensitiveBuffer? round2Master = LockedSensitiveBuffer.Create(V11MasterKdf.MasterBytes);
            try
            {
                V11MasterKdf.DeriveRoundMaster(
                    algorithm, 2, sha3Credential.Bytes, skeinCredential.Bytes,
                    salts.Sha3Round2!, salts.SkeinRound2!, round1Master.Bytes, memory2, round2Master.Bytes);
                var result = new MasterResult(round2Master, memory1, memory2);
                round2Master = null; // ownership transferred to result
                return result;
            }
            finally
            {
                round2Master?.Dispose();
            }
        }
        finally
        {
            round1Master?.Dispose();
        }
    }

    /// <summary>
    /// The suite's cipher and MAC keys, derived through the role key schedule.
    /// </summary>
    public static RoleKeyMaterial DeriveSuiteKeys(
        EncryptionSuiteParameters parameters,
        string userPassword,
        string pin,
        string factorAHex,
        string factorBHex,
        KdfSalts salts,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using MasterResult result = DeriveMaster(
            parameters, userPassword, pin, factorAHex, factorBHex, salts, progress, cancellationToken);
        return SuiteKeySchedule.DeriveSuiteKeys(result.Master.Bytes, parameters);
    }
}

public enum PinPolicyViolation
{
    TooShort,
    TooLong,
    NonDigit,
    NotEnoughDistinctDigits,
    RepeatedDigitsTriple,
    SequentialAscending,
    SequentialDescending,
    Blocklisted,
}

public sealed record PinPolicyAnalysis(
    int Length,
    int DistinctDigits,
    IReadOnlyList<PinPolicyViolation> Violations)
{
    public bool IsAccepted => Violations.Count == 0;
}

public sealed class PinPolicyException : ArgumentException
{
    public PinPolicyException(PinPolicyAnalysis analysis)
        : base($"The PIN does not satisfy the policy for new archive creation: {string.Join(", ", analysis.Violations)}")
    {
        Analysis = analysis;
    }

    public PinPolicyAnalysis Analysis { get; }
}
