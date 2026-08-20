using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// The whole v10 key derivation, from the four things the user holds to the
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
/// </remarks>
internal static class V10KeyDerivation
{
    public const int MinPinLength = 6;
    public const int MaxPinLength = 16;
    public const int FactorHexLength = 256;
    public const int FactorBytes = 128;

    /// <summary>
    /// The final master for a suite, together with the memory costs each round
    /// selected. The costs are returned for the peak-memory and progress code
    /// only; they are never written to the container.
    /// </summary>
    public sealed record MasterResult(byte[] Master, uint Round1MemoryKiB, uint? Round2MemoryKiB);

    public static void ValidatePin(string? pin)
    {
        if (string.IsNullOrEmpty(pin))
        {
            throw new ArgumentException("The PIN is required.", nameof(pin));
        }

        if (pin.Length is < MinPinLength or > MaxPinLength)
        {
            throw new ArgumentException(
                $"The PIN must be {MinPinLength} to {MaxPinLength} digits.", nameof(pin));
        }

        foreach (char c in pin)
        {
            if (c is < '0' or > '9')
            {
                throw new ArgumentException("The PIN must consist of digits only.", nameof(pin));
            }
        }
    }

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
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(factorHex);
        if (normalized.Length != FactorHexLength)
        {
            throw new ArgumentException(
                $"{name} must be exactly {FactorHexLength} hexadecimal characters.", nameof(factorHex));
        }

        var buffer = LockedSensitiveBuffer.Create(FactorBytes);
        try
        {
            // Decoded straight into the locked buffer. Convert.FromHexString
            // would allocate an unlocked, uncleared copy of the factor first.
            for (int i = 0; i < FactorBytes; i++)
            {
                buffer.Bytes[i] = (byte)((DecodeNibble(normalized[2 * i], name) << 4)
                    | DecodeNibble(normalized[(2 * i) + 1], name));
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
        V10Salts salts,
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
        byte[]? sha3Credential = null;
        byte[]? skeinCredential = null;
        byte[]? round1Master = null;
        byte[]? round2Master = null;
        try
        {
            sha3Credential = V10MasterKdf.DeriveSha3CredentialHash(
                algorithm, userPassword, pin, factorA.Bytes, factorB.Bytes);
            skeinCredential = V10MasterKdf.DeriveSkeinCredentialHash(
                algorithm, userPassword, pin, factorA.Bytes, factorB.Bytes);

            cancellationToken.ThrowIfCancellationRequested();
            (_, uint memory1) = V10MasterKdf.DerivePmi(
                algorithm, 1, sha3Credential, skeinCredential,
                ReadOnlySpan<byte>.Empty, salts.Sha3Round1, salts.SkeinRound1);
            progress?.Report(paranoia ? "Key derivation, round 1 of 2" : "Key derivation");
            round1Master = V10MasterKdf.DeriveRoundMaster(
                algorithm, 1, sha3Credential, skeinCredential,
                salts.Sha3Round1, salts.SkeinRound1, secret: null, memory1);

            if (!paranoia)
            {
                byte[] onlyMaster = round1Master;
                round1Master = null;
                return new MasterResult(onlyMaster, memory1, null);
            }

            cancellationToken.ThrowIfCancellationRequested();
            (_, uint memory2) = V10MasterKdf.DerivePmi(
                algorithm, 2, sha3Credential, skeinCredential,
                round1Master, salts.Sha3Round2!, salts.SkeinRound2!);
            progress?.Report("Key derivation, round 2 of 2");
            // The first master is the Argon2id secret here, not the password:
            // it makes round two unreachable without round one, and it keeps
            // the credentials themselves in the same position in both rounds.
            round2Master = V10MasterKdf.DeriveRoundMaster(
                algorithm, 2, sha3Credential, skeinCredential,
                salts.Sha3Round2!, salts.SkeinRound2!, round1Master, memory2);
            byte[] master = round2Master;
            round2Master = null;
            return new MasterResult(master, memory1, memory2);
        }
        finally
        {
            if (sha3Credential is not null) CryptographicOperations.ZeroMemory(sha3Credential);
            if (skeinCredential is not null) CryptographicOperations.ZeroMemory(skeinCredential);
            if (round1Master is not null) CryptographicOperations.ZeroMemory(round1Master);
            if (round2Master is not null) CryptographicOperations.ZeroMemory(round2Master);
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
        V10Salts salts,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        MasterResult result = DeriveMaster(
            parameters, userPassword, pin, factorAHex, factorBHex, salts, progress, cancellationToken);
        try
        {
            return SuiteKeySchedule.DeriveSuiteKeys(result.Master, parameters);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(result.Master);
        }
    }
}
