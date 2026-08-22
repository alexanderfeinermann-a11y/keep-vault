using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// The four public salts a key derivation consumes. Normal suites use the
/// round-1 pair; Paranoia uses all four.
/// </summary>
internal sealed record KdfSalts(
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
                throw new CryptographicException($"Every KDF salt must be {SaltBytes} bytes.");
            }
        }

        for (int i = 0; i < present.Count; i++)
        {
            for (int j = i + 1; j < present.Count; j++)
            {
                if (CryptographicOperations.FixedTimeEquals(present[i], present[j]))
                {
                    throw new CryptographicException("Two KDF salts are identical.");
                }
            }
        }
    }
}
