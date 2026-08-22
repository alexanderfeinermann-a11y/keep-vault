using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace KalynaArchiver.Signing;

/// <summary>
/// SHA-512, computed twice by two independent implementations that must agree.
/// </summary>
/// <remarks>
/// The container derives its second Argon2id round from the same entropy pools
/// as the first, separated only by using SHA-512 where the first round uses
/// SHA3-512. That makes this hash load-bearing for key material: a SHA-512 that
/// is subtly wrong would not fail, it would silently produce a different key,
/// and the archive would be unreadable by any correct build.
///
/// SHA3-512 has no second implementation available here — .NET does not carry
/// SHA3 on every supported platform, so <see cref="Sha3_512Compat"/> has only
/// BouncyCastle. SHA-512 is the opposite case: the platform has one and
/// BouncyCastle has another. Both are computed on every call and compared, so
/// the two have to agree on every block of every derivation rather than only in
/// a test that ran once on some other machine.
///
/// The class also refuses to be used at all unless it reproduces the published
/// FIPS 180-4 digests, which is what turns "two implementations agree" into
/// "two implementations agree and both are right".
/// </remarks>
public static class Sha512Compat
{
    public const int HashSizeInBytes = 64;

    /// <summary>SHA-512 of the empty string, FIPS 180-4.</summary>
    private const string EmptyDigest =
        "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"
        + "47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";

    /// <summary>SHA-512 of "abc", FIPS 180-4.</summary>
    private const string AbcDigest =
        "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
        + "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F";

    /// <summary>
    /// SHA-512 of the 112-byte two-block message from FIPS 180-4, which is what
    /// catches a padding or length-encoding fault that a short message hides.
    /// </summary>
    private const string TwoBlockMessage =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        + "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    private const string TwoBlockDigest =
        "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"
        + "501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909";

    static Sha512Compat()
    {
        VerifyAgainstPublishedVectors();
    }

    public static byte[] HashData(ReadOnlySpan<byte> source)
    {
        byte[] result = new byte[HashSizeInBytes];
        _ = HashData(source, result);
        return result;
    }

    public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (destination.Length < HashSizeInBytes)
        {
            throw new ArgumentException($"SHA-512 needs a {HashSizeInBytes}-byte destination.", nameof(destination));
        }

        Span<byte> platform = stackalloc byte[HashSizeInBytes];
        int platformWritten = SHA512.HashData(source, platform);
        if (platformWritten != HashSizeInBytes)
        {
            throw new CryptographicException("The platform SHA-512 provider returned an invalid digest length.");
        }

        Span<byte> reference = stackalloc byte[HashSizeInBytes];
        var digest = new Sha512Digest();
        digest.BlockUpdate(source);
        int referenceWritten = digest.DoFinal(reference);
        if (referenceWritten != HashSizeInBytes)
        {
            throw new CryptographicException("The reference SHA-512 provider returned an invalid digest length.");
        }

        // Fixed-time even though both sides are public values. The comparison
        // guards key derivation, and a length- or content-dependent compare here
        // would be the one place in this file worth measuring.
        if (!CryptographicOperations.FixedTimeEquals(platform, reference))
        {
            CryptographicOperations.ZeroMemory(platform);
            CryptographicOperations.ZeroMemory(reference);
            throw new CryptographicException(
                "The platform and reference SHA-512 implementations disagree; key derivation was stopped.");
        }

        platform.CopyTo(destination);
        CryptographicOperations.ZeroMemory(platform);
        CryptographicOperations.ZeroMemory(reference);
        return HashSizeInBytes;
    }

    /// <summary>
    /// Checks both implementations against the published digests before either
    /// is trusted with key material.
    /// </summary>
    /// <remarks>
    /// Run from the static constructor, so a build whose SHA-512 is wrong fails
    /// the first time the type is touched rather than at the point where an
    /// archive is being written.
    /// </remarks>
    private static void VerifyAgainstPublishedVectors()
    {
        Check([], EmptyDigest);
        Check("abc"u8.ToArray(), AbcDigest);
        Check(System.Text.Encoding.ASCII.GetBytes(TwoBlockMessage), TwoBlockDigest);

        static void Check(byte[] message, string expectedHex)
        {
            byte[] expected = Convert.FromHexString(expectedHex);

            byte[] platform = SHA512.HashData(message);
            if (!CryptographicOperations.FixedTimeEquals(platform, expected))
            {
                throw new CryptographicException(
                    "The platform SHA-512 implementation does not match the published FIPS 180-4 digests.");
            }

            byte[] reference = new byte[HashSizeInBytes];
            var digest = new Sha512Digest();
            digest.BlockUpdate(message);
            _ = digest.DoFinal(reference);
            if (!CryptographicOperations.FixedTimeEquals(reference, expected))
            {
                throw new CryptographicException(
                    "The reference SHA-512 implementation does not match the published FIPS 180-4 digests.");
            }
        }
    }
}
