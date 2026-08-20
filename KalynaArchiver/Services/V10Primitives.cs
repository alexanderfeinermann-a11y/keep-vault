using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace KalynaArchiver.Services;

/// <summary>
/// The length-prefixed framing every v10 domain construction is built from:
/// <c>LP(X) = LE32(|X|) || X</c>, concatenated for several fields.
/// </summary>
/// <remarks>
/// Framing rather than plain concatenation is the whole point: without it,
/// (password "ab", pin "1") and (password "a", pin "b1") would hash the same
/// bytes and therefore produce the same key.
/// </remarks>
internal static class LengthPrefix
{
    public static byte[] Encode(params ReadOnlyMemory<byte>[] fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        int total = 0;
        foreach (ReadOnlyMemory<byte> field in fields)
        {
            total = checked(total + sizeof(uint) + field.Length);
        }

        byte[] result = new byte[total];
        int offset = 0;
        foreach (ReadOnlyMemory<byte> field in fields)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
                result.AsSpan(offset),
                checked((uint)field.Length));
            offset += sizeof(uint);
            field.Span.CopyTo(result.AsSpan(offset));
            offset += field.Length;
        }

        return result;
    }

    public static byte[] Encode(params string[] fields) =>
        Encode(Array.ConvertAll(fields, field => (ReadOnlyMemory<byte>)Encoding.UTF8.GetBytes(field)));

    public static ReadOnlyMemory<byte> Utf8(string value) => Encoding.UTF8.GetBytes(value);

    public static byte[] EncodeInt32(int value)
    {
        byte[] result = new byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(result, value);
        return result;
    }
}

/// <summary>
/// Skein-MAC with a 1024-bit state and a 1024-bit output, keyed and
/// personalised through Skein's own parameter block.
/// </summary>
/// <remarks>
/// This is deliberately not <c>Skein1024Digest.HashData(key || message)</c>.
/// Skein 1.3 defines a real key parameter for MAC and KDF use, and Bouncy
/// Castle implements it; inventing a keyed construction on top of an unkeyed
/// digest would be a new primitive nobody has analysed.
///
/// Both the state and the output are fixed at 1024 bits. A shorter output would
/// silently cap the master and role material this is used for.
/// </remarks>
internal static class KeyedSkein1024
{
    public const int OutputBytes = 128;

    public static byte[] Compute(
        ReadOnlySpan<byte> key,
        string personalisation,
        ReadOnlySpan<byte> message)
    {
        byte[] output = new byte[OutputBytes];
        try
        {
            Compute(key, personalisation, message, output);
            byte[] result = output;
            output = null!;
            return result;
        }
        finally
        {
            if (output is not null) CryptographicOperations.ZeroMemory(output);
        }
    }

    public static void Compute(
        ReadOnlySpan<byte> key,
        string personalisation,
        ReadOnlySpan<byte> message,
        Span<byte> destination)
    {
        ArgumentException.ThrowIfNullOrEmpty(personalisation);
        if (key.IsEmpty)
        {
            throw new ArgumentException("A keyed Skein-MAC requires a key.", nameof(key));
        }

        if (destination.Length < OutputBytes)
        {
            throw new ArgumentException($"Destination must be at least {OutputBytes} bytes.", nameof(destination));
        }

        var mac = new SkeinMac(SkeinEngine.SKEIN_1024, OutputBytes * 8);
        byte[] parameterKey = key.ToArray();
        byte[] personalisationBytes = Encoding.UTF8.GetBytes(personalisation);
        try
        {
            SkeinParameters parameters = new SkeinParameters.Builder()
                .SetKey(parameterKey)
                .SetPersonalisation(personalisationBytes)
                .Build();
            mac.Init(parameters);
            byte[] messageBytes = message.ToArray();
            try
            {
                mac.BlockUpdate(messageBytes, 0, messageBytes.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(messageBytes);
            }

            byte[] output = new byte[OutputBytes];
            try
            {
                int written = mac.DoFinal(output, 0);
                if (written != OutputBytes)
                {
                    throw new CryptographicException(
                        $"Skein-MAC-1024-1024 returned {written} bytes instead of {OutputBytes}.");
                }

                output.CopyTo(destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(output);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(parameterKey);
            CryptographicOperations.ZeroMemory(personalisationBytes);
            mac.Reset();
        }
    }
}

/// <summary>
/// HKDF-Expand with HMAC-SHA3-512, without the extract step.
/// </summary>
/// <remarks>
/// RFC 5869 permits skipping extract when the input keying material is already
/// a uniformly pseudorandom key, which an Argon2id output is. Bouncy Castle
/// exposes exactly that through <c>HkdfParameters.SkipExtractParameters</c>, so
/// no hand-rolled multi-HMAC chain is needed — and a hand-rolled one is the
/// kind of construction that looks right and expands one block short.
/// </remarks>
internal static class Sha3HkdfExpand
{
    public static byte[] Expand(ReadOnlySpan<byte> pseudoRandomKey, ReadOnlySpan<byte> info, int outputBytes)
    {
        if (outputBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputBytes));
        }

        byte[] prk = pseudoRandomKey.ToArray();
        byte[] infoBytes = info.ToArray();
        try
        {
            var generator = new HkdfBytesGenerator(new Sha3Digest(512));
            generator.Init(HkdfParameters.SkipExtractParameters(prk, infoBytes));
            byte[] output = new byte[outputBytes];
            generator.GenerateBytes(output, 0, outputBytes);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(infoBytes);
        }
    }
}

/// <summary>
/// Byte-interleaving of the two 512-bit Argon2id branch outputs into the
/// 1024-bit master: <c>M[2i] = L[i]</c>, <c>M[2i+1] = R[i]</c>.
/// </summary>
/// <remarks>
/// This is a lossless permutation, not a hash and not a diffusion step. It
/// exists so that no single 512-bit Argon2id output becomes the width of the
/// master; the actual mixing happens afterwards in the domain-separated role
/// key schedule. Documentation and comments have to keep saying so, because a
/// reader who mistakes it for mixing will draw the wrong conclusion about what
/// the construction guarantees.
/// </remarks>
internal static class MasterInterleave
{
    public const int BranchBytes = 64;
    public const int MasterBytes = 128;

    public static byte[] Interleave(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        byte[] master = new byte[MasterBytes];
        Interleave(left, right, master);
        return master;
    }

    public static void Interleave(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
    {
        if (left.Length != BranchBytes || right.Length != BranchBytes)
        {
            throw new ArgumentException(
                $"Both Argon2id branch outputs must be {BranchBytes} bytes.");
        }

        if (destination.Length < MasterBytes)
        {
            throw new ArgumentException($"Destination must be at least {MasterBytes} bytes.", nameof(destination));
        }

        for (int i = 0; i < BranchBytes; i++)
        {
            destination[(2 * i) + 0] = left[i];
            destination[(2 * i) + 1] = right[i];
        }
    }
}
