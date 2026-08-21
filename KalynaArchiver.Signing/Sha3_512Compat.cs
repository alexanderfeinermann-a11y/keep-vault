using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace KalynaArchiver.Signing;

public static class Sha3_512Compat
{
    public const int HashSizeInBytes = 64;

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
            throw new ArgumentException($"SHA3-512 needs a {HashSizeInBytes}-byte destination.", nameof(destination));
        }

        var digest = new Sha3Digest(512);
        digest.BlockUpdate(source);
        int written = digest.DoFinal(destination);
        if (written != HashSizeInBytes)
        {
            throw new CryptographicException("The SHA3-512 provider returned an invalid digest length.");
        }

        return written;
    }
}

public sealed class Sha3_512Incremental : IDisposable
{
    private Sha3Digest? _digest = new(512);

    public void AppendData(ReadOnlySpan<byte> data)
    {
        (_digest ?? throw new ObjectDisposedException(nameof(Sha3_512Incremental))).BlockUpdate(data);
    }

    public byte[] GetHashAndReset()
    {
        Sha3Digest digest = _digest ?? throw new ObjectDisposedException(nameof(Sha3_512Incremental));
        byte[] result = new byte[Sha3_512Compat.HashSizeInBytes];
        int written = digest.DoFinal(result);
        if (written != result.Length)
        {
            CryptographicOperations.ZeroMemory(result);
            throw new CryptographicException("The SHA3-512 provider returned an invalid digest length.");
        }

        digest.Reset();
        return result;
    }

    public int GetHashAndReset(Span<byte> destination)
    {
        if (destination.Length < Sha3_512Compat.HashSizeInBytes)
        {
            throw new ArgumentException("SHA3-512 destination is too short.", nameof(destination));
        }

        Sha3Digest digest = _digest ?? throw new ObjectDisposedException(nameof(Sha3_512Incremental));
        int written = digest.DoFinal(destination);
        digest.Reset();
        return written;
    }

    public void Dispose()
    {
        _digest?.Reset();
        _digest = null;
    }
}

public sealed class HmacSha3_512 : IDisposable
{
    private HMac? _mac;

    public HmacSha3_512(ReadOnlySpan<byte> key)
    {
        byte[] tempKey = key.ToArray();
        try
        {
            _mac = new HMac(new Sha3Digest(512));
            _mac.Init(new KeyParameter(tempKey));
            if (_mac.GetMacSize() != Sha3_512Compat.HashSizeInBytes)
            {
                throw new CryptographicException("The HMAC-SHA3-512 provider returned an invalid tag length.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tempKey);
        }
    }

    public void AppendData(ReadOnlySpan<byte> data)
    {
        (_mac ?? throw new ObjectDisposedException(nameof(HmacSha3_512))).BlockUpdate(data);
    }

    public int GetHashAndReset(Span<byte> destination)
    {
        if (destination.Length < Sha3_512Compat.HashSizeInBytes)
        {
            throw new ArgumentException("Destination span is too short for HMAC-SHA3-512 tag.", nameof(destination));
        }

        HMac mac = _mac ?? throw new ObjectDisposedException(nameof(HmacSha3_512));
        int written = mac.DoFinal(destination);
        if (written != Sha3_512Compat.HashSizeInBytes)
        {
            throw new CryptographicException("The HMAC-SHA3-512 provider returned an invalid tag length.");
        }

        mac.Reset();
        return written;
    }

    public byte[] GetHashAndReset()
    {
        byte[] result = new byte[Sha3_512Compat.HashSizeInBytes];
        GetHashAndReset(result);
        return result;
    }

    public void Dispose()
    {
        _mac?.Reset();
        _mac = null;
    }
}
