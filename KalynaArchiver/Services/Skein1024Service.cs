using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace KalynaArchiver.Services;

internal sealed class Skein1024Digest : IDisposable
{
    public const int DigestSize = 128;
    public const int MacKeySize = 128;
    private readonly SkeinDigest _digest = new(1024, 1024);
    private bool _finalized;

    public void AppendData(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_finalized, this);
        _digest.BlockUpdate(data);
    }

    public byte[] GetHashAndReset()
    {
        byte[] result = new byte[DigestSize];
        GetHashAndReset(result);
        return result;
    }

    public void GetHashAndReset(byte[] destination)
    {
        ObjectDisposedException.ThrowIf(_finalized, this);
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Length != DigestSize)
        {
            throw new ArgumentOutOfRangeException(nameof(destination), $"Skein-1024 requires exactly {DigestSize} output bytes.");
        }

        int written = _digest.DoFinal(destination);
        _digest.Reset();
        if (written != DigestSize)
        {
            throw new CryptographicException("Skein-1024 returned an invalid digest length.");
        }
    }

    public void Dispose()
    {
        if (_finalized)
        {
            return;
        }

        _digest.Reset();
        _finalized = true;
    }

    public static byte[] HashData(ReadOnlySpan<byte> data)
    {
        using var digest = new Skein1024Digest();
        digest.AppendData(data);
        return digest.GetHashAndReset();
    }

    public static byte[] HashData(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var digest = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                digest.AppendData(buffer.AsSpan(0, read));
            }

            return digest.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static async Task<byte[]> HashDataAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var digest = new Skein1024Digest();
        byte[] buffer = new byte[1024 * 1024];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                digest.AppendData(buffer.AsSpan(0, read));
            }

            return digest.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
