using System.Runtime.InteropServices;

namespace KeepVaultMac.Tests;

/// <summary>
/// Binds the official FIPS 202 reference implementation for differential
/// testing.
/// </summary>
/// <remarks>
/// The app computes SHA3-512 and HMAC-SHA3-512 with Bouncy Castle, because
/// Apple's backend does not expose SHA3 through .NET on macOS. Every container
/// tag, every integrity manifest and the key-derivation pre-hash rest on that
/// one library being correct, so it is checked against the reference rather
/// than trusted.
/// </remarks>
internal sealed unsafe class Sha3Reference : IDisposable
{
    private readonly nint _module;
    private readonly delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, int> _hash;
    private readonly delegate* unmanaged[Cdecl]<nuint> _rate;
    private readonly delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, int> _hmac;

    internal Sha3Reference(string path)
    {
        string fullPath = Path.GetFullPath(path);
        _module = NativeLibrary.Load(fullPath);
        try
        {
            _hash = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, int>)
                NativeLibrary.GetExport(_module, "sha3_512_reference_hash");
            _rate = (delegate* unmanaged[Cdecl]<nuint>)
                NativeLibrary.GetExport(_module, "sha3_512_reference_rate");
            _hmac = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, int>)
                NativeLibrary.GetExport(_module, "hmac_sha3_512_reference");
        }
        catch
        {
            NativeLibrary.Free(_module);
            throw;
        }
    }

    /// <summary>The rate SHA3-512 absorbs per permutation, which HMAC uses as its block size.</summary>
    internal int BlockSize => checked((int)_rate());

    internal byte[] Hash(ReadOnlySpan<byte> message)
    {
        byte[] digest = new byte[64];
        fixed (byte* messagePointer = message)
        fixed (byte* digestPointer = digest)
        {
            int status = _hash(messagePointer, (nuint)message.Length, digestPointer, (nuint)digest.Length);
            if (status != 0)
            {
                throw new InvalidOperationException($"The SHA3-512 reference returned {status}.");
            }
        }

        return digest;
    }

    internal byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        byte[] tag = new byte[64];
        fixed (byte* keyPointer = key)
        fixed (byte* messagePointer = message)
        fixed (byte* tagPointer = tag)
        {
            int status = _hmac(
                keyPointer,
                (nuint)key.Length,
                messagePointer,
                (nuint)message.Length,
                tagPointer,
                (nuint)tag.Length);
            if (status != 0)
            {
                throw new InvalidOperationException($"The HMAC-SHA3-512 reference returned {status}.");
            }
        }

        return tag;
    }

    public void Dispose()
    {
        if (_module != 0)
        {
            NativeLibrary.Free(_module);
        }
    }
}
