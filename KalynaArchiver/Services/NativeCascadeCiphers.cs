using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

// Interop for the two cascade layers that come from Crypto++.
//
// Both follow NativeKalyna exactly: the library is loaded through
// NativeToolIntegrity so its manifests and hybrid signatures are checked before
// a single byte is executed, the entry point is resolved once behind a lock,
// and a failure to load is reported with its reason rather than as a missing
// file. A reference library that silently degrades to "unavailable" is
// indistinguishable from one that was tampered with, which is exactly the
// distinction this app exists to make.

internal static unsafe class NativeMars
{
    private const string DllName = "mars_ref.dll";

    /// <summary>MARS accepts 128 to 448 bits; the cascade uses the longest.</summary>
    private const int KeyBytes = 56;

    /// <summary>MARS has a 128-bit block, so its counter is 16 bytes wide.</summary>
    internal const int BlockBytes = 16;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int> _encryptBlock;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void XCryptCtr448(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != BlockBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"MARS-448 requires a {KeyBytes}-byte key, a {BlockBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length);
        }

        ThrowOnError(result, "MARS");
    }

    /// <summary>
    /// One block, no counter. Used by the tests to compare against published
    /// vectors, so that the vector check exercises the cipher rather than the
    /// mode wrapped around it.
    /// </summary>
    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (input.Length != BlockBytes || output.Length < BlockBytes)
        {
            throw new ArgumentException($"MARS operates on {BlockBytes}-byte blocks.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, (nuint)key.Length, inputPointer, outputPointer);
        }

        ThrowOnError(result, "MARS");
    }

    private static void ThrowOnError(int result, string algorithm)
    {
        if (result == 0)
        {
            return;
        }

        throw new CryptographicException(result switch
        {
            1 => $"{algorithm} reference library received invalid buffers.",
            2 => $"{algorithm} reference library rejected the key length.",
            3 => $"{algorithm} reference library could not start CTR worker threads.",
            4 => $"{algorithm} CTR counter is exhausted or overflowed.",
            _ => $"{algorithm} reference library returned error {result}.",
        });
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int>)
                    NativeLibrary.GetExport(handle, "mars_448_ctr_xcrypt");
                _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int>)
                    NativeLibrary.GetExport(handle, "mars_encrypt_block");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _xcryptCtr = null;
                _encryptBlock = null;
                throw;
            }
        }
    }
}

internal static unsafe class NativeShacal2
{
    private const string DllName = "shacal2_ref.dll";

    private const int KeyBytes = 64;

    /// <summary>
    /// SHACAL-2 works on 256-bit blocks — twice AES's, half Kalyna's. The
    /// counter is therefore 32 bytes wide, which the cascade's nonce split has
    /// to account for.
    /// </summary>
    internal const int BlockBytes = 32;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int> _encryptBlock;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void XCryptCtr512(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != BlockBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"SHACAL-2-512 requires a {KeyBytes}-byte key, a {BlockBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length);
        }

        ThrowOnError(result);
    }

    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (input.Length != BlockBytes || output.Length < BlockBytes)
        {
            throw new ArgumentException($"SHACAL-2 operates on {BlockBytes}-byte blocks.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, (nuint)key.Length, inputPointer, outputPointer);
        }

        ThrowOnError(result);
    }

    private static void ThrowOnError(int result)
    {
        if (result == 0)
        {
            return;
        }

        throw new CryptographicException(result switch
        {
            1 => "SHACAL-2 reference library received invalid buffers.",
            2 => "SHACAL-2 reference library rejected the key length.",
            3 => "SHACAL-2 reference library could not start CTR worker threads.",
            4 => "SHACAL-2 CTR counter is exhausted or overflowed.",
            _ => $"SHACAL-2 reference library returned error {result}.",
        });
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int>)
                    NativeLibrary.GetExport(handle, "shacal2_512_ctr_xcrypt");
                _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int>)
                    NativeLibrary.GetExport(handle, "shacal2_encrypt_block");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _xcryptCtr = null;
                _encryptBlock = null;
                throw;
            }
        }
    }
}

internal static unsafe class NativeAes
{
    private const string DllName = "aes_ref.dll";
    private const int KeyBytes = 32;

    internal const int BlockBytes = 16;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int> _encryptBlock;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// The reference AES, used when the platform implementation is unavailable
    /// and by the tests to check the platform against something independent.
    /// </summary>
    /// <remarks>
    /// This is the slow path on purpose. Production AES runs on the platform,
    /// which reaches AES-NI and the Apple silicon crypto extensions; this one
    /// is compiled with Crypto++'s assembly paths switched off.
    /// </remarks>
    public static void XCryptCtr256(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != BlockBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"AES-256 requires a {KeyBytes}-byte key, a {BlockBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length);
        }

        if (result != 0)
        {
            throw new CryptographicException($"AES reference library returned error {result}.");
        }
    }

    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (input.Length != BlockBytes || output.Length < BlockBytes)
        {
            throw new ArgumentException($"AES operates on {BlockBytes}-byte blocks.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, (nuint)key.Length, inputPointer, outputPointer);
        }

        if (result != 0)
        {
            throw new CryptographicException($"AES reference library returned error {result}.");
        }
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, int>)
                    NativeLibrary.GetExport(handle, "aes_256_ctr_xcrypt");
                _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int>)
                    NativeLibrary.GetExport(handle, "aes_encrypt_block");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _xcryptCtr = null;
                _encryptBlock = null;
                throw;
            }
        }
    }
}

internal static unsafe class NativeChaChaPoly
{
    private const string DllName = "chachapoly_ref.dll";

    internal const int KeyBytes = 32;
    internal const int NonceBytes = 12;
    internal const int TagBytes = 16;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, nuint, byte*, byte*, nuint, byte*, int> _encrypt;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, nuint, byte*, byte*, nuint, byte*, int> _decrypt;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void Encrypt(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] plaintext,
        byte[] ciphertext,
        int length,
        byte[] tag)
    {
        Validate(key, nonce, tag, plaintext, ciphertext, length);

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = plaintext)
        fixed (byte* outputPointer = ciphertext)
        fixed (byte* tagPointer = tag)
        {
            result = _encrypt(
                keyPointer, noncePointer, aadPointer, (nuint)associatedData.Length,
                inputPointer, outputPointer, (nuint)length, tagPointer);
        }

        ThrowOnError(result);
    }

    /// <summary>
    /// Verifies the tag and decrypts, or throws.
    /// </summary>
    /// <remarks>
    /// A failed tag is reported as its own exception rather than folded into a
    /// generic error. It is the one outcome that means the ciphertext was
    /// altered, and a caller that cannot tell it apart from a missing library
    /// cannot react correctly to either.
    /// </remarks>
    public static void Decrypt(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] ciphertext,
        byte[] plaintext,
        int length,
        byte[] tag)
    {
        Validate(key, nonce, tag, ciphertext, plaintext, length);

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = ciphertext)
        fixed (byte* outputPointer = plaintext)
        fixed (byte* tagPointer = tag)
        {
            result = _decrypt(
                keyPointer, noncePointer, aadPointer, (nuint)associatedData.Length,
                inputPointer, outputPointer, (nuint)length, tagPointer);
        }

        if (result == 6)
        {
            throw new CryptographicException(
                "The ChaCha20-Poly1305 authentication tag does not match; the ciphertext was altered.");
        }

        ThrowOnError(result);
    }

    private static void Validate(byte[] key, byte[] nonce, byte[] tag, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != NonceBytes || tag.Length != TagBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"ChaCha20-Poly1305 requires a {KeyBytes}-byte key, a {NonceBytes}-byte nonce, "
                + $"a {TagBytes}-byte tag, and sufficiently large buffers.");
        }
    }

    private static void ThrowOnError(int result)
    {
        if (result == 0)
        {
            return;
        }

        throw new CryptographicException(result switch
        {
            1 => "ChaCha20-Poly1305 reference library received invalid buffers.",
            5 => "ChaCha20-Poly1305 reference library failed internally.",
            _ => $"ChaCha20-Poly1305 reference library returned error {result}.",
        });
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                _encrypt = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, nuint, byte*, byte*, nuint, byte*, int>)
                    NativeLibrary.GetExport(handle, "chacha20poly1305_encrypt");
                _decrypt = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, nuint, byte*, byte*, nuint, byte*, int>)
                    NativeLibrary.GetExport(handle, "chacha20poly1305_decrypt");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _encrypt = null;
                _decrypt = null;
                throw;
            }
        }
    }
}
