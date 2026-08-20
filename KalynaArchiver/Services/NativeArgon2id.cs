using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

internal static unsafe partial class NativeArgon2id
{
    private const string DllName = "argon2_ref.dll";
    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<uint, uint, uint, byte*, uint, byte*, uint, byte*, uint, int> _hashRaw;
    private static delegate* unmanaged[Cdecl]<
        uint, uint, uint, byte*, uint, byte*, uint, byte*, uint, byte*, uint, byte*, uint, int> _hashRawV10;
    private static delegate* unmanaged[Cdecl]<int, nint> _errorMessage;
    private static delegate* unmanaged[Cdecl]<uint> _lastMemoryLockError;

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void HashRaw(uint iterations, uint memoryKiB, uint parallelism, byte[] password, byte[] salt, byte[] output)
    {
        if (password.Length == 0 || salt.Length < 8 || output.Length < 4)
        {
            throw new ArgumentException("Argon2id benötigt Passwort-, Salt- und Output-Puffer.");
        }

        // Integrity + signature are verified once in EnsureLoaded/LoadTrustedLibrary. The
        // module is then held loaded (and OS-locked against modification) for the process
        // lifetime, so re-hashing/re-verifying on every call adds cost without added safety.
        EnsureLoaded();

        using IDisposable workingSetReservation = SecureMemory.ReserveWorkingSetCapacity(
            checked((long)memoryKiB * 1024));
        fixed (byte* passwordPtr = password)
        fixed (byte* saltPtr = salt)
        fixed (byte* outputPtr = output)
        {
            int result = _hashRaw(
                iterations,
                memoryKiB,
                parallelism,
                passwordPtr,
                checked((uint)password.Length),
                saltPtr,
                checked((uint)salt.Length),
                outputPtr,
                checked((uint)output.Length));

            if (result != 0)
            {
                string lockFailure = DescribeMemoryLockFailure();
                throw new CryptographicException($"Argon2id PHC reference returned {result}: {GetErrorMessage(result)}.{lockFailure}");
            }
        }
    }

    /// <summary>
    /// Explains why the Argon2id working memory could not be locked, in the
    /// terms of whichever platform reported it.
    /// </summary>
    /// <remarks>
    /// The native side reports a raw platform error code. It used to be
    /// rendered through <see cref="Win32Exception"/> unconditionally, so a
    /// macOS <c>mlock</c> refusal — most often ENOMEM against the per-process
    /// wired-memory limit, or EPERM — arrived as a sentence about Windows and a
    /// message looked up in the wrong table. Locking still fails closed either
    /// way; only the diagnosis was wrong, which is exactly the kind of wrong
    /// that costs an afternoon.
    /// </remarks>
    private static string DescribeMemoryLockFailure()
    {
        uint lockError = _lastMemoryLockError();
        if (lockError == 0)
        {
            return string.Empty;
        }

        int code = checked((int)lockError);
        if (OperatingSystem.IsWindows())
        {
            return $" Windows could not lock the Argon2id working memory: "
                + $"{new Win32Exception(code).Message} ({lockError}).";
        }

        string detail = code switch
        {
            12 => "ENOMEM: the wired-memory limit for this process was reached",
            1 => "EPERM: locking memory is not permitted for this process",
            22 => "EINVAL: the range handed to mlock was rejected",
            _ => $"errno {code}",
        };
        return $" mlock could not lock the Argon2id working memory: {detail}.";
    }

    /// <summary>
    /// One v10 Argon2id branch, with Argon2's optional secret and
    /// associated-data inputs.
    /// </summary>
    /// <remarks>
    /// The buffers handed in here are one-call copies and nothing else. The
    /// native side sets ARGON2_FLAG_CLEAR_PASSWORD, and ARGON2_FLAG_CLEAR_SECRET
    /// when a secret is present, so both are wiped inside the call. Passing a
    /// buffer that a later call still needs is precisely the defect that made
    /// v9's second Paranoia round run over zero bytes; the caller owns the
    /// masters and copies from them.
    ///
    /// This method stays single-call on purpose. Sequencing the two KDF branches
    /// happens one level up, in PasswordKeyService, so the order is visible and
    /// testable rather than buried behind a native lock.
    /// </remarks>
    public static void HashRawV10(
        uint iterations,
        uint memoryKiB,
        uint parallelism,
        byte[] password,
        byte[] salt,
        byte[]? secret,
        byte[] associatedData,
        byte[] output)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(associatedData);
        ArgumentNullException.ThrowIfNull(output);
        if (associatedData.Length == 0)
        {
            throw new ArgumentException("A v10 Argon2id branch requires associated data.", nameof(associatedData));
        }

        EnsureLoaded();

        using IDisposable workingSetReservation = SecureMemory.ReserveWorkingSetCapacity(
            checked((long)memoryKiB * 1024));
        byte[] secretBuffer = secret ?? [];
        fixed (byte* passwordPtr = password)
        fixed (byte* saltPtr = salt)
        fixed (byte* secretPtr = secretBuffer)
        fixed (byte* associatedDataPtr = associatedData)
        fixed (byte* outputPtr = output)
        {
            int result = _hashRawV10(
                iterations,
                memoryKiB,
                parallelism,
                passwordPtr,
                checked((uint)password.Length),
                saltPtr,
                checked((uint)salt.Length),
                secretBuffer.Length == 0 ? null : secretPtr,
                checked((uint)secretBuffer.Length),
                associatedDataPtr,
                checked((uint)associatedData.Length),
                outputPtr,
                checked((uint)output.Length));

            if (result != 0)
            {
                string lockFailure = DescribeMemoryLockFailure();
                throw new CryptographicException(
                    $"Argon2id v10 returned {result}: {GetErrorMessage(result)}.{lockFailure}");
            }
        }
    }

    private static string GetErrorMessage(int errorCode)
    {
        nint message = _errorMessage(errorCode);
        return Marshal.PtrToStringAnsi(message) ?? "unknown error";
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
                _hashRaw = (delegate* unmanaged[Cdecl]<uint, uint, uint, byte*, uint, byte*, uint, byte*, uint, int>)
                    NativeLibrary.GetExport(handle, "phc_argon2id_hash_raw");
                _hashRawV10 = (delegate* unmanaged[Cdecl]<
                    uint, uint, uint, byte*, uint, byte*, uint, byte*, uint, byte*, uint, byte*, uint, int>)
                    NativeLibrary.GetExport(handle, "keepvault_argon2id_v10");
                _errorMessage = (delegate* unmanaged[Cdecl]<int, nint>)
                    NativeLibrary.GetExport(handle, "phc_argon2_error_message");
                _lastMemoryLockError = (delegate* unmanaged[Cdecl]<uint>)
                    NativeLibrary.GetExport(handle, "phc_argon2_last_memory_lock_error");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _hashRaw = null;
                _errorMessage = null;
                _lastMemoryLockError = null;
                throw;
            }
        }
    }
}
