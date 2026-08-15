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
                uint lockError = _lastMemoryLockError();
                string lockFailure = lockError == 0
                    ? string.Empty
                    : $" Windows could not lock the Argon2id working memory: {new Win32Exception(checked((int)lockError)).Message} ({lockError}).";
                throw new CryptographicException($"Argon2id PHC reference returned {result}: {GetErrorMessage(result)}.{lockFailure}");
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
