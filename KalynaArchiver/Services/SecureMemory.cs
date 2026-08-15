using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KalynaArchiver.Services;

internal static partial class SecureMemory
{
    private const long MinimumWorkingSetMargin = 64L * 1024 * 1024;
    private const long MaximumWorkingSetMargin = 256L * 1024 * 1024;
    private static readonly object WorkingSetGate = new();
    private static long _lockedBytes;
    private static long _reservedWorkingSetBytes;
    private static nuint _originalMinimumWorkingSet;
    private static nuint _originalMaximumWorkingSet;
    private static bool _originalWorkingSetAvailable;
    private static readonly Dictionary<nuint, int> MacLockedPages = [];

    internal static long LockedBytesForTests
    {
        get
        {
            lock (WorkingSetGate)
            {
                return _lockedBytes;
            }
        }
    }

    internal static long ReservedWorkingSetBytesForTests
    {
        get
        {
            lock (WorkingSetGate)
            {
                return _reservedWorkingSetBytes;
            }
        }
    }

    public static IDisposable TryLock(byte[]? buffer)
    {
        if (buffer is null || buffer.Length == 0)
        {
            return NoopDisposable.Instance;
        }

        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("Secure memory locking requires a reviewed operating-system adapter.");
        }

        return new LockedArray(buffer);
    }

    private static long RoundedPageBytes(int length)
    {
        long pageSize = Environment.SystemPageSize;
        return checked(((long)length + pageSize - 1) / pageSize * pageSize);
    }

    private static void ReserveWorkingSet(long additionalBytes)
    {
        if (OperatingSystem.IsMacOS())
        {
            _lockedBytes = checked(_lockedBytes + additionalBytes);
            return;
        }

        CaptureOriginalWorkingSetIfNeeded();
        long newTotal = checked(_lockedBytes + additionalBytes);
        SetWorkingSetOrThrow(checked(newTotal + _reservedWorkingSetBytes));
        _lockedBytes = newTotal;
    }

    internal static IDisposable ReserveWorkingSetCapacity(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytes);

        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("Working-set reservations require a reviewed operating-system adapter.");
        }

        var reservation = new WorkingSetReservation(bytes);
        lock (WorkingSetGate)
        {
            if (OperatingSystem.IsMacOS())
            {
                EnsureMacMemoryLockLimit(checked(_lockedBytes + _reservedWorkingSetBytes + bytes));
                _reservedWorkingSetBytes = checked(_reservedWorkingSetBytes + bytes);
                return reservation;
            }

            CaptureOriginalWorkingSetIfNeeded();
            long newReservedBytes = checked(_reservedWorkingSetBytes + bytes);
            SetWorkingSetOrThrow(checked(_lockedBytes + newReservedBytes));
            _reservedWorkingSetBytes = newReservedBytes;
        }

        return reservation;
    }

    private static void CaptureOriginalWorkingSetIfNeeded()
    {
        if (_lockedBytes != 0 || _reservedWorkingSetBytes != 0)
        {
            return;
        }

        _originalWorkingSetAvailable = GetProcessWorkingSetSize(
            GetCurrentProcess(),
            out _originalMinimumWorkingSet,
            out _originalMaximumWorkingSet);
    }

    private static void SetWorkingSetOrThrow(long reservedBytes)
    {
        long minimum = checked(reservedBytes + MinimumWorkingSetMargin);
        long maximum = checked(reservedBytes + MaximumWorkingSetMargin);
        if (!SetProcessWorkingSetSize(GetCurrentProcess(), checked((nuint)minimum), checked((nuint)maximum)))
        {
            throw new CryptographicException(
                "Windows could not reserve the working-set quota required to lock sensitive memory.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }
    }

    private static void ReleaseWorkingSet(long releasedBytes)
    {
        _lockedBytes = Math.Max(0, _lockedBytes - releasedBytes);
        ResizeWorkingSetAfterRelease();
    }

    private static void ReleaseWorkingSetCapacity(long releasedBytes)
    {
        lock (WorkingSetGate)
        {
            _reservedWorkingSetBytes = Math.Max(0, _reservedWorkingSetBytes - releasedBytes);
            ResizeWorkingSetAfterRelease();
        }
    }

    private static void ResizeWorkingSetAfterRelease()
    {
        if (OperatingSystem.IsMacOS())
        {
            return;
        }

        long totalReservedBytes = checked(_lockedBytes + _reservedWorkingSetBytes);
        if (totalReservedBytes == 0 && _originalWorkingSetAvailable)
        {
            _ = SetProcessWorkingSetSize(
                GetCurrentProcess(),
                _originalMinimumWorkingSet,
                _originalMaximumWorkingSet);
            _originalWorkingSetAvailable = false;
            return;
        }

        if (totalReservedBytes == 0)
        {
            _ = SetProcessWorkingSetSize(GetCurrentProcess(), nuint.MaxValue, nuint.MaxValue);
            return;
        }

        long minimum = checked(totalReservedBytes + MinimumWorkingSetMargin);
        long maximum = checked(totalReservedBytes + MaximumWorkingSetMargin);
        _ = SetProcessWorkingSetSize(GetCurrentProcess(), checked((nuint)minimum), checked((nuint)maximum));
    }

    private sealed class WorkingSetReservation(long bytes) : IDisposable
    {
        private long _bytes = bytes;

        public void Dispose()
        {
            long releasedBytes = Interlocked.Exchange(ref _bytes, 0);
            if (releasedBytes != 0)
            {
                ReleaseWorkingSetCapacity(releasedBytes);
            }
        }
    }

    private sealed class LockedArray : IDisposable
    {
        private readonly int _length;
        private readonly long _reservedBytes;
        private nuint[] _macPages = [];
        private GCHandle _handle;
        private bool _locked;

        public LockedArray(byte[] buffer)
        {
            _length = buffer.Length;
            _reservedBytes = RoundedPageBytes(buffer.Length);
            _handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                lock (WorkingSetGate)
                {
                    ReserveWorkingSet(_reservedBytes);
                    bool lockSucceeded;
                    if (OperatingSystem.IsWindows())
                    {
                        lockSucceeded = VirtualLock(_handle.AddrOfPinnedObject(), checked((nuint)buffer.Length));
                    }
                    else
                    {
                        lockSucceeded = TryLockMacPages(
                            _handle.AddrOfPinnedObject(),
                            checked((nuint)buffer.Length),
                            out _macPages,
                            out int macError);
                        if (!lockSucceeded)
                        {
                            Marshal.SetLastPInvokeError(macError);
                        }
                    }

                    if (!lockSucceeded)
                    {
                        int error = Marshal.GetLastPInvokeError();
                        ReleaseWorkingSet(_reservedBytes);
                        throw new CryptographicException(
                            "The operating system could not lock sensitive memory; the operation was stopped to prevent swap exposure.",
                            new Win32Exception(error));
                    }

                    _locked = true;
                }
            }
            catch
            {
                _handle.Free();
                throw;
            }
        }

        public void Dispose()
        {
            if (!_handle.IsAllocated)
            {
                return;
            }

            lock (WorkingSetGate)
            {
                if (_locked)
                {
                    if (OperatingSystem.IsWindows())
                    {
                        _ = VirtualUnlock(_handle.AddrOfPinnedObject(), checked((nuint)_length));
                    }
                    else
                    {
                        UnlockMacPages(_macPages);
                        _macPages = [];
                    }
                    _locked = false;
                    ReleaseWorkingSet(_reservedBytes);
                }
            }

            _handle.Free();
        }
    }

    private static void EnsureMacMemoryLockLimit(long requestedBytes)
    {
        if (GetResourceLimit(ResourceLimitMemoryLock, out ResourceLimit limit) != 0)
        {
            throw new CryptographicException(
                "macOS could not report the memory-lock limit.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        ulong requested = checked((ulong)requestedBytes);
        if (limit.Current != ulong.MaxValue && requested > limit.Current)
        {
            throw new CryptographicException(
                $"macOS permits only {limit.Current} locked bytes, but {requested} bytes are required.");
        }
    }

    private static bool TryLockMacPages(
        nint address,
        nuint length,
        out nuint[] pages,
        out int error)
    {
        nuint pageSize = checked((nuint)Environment.SystemPageSize);
        nuint first = checked((nuint)address) / pageSize * pageSize;
        nuint lastExclusive = checked((checked((nuint)address) + length + pageSize - 1) / pageSize * pageSize);
        var acquired = new List<nuint>(checked((int)((lastExclusive - first) / pageSize)));
        error = 0;
        for (nuint page = first; page < lastExclusive; page += pageSize)
        {
            if (MacLockedPages.TryGetValue(page, out int leases))
            {
                MacLockedPages[page] = checked(leases + 1);
                acquired.Add(page);
                continue;
            }

            if (MacMemoryLock(checked((nint)page), pageSize) != 0)
            {
                error = Marshal.GetLastPInvokeError();
                UnlockMacPages([.. acquired]);
                pages = [];
                return false;
            }

            MacLockedPages.Add(page, 1);
            acquired.Add(page);
        }

        pages = [.. acquired];
        return true;
    }

    private static void UnlockMacPages(nuint[] pages)
    {
        nuint pageSize = checked((nuint)Environment.SystemPageSize);
        foreach (nuint page in pages)
        {
            if (!MacLockedPages.TryGetValue(page, out int leases))
            {
                continue;
            }

            if (leases > 1)
            {
                MacLockedPages[page] = leases - 1;
            }
            else
            {
                _ = MacMemoryUnlock(checked((nint)page), pageSize);
                MacLockedPages.Remove(page);
            }
        }
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();

        public void Dispose()
        {
        }
    }

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessWorkingSetSize(
        nint process,
        out nuint minimumWorkingSetSize,
        out nuint maximumWorkingSetSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessWorkingSetSize(
        nint process,
        nuint minimumWorkingSetSize,
        nuint maximumWorkingSetSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualLock(nint address, nuint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualUnlock(nint address, nuint size);

    private const int ResourceLimitMemoryLock = 6;

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ResourceLimit
    {
        public readonly ulong Current;
        public readonly ulong Maximum;
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "getrlimit", SetLastError = true)]
    private static partial int GetResourceLimit(int resource, out ResourceLimit limit);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "mlock", SetLastError = true)]
    private static partial int MacMemoryLock(nint address, nuint size);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "munlock", SetLastError = true)]
    private static partial int MacMemoryUnlock(nint address, nuint size);
}

internal sealed class LockedSensitiveBuffer : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _bytes;
    private IDisposable? _memoryLock;

    internal LockedSensitiveBuffer(byte[] bytes, IDisposable memoryLock)
    {
        _bytes = bytes;
        _memoryLock = memoryLock;
    }

    public byte[] Bytes
    {
        get
        {
            lock (_gate)
            {
                return _bytes ?? throw new ObjectDisposedException(nameof(LockedSensitiveBuffer));
            }
        }
    }

    public static LockedSensitiveBuffer Create(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] bytes = new byte[length];
        IDisposable? memoryLock = null;
        try
        {
            memoryLock = SecureMemory.TryLock(bytes);
            return new LockedSensitiveBuffer(bytes, memoryLock);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            memoryLock?.Dispose();
            throw;
        }
    }

    public static LockedSensitiveBuffer Encode(string value, Encoding encoding)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(encoding);
        LockedSensitiveBuffer buffer = Create(encoding.GetByteCount(value));
        try
        {
            int written = encoding.GetBytes(value.AsSpan(), buffer.Bytes);
            if (written != buffer.Bytes.Length)
            {
                throw new CryptographicException("Sensitive text was not encoded completely.");
            }

            return buffer;
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_bytes is null)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(_bytes);
            _bytes = null;
            _memoryLock?.Dispose();
            _memoryLock = null;
        }
    }
}
