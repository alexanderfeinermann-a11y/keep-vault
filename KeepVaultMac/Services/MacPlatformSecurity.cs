using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal static partial class MacSafeFileSystem
{
    internal const int OpenReadOnly = 0x0000;
    internal const int OpenReadWrite = 0x0002;
    internal const int OpenDirectory = 0x00100000;
    internal const int OpenCloseOnExec = 0x01000000;
    internal const int OpenNoFollowAny = 0x20000000;
    private const uint CloneNoOwnerCopy = 0x0002;
    private const uint CloneNoFollowAny = 0x0008;
    private const uint CloneResolveBeneath = 0x0010;
    private const int FFullFsync = 51;
    private const uint RegularFileMode = 0x8000;
    private const uint FileTypeMask = 0xF000;

    internal static FileStream OpenReadNoSymlinks(string path)
    {
        SafeFileHandle handle = OpenHandleNoSymlinks(path, write: false);
        try
        {
            ValidateRegularFile(handle, requireSingleLink: false, path);
            return new FileStream(handle, FileAccess.Read, bufferSize: 1024 * 1024, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static FileStream OpenReadWriteNoSymlinks(string path, bool requireSingleLink)
    {
        SafeFileHandle handle = OpenHandleNoSymlinks(path, write: true);
        try
        {
            ValidateRegularFile(handle, requireSingleLink, path);

            // The descriptor comes from a plain open(2) and is therefore
            // synchronous. Constructing the stream with isAsync: true would
            // throw, because FileStream requires a handle that was opened for
            // overlapped I/O — a Windows concept with no macOS equivalent.
            // Asynchronous reads and writes still work; .NET runs them on the
            // thread pool, exactly as for the read-only path above.
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 1024 * 1024, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle OpenHandleNoSymlinks(string path, bool write)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException();
        }

        string fullPath = Path.GetFullPath(path);
        int descriptor = Open(fullPath, (write ? OpenReadWrite : OpenReadOnly) | OpenCloseOnExec | OpenNoFollowAny);
        if (descriptor < 0)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new IOException(
                $"macOS refused the symlink-safe open: {fullPath}",
                new Win32Exception(error));
        }

        return new SafeFileHandle(descriptor, ownsHandle: true);
    }

    internal static void CloneOpenedFileIntoDirectory(
        SafeFileHandle sourceHandle,
        string destinationDirectory,
        string destinationFileName)
    {
        ArgumentNullException.ThrowIfNull(sourceHandle);
        if (string.IsNullOrWhiteSpace(destinationFileName)
            || !string.Equals(destinationFileName, Path.GetFileName(destinationFileName), StringComparison.Ordinal))
        {
            throw new ArgumentException("A private clone destination must be a single file name.", nameof(destinationFileName));
        }

        string canonicalDirectory = ResolveExistingRealPath(destinationDirectory);
        int directoryDescriptor = Open(
            canonicalDirectory,
            OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny);
        if (directoryDescriptor < 0)
        {
            throw new IOException(
                $"macOS refused the private snapshot directory: {canonicalDirectory}",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        using var directoryHandle = new SafeFileHandle(directoryDescriptor, ownsHandle: true);
        bool sourceAdded = false;
        bool directoryAdded = false;
        try
        {
            sourceHandle.DangerousAddRef(ref sourceAdded);
            directoryHandle.DangerousAddRef(ref directoryAdded);
            int sourceDescriptor = checked((int)sourceHandle.DangerousGetHandle());
            int targetDescriptor = checked((int)directoryHandle.DangerousGetHandle());
            if (FCloneFileAt(
                    sourceDescriptor,
                    targetDescriptor,
                    destinationFileName,
                    CloneNoOwnerCopy | CloneNoFollowAny | CloneResolveBeneath) != 0)
            {
                int errorCode = Marshal.GetLastPInvokeError();
                const int Exdev = 18;
                const int Enotsup = 45;
                const int Eopnotsupp = 102;
                if (errorCode == Exdev || errorCode == Enotsup || errorCode == Eopnotsupp)
                {
                    StreamCopyDescriptorIntoPrivateDirectory(sourceDescriptor, targetDescriptor, destinationFileName);
                }
                else
                {
                    throw new IOException(
                        "macOS could not create the required descriptor-bound atomic copy-on-write snapshot.",
                        new Win32Exception(errorCode));
                }
            }
        }
        finally
        {
            if (directoryAdded)
            {
                directoryHandle.DangerousRelease();
            }

            if (sourceAdded)
            {
                sourceHandle.DangerousRelease();
            }
        }
    }

    private static unsafe void StreamCopyDescriptorIntoPrivateDirectory(
        int sourceDescriptor,
        int targetDirectoryDescriptor,
        string destinationFileName)
    {
        if (FStat(sourceDescriptor, out DarwinStat beforeStat) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not stat source descriptor before copy.");
        }

        // Open target file descriptor directly via openat
        const int openFlags = 0x0002 /* O_RDWR */
            | 0x0200 /* O_CREAT */
            | 0x0800 /* O_EXCL */
            | 0x20000000 /* O_NOFOLLOW_ANY */
            | 0x01000000 /* O_CLOEXEC */;

        int targetFileFd = PInvokeOpenAt(targetDirectoryDescriptor, destinationFileName, openFlags, 0x180 /* 0600 */);
        if (targetFileFd < 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS openat failed for snapshot destination.");
        }

        using var targetFileHandle = new SafeFileHandle(targetFileFd, ownsHandle: true);

        using var hashStream = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        byte[] buffer = new byte[64 * 1024];
        long sourceOffset = 0;
        long totalRead = 0;
        try
        {
            fixed (byte* pBuf = buffer)
            {
                while (sourceOffset < beforeStat.Size)
                {
                    int toRead = checked((int)Math.Min(buffer.Length, beforeStat.Size - sourceOffset));
                    nint bytesRead;
                    while (true)
                    {
                        bytesRead = PRead(sourceDescriptor, pBuf, (nuint)toRead, sourceOffset);
                        if (bytesRead < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == 4 /* EINTR */) continue;
                            throw new Win32Exception(err, "macOS pread failed during cross-volume snapshot.");
                        }
                        break;
                    }
                    if (bytesRead == 0)
                    {
                        break;
                    }

                    long chunkWritten = 0;
                    while (chunkWritten < bytesRead)
                    {
                        nint written = PWrite(targetFileFd, pBuf + chunkWritten, (nuint)(bytesRead - chunkWritten), sourceOffset + chunkWritten);
                        if (written < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == 4 /* EINTR */) continue;
                            throw new Win32Exception(err, "macOS pwrite failed during cross-volume snapshot.");
                        }
                        if (written == 0)
                        {
                            throw new IOException("macOS pwrite made no progress during cross-volume snapshot.");
                        }
                        chunkWritten += written;
                    }

                    hashStream.AppendData(buffer, 0, (int)bytesRead);
                    sourceOffset += bytesRead;
                    totalRead += bytesRead;
                }
            }
            MacSafeFileSystem.FullSync(targetFileHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        byte[] writtenHash = hashStream.GetHashAndReset();

        using var verifyHashStream = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        long verifyOffset = 0;
        try
        {
            fixed (byte* pBuf = buffer)
            {
                while (verifyOffset < beforeStat.Size)
                {
                    int toRead = checked((int)Math.Min(buffer.Length, beforeStat.Size - verifyOffset));
                    nint bytesRead;
                    while (true)
                    {
                        bytesRead = PRead(sourceDescriptor, pBuf, (nuint)toRead, verifyOffset);
                        if (bytesRead < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == 4 /* EINTR */) continue;
                            throw new Win32Exception(err, "macOS pread verification pass failed.");
                        }
                        break;
                    }
                    if (bytesRead == 0)
                    {
                        break;
                    }
                    verifyHashStream.AppendData(buffer, 0, (int)bytesRead);
                    verifyOffset += bytesRead;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        byte[] verifyHash = verifyHashStream.GetHashAndReset();

        if (FStat(sourceDescriptor, out DarwinStat afterStat) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not stat source descriptor after copy.");
        }

        bool stable = beforeStat.Device == afterStat.Device
            && beforeStat.Inode == afterStat.Inode
            && beforeStat.Size == afterStat.Size
            && beforeStat.ModificationTime.Seconds == afterStat.ModificationTime.Seconds
            && beforeStat.ModificationTime.Nanoseconds == afterStat.ModificationTime.Nanoseconds
            && beforeStat.ChangeTime.Seconds == afterStat.ChangeTime.Seconds
            && beforeStat.ChangeTime.Nanoseconds == afterStat.ChangeTime.Nanoseconds
            && totalRead == beforeStat.Size
            && verifyOffset == beforeStat.Size
            && CryptographicOperations.FixedTimeEquals(writtenHash, verifyHash);

        if (!stable)
        {
            PInvokeUnlinkAt(targetDirectoryDescriptor, destinationFileName, 0);
            throw new InvalidOperationException("Source file metadata or content mutated concurrently during cross-volume snapshot copy.");
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "pread", SetLastError = true)]
    private static unsafe partial nint PRead(int descriptor, byte* buffer, nuint count, long offset);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "pwrite", SetLastError = true)]
    private static unsafe partial nint PWrite(int descriptor, byte* buffer, nuint count, long offset);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "dup", SetLastError = true)]
    private static partial int Dup(int descriptor);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fdopendir", SetLastError = true)]
    private static partial nint FdOpenDir(int descriptor);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "readdir", SetLastError = true)]
    private static partial nint ReadDir(nint dirp);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "closedir", SetLastError = true)]
    private static partial int CloseDir(nint dirp);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct DarwinDirent
    {
        public ulong d_ino;
        public ulong d_seekoff;
        public ushort d_reclen;
        public ushort d_namlen;
        public byte d_type;
        public fixed byte d_name[1024];
    }

    internal static MacFileIdentity GetIdentity(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            if (FStat(descriptor, out DarwinStat status) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not inspect the open file descriptor.");
            }

            return new MacFileIdentity(status.Device, status.Inode, status.LinkCount, status.Mode, status.Size);
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    internal static MacFileIdentity GetPathIdentityNoFollow(string path)
    {
        if (LStat(Path.GetFullPath(path), out DarwinStat status) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not inspect the file path without following links.");
        }

        return new MacFileIdentity(status.Device, status.Inode, status.LinkCount, status.Mode, status.Size);
    }

    internal static string ResolveExistingRealPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        nint resolved = RealPath(fullPath, 0);
        if (resolved == 0)
        {
            throw new IOException(
                $"macOS could not canonicalize an existing private path: {fullPath}",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        try
        {
            return Marshal.PtrToStringUTF8(resolved)
                ?? throw new IOException("macOS returned an invalid canonical private path.");
        }
        finally
        {
            Free(resolved);
        }
    }

    internal static void ValidateRegularFile(SafeFileHandle handle, bool requireSingleLink, string displayPath)
    {
        MacFileIdentity identity = GetIdentity(handle);
        if ((identity.Mode & FileTypeMask) != RegularFileMode)
        {
            throw new IOException($"Only a regular file is accepted: {displayPath}");
        }

        if (requireSingleLink && identity.LinkCount != 1)
        {
            throw new IOException($"The operation refuses files with multiple hard links: {displayPath}");
        }
    }

    internal static void RequirePathStillNamesHandle(SafeFileHandle handle, string path)
    {
        MacFileIdentity handleIdentity = GetIdentity(handle);
        MacFileIdentity pathIdentity = GetPathIdentityNoFollow(path);
        if (!handleIdentity.SameObject(pathIdentity))
        {
            throw new IOException("The file path was replaced while its security properties were being verified.");
        }
    }

    internal static void FullSync(SafeFileHandle handle)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            if (FcntlNoArgument(descriptor, FFullFsync) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "F_FULLFSYNC failed for sensitive file data.");
            }
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinTimespec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct DarwinStat
    {
        internal int Device;
        internal ushort Mode;
        internal ushort LinkCount;
        internal ulong Inode;
        internal uint Uid;
        internal uint Gid;
        internal int Rdev;
        internal DarwinTimespec AccessTime;
        internal DarwinTimespec ModificationTime;
        internal DarwinTimespec ChangeTime;
        internal DarwinTimespec BirthTime;
        internal long Size;
        internal long Blocks;
        internal int BlockSize;
        internal uint Flags;
        internal uint Generation;
        internal int Spare;
        internal fixed long Reserved[2];
    }

    internal static SafeFileHandle OpenDirectoryHandle(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        int descriptor = Open(path, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny);
        if (descriptor < 0)
        {
            throw new IOException(
                $"macOS could not open directory handle for '{path}'.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }
        return new SafeFileHandle(descriptor, ownsHandle: true);
    }

    internal static SafeFileHandle OpenDirectoryHandleAt(SafeFileHandle parentHandle, string relativePath)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            int descriptor = PInvokeOpenAt(parentFd, relativePath, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny, 0);
            if (descriptor < 0)
            {
                throw new IOException(
                    $"macOS could not open directory handle for '{relativePath}' relative to parent descriptor.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }
            return new SafeFileHandle(descriptor, ownsHandle: true);
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static void MkdirAt(SafeFileHandle parentHandle, string relativePath, int mode)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            if (PInvokeMkdirAt(parentFd, relativePath, (uint)mode) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not mkdir '{relativePath}' relative to parent descriptor.");
            }
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static bool IsDirectoryEmptyDescriptor(SafeFileHandle dirHandle)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }
            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }
                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is not ("." or ".."))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }
    }

    internal static List<(string FullPath, string RelativePath)> EnumerateDirectoryTreeNoFollow(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDirectory));
        using SafeFileHandle rootHandle = OpenDirectoryHandle(fullRoot);
        RequirePathStillNamesHandle(rootHandle, fullRoot);
        var results = new List<(string FullPath, string RelativePath)>();
        EnumerateDirectoryTreeNoFollowDescriptor(rootHandle, fullRoot, string.Empty, results);
        return results;
    }

    private static void EnumerateDirectoryTreeNoFollowDescriptor(
        SafeFileHandle dirHandle,
        string currentFullPath,
        string relativePrefix,
        List<(string FullPath, string RelativePath)> results)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }
            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }
                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is "." or "..")
                        {
                            continue;
                        }

                        string itemRelPath = string.IsNullOrEmpty(relativePrefix) ? name : Path.Combine(relativePrefix, name);
                        string itemFullPath = Path.Combine(currentFullPath, name);

                        if (entry->d_type == 10 /* DT_LNK */)
                        {
                            throw new IOException($"Die Eingabe enthält einen symbolischen Link: {itemFullPath}");
                        }

                        bool isDirectory = entry->d_type == 4 /* DT_DIR */;
                        bool isRegular = entry->d_type == 8 /* DT_REG */;

                        if (entry->d_type == 0 /* DT_UNKNOWN */ || (!isDirectory && !isRegular))
                        {
                            if (FStatAt(fd, name, out DarwinStat status, 0x0020 /* AT_SYMLINK_NOFOLLOW */) == 0)
                            {
                                uint fileType = (uint)(status.Mode & 0xF000 /* S_IFMT */);
                                if (fileType == 0xA000 /* S_IFLNK */)
                                {
                                    throw new IOException($"Die Eingabe enthält einen symbolischen Link: {itemFullPath}");
                                }
                                isDirectory = fileType == 0x4000 /* S_IFDIR */;
                                isRegular = fileType == 0x8000 /* S_IFREG */;
                            }
                        }

                        if (isDirectory)
                        {
                            int subFd = PInvokeOpenAt(fd, name, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny, 0);
                            if (subFd < 0)
                            {
                                int err = Marshal.GetLastPInvokeError();
                                throw new IOException(
                                    $"macOS could not open subdirectory '{itemFullPath}' without following symlinks.",
                                    new Win32Exception(err));
                            }
                            using (var subHandle = new SafeFileHandle(subFd, ownsHandle: true))
                            {
                                EnumerateDirectoryTreeNoFollowDescriptor(subHandle, itemFullPath, itemRelPath, results);
                            }
                        }
                        else if (isRegular)
                        {
                            results.Add((itemFullPath, itemRelPath));
                        }
                        else
                        {
                            throw new IOException($"Eingabe ist weder eine reguläre Datei noch ein Verzeichnis: {itemFullPath}");
                        }
                    }
                }
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }
    }

    internal static void DeleteDirectoryContentsDescriptor(SafeFileHandle dirHandle)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }
            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }
                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is "." or "..")
                        {
                            continue;
                        }

                        bool isDirectory = entry->d_type == 4 /* DT_DIR */;
                        if (entry->d_type == 0 /* DT_UNKNOWN */)
                        {
                            if (FStatAt(fd, name, out DarwinStat status, 0x0020 /* AT_SYMLINK_NOFOLLOW */) == 0)
                            {
                                isDirectory = (status.Mode & 0xF000 /* S_IFMT */) == 0x4000 /* S_IFDIR */;
                            }
                        }

                        if (isDirectory)
                        {
                            int subFd = PInvokeOpenAt(fd, name, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny, 0);
                            if (subFd >= 0)
                            {
                                using (var subHandle = new SafeFileHandle(subFd, ownsHandle: true))
                                {
                                    DeleteDirectoryContentsDescriptor(subHandle);
                                }
                            }
                            if (PInvokeUnlinkAt(fd, name, 0x0080 /* AT_REMOVEDIR */) != 0)
                            {
                                int err = Marshal.GetLastPInvokeError();
                                if (err != 2 /* ENOENT */)
                                {
                                    throw new Win32Exception(err, $"Could not remove directory '{name}'.");
                                }
                            }
                        }
                        else
                        {
                            if (PInvokeUnlinkAt(fd, name, 0) != 0)
                            {
                                int err = Marshal.GetLastPInvokeError();
                                if (err != 2 /* ENOENT */)
                                {
                                    throw new Win32Exception(err, $"Could not unlink entry '{name}'.");
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }
    }

    internal static long GetFreeDiskSpaceBytes(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (StatVfs(path, out DarwinStatVfs stat) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not stat filesystem at '{path}'.");
        }
        return checked((long)(stat.f_bavail * stat.f_frsize));
    }

    internal static MacFileIdentity GetIdentityAt(SafeFileHandle parentHandle, string relativePath)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            // 0x0020 is AT_SYMLINK_NOFOLLOW on macOS
            if (FStatAt(parentFd, relativePath, out DarwinStat status, 0x0020) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not inspect '{relativePath}' relative to directory descriptor.");
            }
            return new MacFileIdentity(status.Device, status.Inode, status.LinkCount, status.Mode, status.Size);
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static void RenameAt(SafeFileHandle fromDirHandle, string fromPath, SafeFileHandle toDirHandle, string toPath)
    {
        ArgumentNullException.ThrowIfNull(fromDirHandle);
        ArgumentNullException.ThrowIfNull(toDirHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(fromPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(toPath);

        bool fromAdded = false;
        bool toAdded = false;
        try
        {
            fromDirHandle.DangerousAddRef(ref fromAdded);
            toDirHandle.DangerousAddRef(ref toAdded);
            int fromFd = checked((int)fromDirHandle.DangerousGetHandle());
            int toFd = checked((int)toDirHandle.DangerousGetHandle());
            if (PInvokeRenameAt(fromFd, fromPath, toFd, toPath) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS renameat failed from '{fromPath}' to '{toPath}'.");
            }
        }
        finally
        {
            if (toAdded) toDirHandle.DangerousRelease();
            if (fromAdded) fromDirHandle.DangerousRelease();
        }
    }

    internal static void RenameAtExclusive(SafeFileHandle fromDirHandle, string fromPath, SafeFileHandle toDirHandle, string toPath)
    {
        ArgumentNullException.ThrowIfNull(fromDirHandle);
        ArgumentNullException.ThrowIfNull(toDirHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(fromPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(toPath);

        bool fromAdded = false;
        bool toAdded = false;
        try
        {
            fromDirHandle.DangerousAddRef(ref fromAdded);
            toDirHandle.DangerousAddRef(ref toAdded);
            int fromFd = checked((int)fromDirHandle.DangerousGetHandle());
            int toFd = checked((int)toDirHandle.DangerousGetHandle());
            // 0x00000004 is RENAME_EXCL on macOS
            if (PInvokeRenameAtxNp(fromFd, fromPath, toFd, toPath, 0x00000004) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS renameatx_np(RENAME_EXCL) failed from '{fromPath}' to '{toPath}'.");
            }
        }
        finally
        {
            if (toAdded) toDirHandle.DangerousRelease();
            if (fromAdded) fromDirHandle.DangerousRelease();
        }
    }

    internal static void UnlinkAt(SafeFileHandle parentHandle, string relativePath, int flags = 0)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            if (PInvokeUnlinkAt(parentFd, relativePath, flags) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not unlink '{relativePath}' relative to directory descriptor.");
            }
        }
        finally
        {
            if (added) parentHandle.DangerousRelease();
        }
    }

    internal static void CloseDescriptor(int descriptor)
    {
        if (descriptor >= 0)
        {
            Close(descriptor);
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int fd);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int FcntlNoArgument(int descriptor, int command);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fclonefileat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FCloneFileAt(int sourceDescriptor, int destinationDirectoryDescriptor, string destinationFileName, uint flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int descriptor, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstatat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FStatAt(int dirfd, string path, out DarwinStat status, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int LStat(string path, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "realpath", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint RealPath(string path, nint resolvedPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "free")]
    private static partial void Free(nint pointer);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeOpenAt(int dirfd, string path, int flags, int mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "mkdirat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeMkdirAt(int dirfd, string path, uint mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "renameat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeRenameAt(int fromDirFd, string fromPath, int toDirFd, string toPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "renameatx_np", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeRenameAtxNp(int fromDirFd, string fromPath, int toDirFd, string toPath, uint flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "unlinkat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeUnlinkAt(int dirfd, string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "statvfs", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int StatVfs(string path, out DarwinStatVfs buf);
}

[StructLayout(LayoutKind.Sequential)]
internal struct DarwinStatVfs
{
    public ulong f_bsize;
    public ulong f_frsize;
    public uint f_blocks;
    public uint f_bfree;
    public uint f_bavail;
    public uint f_files;
    public uint f_ffree;
    public uint f_favail;
    public ulong f_fsid;
    public ulong f_flag;
    public ulong f_namemax;
}

internal readonly record struct MacFileIdentity(int Device, ulong Inode, ushort LinkCount, ushort Mode, long Size)
{
    internal bool SameObject(MacFileIdentity other) => Device == other.Device && Inode == other.Inode;
}

internal static partial class NativePathResolver
{
    internal static string ResolveExistingPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return MacSafeFileSystem.ResolveExistingRealPath(path);
    }

    internal static string ResolveFinalDosPath(SafeFileHandle handle) =>
        throw new PlatformNotSupportedException(
            "Descriptor-only pathname recovery is intentionally unavailable on macOS. Pass the already no-follow-opened expected path and compare file identity instead.");

    internal static string RequireCanonicalFilePath(SafeFileHandle handle, string expectedPath, string label)
    {
        string expected = Path.GetFullPath(expectedPath);
        MacSafeFileSystem.RequirePathStillNamesHandle(handle, expected);
        return expected;
    }
}

internal static partial class MacCodeSignature
{
    private const uint CheckAllArchitectures = 1U << 0;
    private const uint CheckNestedCode = 1U << 3;
    private const uint StrictValidate = 1U << 4;
    private const uint Utf8Encoding = 0x08000100;
    private const string TeamMetadataKey = "KeepVaultAppleTeamIdentifier";

    internal static MacSignatureInfo Check(string path, bool nestedBundle = false)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return new MacSignatureInfo(SignatureState.Missing, null, "Apple code-signature validation is available only on macOS.");
        }

        string? team = typeof(MacCodeSignature).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, TeamMetadataKey, StringComparison.Ordinal))
            ?.Value;
        if (string.IsNullOrWhiteSpace(team) || team.Any(character => !(char.IsAsciiLetterOrDigit(character))))
        {
            return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, null, "The pinned Apple Team ID is missing or invalid.");
        }

        nint url = 0;
        nint code = 0;
        nint requirementText = 0;
        nint requirement = 0;
        nint errors = 0;
        byte[] utf8Path = Encoding.UTF8.GetBytes(Path.GetFullPath(path));
        byte[] requirementBytes = Encoding.UTF8.GetBytes($"anchor apple generic and certificate leaf[subject.OU] = \"{team}\"");
        try
        {
            url = CFURLCreateFromFileSystemRepresentation(0, utf8Path, checked((nint)utf8Path.Length), false);
            if (url == 0)
            {
                return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, "CoreFoundation could not create the code URL.");
            }

            int status = SecStaticCodeCreateWithPath(url, 0, out code);
            if (status != 0 || code == 0)
            {
                return new MacSignatureInfo(SignatureState.Missing, team, $"SecStaticCodeCreateWithPath failed with OSStatus {status}.");
            }

            requirementText = CFStringCreateWithBytes(0, requirementBytes, checked((nint)requirementBytes.Length), Utf8Encoding, false);
            if (requirementText == 0)
            {
                return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, "CoreFoundation could not create the signing requirement.");
            }

            status = SecRequirementCreateWithString(requirementText, 0, out requirement);
            if (status != 0 || requirement == 0)
            {
                return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, $"SecRequirementCreateWithString failed with OSStatus {status}.");
            }

            uint flags = CheckAllArchitectures | StrictValidate | (nestedBundle ? CheckNestedCode : 0U);
            status = SecStaticCodeCheckValidityWithErrors(code, flags, requirement, out errors);
            return status == 0
                ? new MacSignatureInfo(SignatureState.Trusted, team, "Apple code signature, all architectures, and pinned Team ID are valid.")
                : new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, $"Apple code-signature validation failed with OSStatus {status}.");
        }
        finally
        {
            if (errors != 0) CFRelease(errors);
            if (requirement != 0) CFRelease(requirement);
            if (requirementText != 0) CFRelease(requirementText);
            if (code != 0) CFRelease(code);
            if (url != 0) CFRelease(url);
        }
    }

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFURLCreateFromFileSystemRepresentation")]
    private static partial nint CFURLCreateFromFileSystemRepresentation(nint allocator, byte[] bytes, nint length, [MarshalAs(UnmanagedType.I1)] bool isDirectory);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFStringCreateWithBytes")]
    private static partial nint CFStringCreateWithBytes(nint allocator, byte[] bytes, nint length, uint encoding, [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease")]
    private static partial void CFRelease(nint value);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecStaticCodeCreateWithPath")]
    private static partial int SecStaticCodeCreateWithPath(nint path, uint flags, out nint staticCode);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecRequirementCreateWithString")]
    private static partial int SecRequirementCreateWithString(nint text, uint flags, out nint requirement);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecStaticCodeCheckValidityWithErrors")]
    private static partial int SecStaticCodeCheckValidityWithErrors(nint staticCode, uint flags, nint requirement, out nint errors);
}

internal sealed class MacExtractionStaging : IDisposable
{
    private readonly SafeFileHandle _parentHandle;
    private readonly SafeFileHandle _stagingHandle;
    private readonly MacFileIdentity _stagingIdentity;
    public string DestinationPath { get; }
    public string StagingPath { get; }
    public string StagingName { get; }
    public MacFileIdentity StagingIdentity => _stagingIdentity;
    private bool _installed;

    internal static Action? TestHookBeforeInstallRename { get; set; }

    public MacExtractionStaging(string destinationPath)
    {
        DestinationPath = Path.GetFullPath(destinationPath);
        if (File.Exists(DestinationPath))
        {
            throw new InvalidOperationException("Extraction target must be a directory path.");
        }

        string parentDir = Path.GetDirectoryName(DestinationPath) ?? Environment.CurrentDirectory;
        Directory.CreateDirectory(parentDir);
        string canonicalParent = MacSafeFileSystem.ResolveExistingRealPath(parentDir);

        _parentHandle = MacSafeFileSystem.OpenDirectoryHandle(canonicalParent);
        StagingName = $".{Path.GetFileName(DestinationPath)}.{Guid.NewGuid():N}.extract-part";
        StagingPath = Path.Combine(canonicalParent, StagingName);

        bool parentAdded = false;
        bool stagingCreated = false;
        int stagingFd = -1;
        try
        {
            _parentHandle.DangerousAddRef(ref parentAdded);
            int parentFd = checked((int)_parentHandle.DangerousGetHandle());
            // 0x1C0 is POSIX octal 0700 (S_IRWXU: rwx------)
            if (MacSafeFileSystem.PInvokeMkdirAt(parentFd, StagingName, 0x1C0) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not create extraction staging directory.");
            }
            stagingCreated = true;

            stagingFd = MacSafeFileSystem.PInvokeOpenAt(
                parentFd,
                StagingName,
                0x0000 /* O_RDONLY */ | 0x00100000 /* O_DIRECTORY */ | 0x20000000 /* O_NOFOLLOW_ANY */ | 0x01000000 /* O_CLOEXEC */,
                0);
            if (stagingFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not open extraction staging directory descriptor.");
            }

            _stagingHandle = new SafeFileHandle(stagingFd, ownsHandle: true);
            stagingFd = -1; // Transferred ownership
            _stagingIdentity = MacSafeFileSystem.GetIdentity(_stagingHandle);
        }
        catch
        {
            if (stagingFd >= 0)
            {
                MacSafeFileSystem.CloseDescriptor(stagingFd);
            }
            _stagingHandle?.Dispose();
            if (stagingCreated && parentAdded)
            {
                int parentFd = checked((int)_parentHandle.DangerousGetHandle());
                // 0x0080 is AT_REMOVEDIR on macOS
                _ = MacSafeFileSystem.PInvokeUnlinkAt(parentFd, StagingName, 0x0080);
            }
            _parentHandle?.Dispose();
            throw;
        }
        finally
        {
            if (parentAdded)
            {
                _parentHandle.DangerousRelease();
            }
        }
    }

    public void VerifyIdentity()
    {
        MacSafeFileSystem.RequirePathStillNamesHandle(_stagingHandle, StagingPath);
        MacFileIdentity current = MacSafeFileSystem.GetIdentity(_stagingHandle);
        if (current.Device != _stagingIdentity.Device || current.Inode != _stagingIdentity.Inode)
        {
            throw new InvalidOperationException("Extraction staging directory identity changed during extraction.");
        }
    }

    public void Install()
    {
        VerifyIdentity();
        string destName = Path.GetFileName(DestinationPath);

        // Verify that Staging directory entry under parent matches our descriptor before rename
        MacFileIdentity parentStagingIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, StagingName);
        if (!parentStagingIdentity.SameObject(_stagingIdentity))
        {
            throw new InvalidOperationException("Extraction staging directory entry changed before installation.");
        }

        TestHookBeforeInstallRename?.Invoke();

        // Attempt atomic exclusive rename
        try
        {
            MacSafeFileSystem.RenameAtExclusive(_parentHandle, StagingName, _parentHandle, destName);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 17 /* EEXIST */)
        {
            bool parentAdded = false;
            bool removed = false;
            try
            {
                _parentHandle.DangerousAddRef(ref parentAdded);
                int parentFd = checked((int)_parentHandle.DangerousGetHandle());
                int destFd = MacSafeFileSystem.PInvokeOpenAt(
                    parentFd,
                    destName,
                    MacSafeFileSystem.OpenReadOnly | MacSafeFileSystem.OpenDirectory | MacSafeFileSystem.OpenNoFollowAny | MacSafeFileSystem.OpenCloseOnExec,
                    0);
                if (destFd >= 0)
                {
                    using (var existingHandle = new SafeFileHandle(destFd, ownsHandle: true))
                    {
                        if (MacSafeFileSystem.IsDirectoryEmptyDescriptor(existingHandle))
                        {
                            // 0x0080 is AT_REMOVEDIR on macOS
                            if (MacSafeFileSystem.PInvokeUnlinkAt(parentFd, destName, 0x0080) == 0)
                            {
                                removed = true;
                            }
                        }
                    }
                }
            }
            finally
            {
                if (parentAdded)
                {
                    _parentHandle.DangerousRelease();
                }
            }

            if (removed)
            {
                MacSafeFileSystem.RenameAtExclusive(_parentHandle, StagingName, _parentHandle, destName);
            }
            else
            {
                throw new IOException("The extraction target changed or is not empty before installation.", ex);
            }
        }

        // Post-rename identity verification
        MacFileIdentity postRenameIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, destName);
        if (!postRenameIdentity.SameObject(_stagingIdentity))
        {
            // Isolate the foreign tree away from destName so destination is not left corrupted
            string quarantineName = $".keepvault_quarantine_{Guid.NewGuid():N}.extract-mismatch";
            try
            {
                MacSafeFileSystem.RenameAtExclusive(_parentHandle, destName, _parentHandle, quarantineName);
            }
            catch
            {
            }
            throw new InvalidOperationException($"Installed directory identity mismatch after atomic rename. Foreign item isolated under '{quarantineName}'.");
        }

        _installed = true;
    }

    public void Cleanup()
    {
        if (_installed)
        {
            return;
        }

        try
        {
            // Verify that staging handle and parent directory entry still match before deletion
            if (!_stagingHandle.IsInvalid && !_stagingHandle.IsClosed && !_parentHandle.IsInvalid && !_parentHandle.IsClosed)
            {
                MacFileIdentity currentDescriptorIdentity = MacSafeFileSystem.GetIdentity(_stagingHandle);
                if (!currentDescriptorIdentity.SameObject(_stagingIdentity))
                {
                    return; // Descriptor mutated; refuse deletion
                }

                MacFileIdentity parentEntryIdentity;
                try
                {
                    parentEntryIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, StagingName);
                }
                catch
                {
                    return; // Staging directory entry vanished or inaccessible
                }

                if (!parentEntryIdentity.SameObject(_stagingIdentity))
                {
                    return; // Path swapped; refuse recursive deletion of foreign directory!
                }

                // Atomically rename staging directory to a unique private cleanup name in parent
                string cleanupName = $".keepvault_cleanup_{Guid.NewGuid():N}.extract-part";
                try
                {
                    MacSafeFileSystem.RenameAt(_parentHandle, StagingName, _parentHandle, cleanupName);
                }
                catch
                {
                    return;
                }

                // Verify identity of renamed cleanup entry
                MacFileIdentity cleanupIdentity;
                try
                {
                    cleanupIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, cleanupName);
                }
                catch
                {
                    return;
                }

                if (!cleanupIdentity.SameObject(_stagingIdentity))
                {
                    return; // Cleanup entry mismatch! Refuse deletion.
                }

                // Safely remove the isolated cleanup directory descriptor-bound without path-based recursive delete
                try
                {
                    using SafeFileHandle cleanupDirHandle = MacSafeFileSystem.OpenDirectoryHandleAt(_parentHandle, cleanupName);
                    MacFileIdentity currentCleanupIdentity = MacSafeFileSystem.GetIdentity(cleanupDirHandle);
                    if (currentCleanupIdentity.SameObject(_stagingIdentity))
                    {
                        MacSafeFileSystem.DeleteDirectoryContentsDescriptor(cleanupDirHandle);
                    }
                }
                catch
                {
                }

                try
                {
                    bool parentAdded = false;
                    try
                    {
                        _parentHandle.DangerousAddRef(ref parentAdded);
                        int parentFd = checked((int)_parentHandle.DangerousGetHandle());
                        MacSafeFileSystem.PInvokeUnlinkAt(parentFd, cleanupName, 0x0080 /* AT_REMOVEDIR */);
                    }
                    finally
                    {
                        if (parentAdded) _parentHandle.DangerousRelease();
                    }
                }
                catch
                {
                }
            }
        }
        catch
        {
            // best effort non-destructive cleanup
        }
    }

    public void Dispose()
    {
        if (!_installed)
        {
            Cleanup();
        }
        _stagingHandle?.Dispose();
        _parentHandle?.Dispose();
    }
}

internal sealed record MacSignatureInfo(SignatureState State, string? TeamIdentifier, string Message);
