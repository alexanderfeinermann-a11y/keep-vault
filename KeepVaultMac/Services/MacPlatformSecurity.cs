using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal static partial class MacSafeFileSystem
{
    private const int OpenReadOnly = 0x0000;
    private const int OpenReadWrite = 0x0002;
    private const int OpenDirectory = 0x00100000;
    private const int OpenCloseOnExec = 0x01000000;
    private const int OpenNoFollowAny = 0x20000000;
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

    private static void StreamCopyDescriptorIntoPrivateDirectory(
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

        int targetFileFd = OpenAt(targetDirectoryDescriptor, destinationFileName, openFlags, 0x180 /* 0600 */);
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
            while (sourceOffset < beforeStat.Size)
            {
                int toRead = checked((int)Math.Min(buffer.Length, beforeStat.Size - sourceOffset));
                nint bytesRead = PRead(sourceDescriptor, buffer, (nuint)toRead, sourceOffset);
                if (bytesRead < 0)
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS pread failed during cross-volume snapshot.");
                }
                if (bytesRead == 0)
                {
                    break;
                }

                nint bytesWritten = PWrite(targetFileFd, buffer, (nuint)bytesRead, sourceOffset);
                if (bytesWritten != bytesRead)
                {
                    throw new IOException("macOS pwrite incomplete during cross-volume snapshot.");
                }

                hashStream.AppendData(buffer, 0, (int)bytesRead);
                sourceOffset += bytesRead;
                totalRead += bytesRead;
            }
            MacSafeFileSystem.FullSync(targetFileHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        byte[] writtenHash = hashStream.GetHashAndReset();

        // Independent second verification pass over source descriptor to detect concurrent mutations
        using var verifyHashStream = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        long verifyOffset = 0;
        try
        {
            while (verifyOffset < beforeStat.Size)
            {
                int toRead = checked((int)Math.Min(buffer.Length, beforeStat.Size - verifyOffset));
                nint bytesRead = PRead(sourceDescriptor, buffer, (nuint)toRead, verifyOffset);
                if (bytesRead < 0)
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS pread verification pass failed.");
                }
                if (bytesRead == 0)
                {
                    break;
                }
                verifyHashStream.AppendData(buffer, 0, (int)bytesRead);
                verifyOffset += bytesRead;
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
    private static partial nint PRead(int descriptor, byte[] buffer, nuint count, long offset);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "pwrite", SetLastError = true)]
    private static partial nint PWrite(int descriptor, byte[] buffer, nuint count, long offset);

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
        internal uint UserId;
        internal uint GroupId;
        internal int SpecialDevice;
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

    internal static void UnlinkAt(SafeFileHandle dirHandle, string path)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int dirFd = checked((int)dirHandle.DangerousGetHandle());
            if (PInvokeUnlinkAt(dirFd, path, 0) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS unlinkat failed for '{path}'.");
            }
        }
        finally
        {
            if (added) dirHandle.DangerousRelease();
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "close", SetLastError = true)]
    internal static partial int CloseDescriptor(int fd);

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

    [LibraryImport("libSystem.B.dylib", EntryPoint = "mkdirat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int MkdirAt(int dirfd, string path, uint mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int OpenAt(int dirfd, string path, int flags, int mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "renameat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int PInvokeRenameAt(int fromDirFd, string fromPath, int toDirFd, string toPath);

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
    private bool _installed;

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
            if (MacSafeFileSystem.MkdirAt(parentFd, StagingName, 0x1C0) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not create extraction staging directory.");
            }
            stagingCreated = true;

            stagingFd = MacSafeFileSystem.OpenAt(
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

        // Attempt atomic exclusive rename
        try
        {
            MacSafeFileSystem.RenameAtExclusive(_parentHandle, StagingName, _parentHandle, destName);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 17 /* EEXIST */)
        {
            if (Directory.Exists(DestinationPath))
            {
                FileAttributes attributes = File.GetAttributes(DestinationPath);
                if ((attributes & FileAttributes.ReparsePoint) == 0 && !Directory.EnumerateFileSystemEntries(DestinationPath).Any())
                {
                    Directory.Delete(DestinationPath);
                    MacSafeFileSystem.RenameAtExclusive(_parentHandle, StagingName, _parentHandle, destName);
                }
                else
                {
                    throw new IOException("The extraction target changed or is not empty before installation.", ex);
                }
            }
            else
            {
                throw new IOException("A file appeared at the extraction target before installation.", ex);
            }
        }

        // Post-rename identity verification
        MacFileIdentity postRenameIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, destName);
        if (!postRenameIdentity.SameObject(_stagingIdentity))
        {
            throw new InvalidOperationException("Installed directory identity mismatch after atomic rename.");
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

                // Safely remove the isolated cleanup directory
                string canonicalParent = MacSafeFileSystem.ResolveExistingRealPath(Path.GetDirectoryName(DestinationPath) ?? Environment.CurrentDirectory);
                string cleanupPath = Path.Combine(canonicalParent, cleanupName);
                if (Directory.Exists(cleanupPath))
                {
                    FileAttributes attributes = File.GetAttributes(cleanupPath);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        Directory.Delete(cleanupPath);
                    }
                    else
                    {
                        Directory.Delete(cleanupPath, recursive: true);
                    }
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
