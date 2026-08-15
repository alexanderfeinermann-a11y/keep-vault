using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
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

    internal static FileStream OpenReadWriteNoSymlinks(string path, bool asynchronous, bool requireSingleLink)
    {
        SafeFileHandle handle = OpenHandleNoSymlinks(path, write: true);
        try
        {
            ValidateRegularFile(handle, requireSingleLink, path);
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 1024 * 1024, isAsync: asynchronous);
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
                throw new IOException(
                    "macOS could not create the required descriptor-bound atomic copy-on-write snapshot. "
                    + "The source may be on a different file-system volume from the private app container; "
                    + "Keep Vault refuses a non-atomic fallback.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
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

    [LibraryImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int FcntlNoArgument(int descriptor, int command);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fclonefileat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FCloneFileAt(int sourceDescriptor, int destinationDirectoryDescriptor, string destinationFileName, uint flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int descriptor, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int LStat(string path, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "realpath", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint RealPath(string path, nint resolvedPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "free")]
    private static partial void Free(nint pointer);
}

internal readonly record struct MacFileIdentity(int Device, ulong Inode, ushort LinkCount, ushort Mode, long Size)
{
    internal bool SameObject(MacFileIdentity other) => Device == other.Device && Inode == other.Inode;
}

internal static partial class NativePathResolver
{
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

internal sealed record MacSignatureInfo(SignatureState State, string? TeamIdentifier, string Message);
