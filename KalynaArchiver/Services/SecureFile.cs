using System.IO;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

public static partial class SecureFile
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;

    public static void DeleteIfExists(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        File.Delete(path);
    }

    public static void DestroyPrefixAndDelete(string? path, int prefixBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(prefixBytes);

        byte[] buffer = new byte[prefixBytes];
        using IDisposable bufferLock = SecureMemory.TryLock(buffer);
        RandomNumberGenerator.Fill(buffer);

        try
        {
            using FileStream stream = OpenVerifiedSingleLinkFile(path);
            int count = (int)Math.Min(buffer.Length, stream.Length);
            stream.Position = 0;
            stream.Write(buffer, 0, count);
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        File.Delete(path);
    }

    public static void DestroyPrefixAndSuffixAndDelete(
        string? path,
        int prefixBytes,
        int suffixBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(prefixBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(suffixBytes);

        int bufferLength = Math.Max(prefixBytes, suffixBytes);
        byte[] buffer = new byte[bufferLength];
        using IDisposable bufferLock = SecureMemory.TryLock(buffer);
        try
        {
            using FileStream stream = OpenVerifiedSingleLinkFile(path);

            int prefixCount = (int)Math.Min(prefixBytes, stream.Length);
            RandomNumberGenerator.Fill(buffer.AsSpan(0, prefixCount));
            stream.Position = 0;
            stream.Write(buffer, 0, prefixCount);

            int suffixCount = (int)Math.Min(suffixBytes, stream.Length);
            RandomNumberGenerator.Fill(buffer.AsSpan(0, suffixCount));
            stream.Position = stream.Length - suffixCount;
            stream.Write(buffer, 0, suffixCount);
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        File.Delete(path);
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "FileStream takes ownership of the SafeFileHandle on success; the catch path disposes it before rethrowing.")]
    private static FileStream OpenVerifiedSingleLinkFile(string path)
    {
        string fullPath = Path.GetFullPath(path);
        FileAttributes attributes = File.GetAttributes(fullPath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("Secure deletion refuses directories and reparse-point files.");
        }

        SafeFileHandle handle = File.OpenHandle(
            fullPath,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            FileOptions.WriteThrough);
        try
        {
            ValidateSingleLinkHandle(handle, fullPath);

            return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 4096, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "FileStream takes ownership of the SafeFileHandle on success; the catch path disposes it before rethrowing.")]
    internal static FileStream OpenVerifiedSingleLinkFileForDestruction(string path)
    {
        string fullPath = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFileForDestruction(
            fullPath,
            GenericRead | GenericWrite | DeleteAccess,
            0,
            0,
            OpenExisting,
            FileAttributeNormal
                | FileFlagWriteThrough
                | FileFlagOverlapped
                | FileFlagOpenReparsePoint
                | FileFlagSequentialScan,
            0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new Win32Exception(error, "Could not exclusively open the secure-delete target.");
        }

        try
        {
            ValidateSingleLinkHandle(handle, fullPath);
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 4096, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static void MarkForDeletion(FileStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var disposition = new FileDispositionInformation { DeleteFile = 1 };
        if (!SetFileInformationByHandle(
                stream.SafeFileHandle,
                FileInformationClass.FileDispositionInfo,
                ref disposition,
                checked((uint)Marshal.SizeOf<FileDispositionInformation>())))
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Could not mark the securely corrupted file for deletion.");
        }
    }

    private static void ValidateSingleLinkHandle(SafeFileHandle handle, string fullPath)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Could not inspect the secure-delete target handle.");
        }

        if ((information.FileAttributes
                & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0
            || information.NumberOfLinks != 1)
        {
            throw new IOException(
                "Secure deletion refuses reparse points and files with multiple hard links.");
        }

        _ = NativePathResolver.RequireCanonicalFilePath(handle, fullPath, "Secure-delete target");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public NativeFileTime CreationTime;
        public NativeFileTime LastAccessTime;
        public NativeFileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        public int DeleteFile;
    }

    private enum FileInformationClass
    {
        FileDispositionInfo = 4,
    }

    [LibraryImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial SafeFileHandle CreateFileForDestruction(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInformationClass fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);
}
