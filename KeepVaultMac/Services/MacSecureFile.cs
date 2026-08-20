using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

public static partial class SecureFile
{
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
        DestroyPrefixAndSuffixAndDelete(path, prefixBytes, prefixBytes);
    }

    public static void DestroyPrefixAndSuffixAndDelete(string? path, int prefixBytes, int suffixBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(prefixBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(suffixBytes);
        byte[] buffer = new byte[Math.Max(prefixBytes, suffixBytes)];
        using IDisposable memoryLock = SecureMemory.TryLock(buffer);
        try
        {
            using FileStream stream = OpenVerifiedSingleLinkFileForDestruction(path);
            int prefixLength = checked((int)Math.Min(prefixBytes, stream.Length));
            RandomNumberGenerator.Fill(buffer.AsSpan(0, prefixLength));
            stream.Position = 0;
            stream.Write(buffer, 0, prefixLength);

            int suffixLength = checked((int)Math.Min(suffixBytes, stream.Length));
            RandomNumberGenerator.Fill(buffer.AsSpan(0, suffixLength));
            stream.Position = stream.Length - suffixLength;
            stream.Write(buffer, 0, suffixLength);
            stream.Flush(flushToDisk: true);
            MacSafeFileSystem.FullSync(stream.SafeFileHandle);
            MarkForDeletion(stream, Path.GetFullPath(path));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static FileStream OpenVerifiedSingleLinkFileForDestruction(string path)
    {
        string fullPath = Path.GetFullPath(path);
        FileStream stream = MacSafeFileSystem.OpenReadWriteNoSymlinks(fullPath, requireSingleLink: true);
        try
        {
            _ = NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, fullPath, "Secure-delete target");
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    internal static void MarkForDeletion(FileStream stream, string path)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        path = Path.GetFullPath(path);
        string parentDir = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("Parent directory not found for secure deletion target.");

        string quarantinePath = Path.Combine(parentDir, ".keepvault_erase_" + Guid.NewGuid().ToString("N"));

        MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, path);
        if (Rename(path, quarantinePath) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not atomically quarantine the file for secure deletion.");
        }

        try
        {
            MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, quarantinePath);
            MacSafeFileSystem.FullSync(stream.SafeFileHandle);
            if (Unlink(quarantinePath) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not unlink the securely quarantined file.");
            }
        }
        catch
        {
            // If unlinking the quarantine path failed, attempt to clean up or leave in quarantine
            _ = Unlink(quarantinePath);
            throw;
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "rename", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Rename(string oldPath, string newPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "unlink", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Unlink(string path);
}
