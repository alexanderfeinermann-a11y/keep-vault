using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

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

    internal static Action? TestHookBeforeRename { get; set; }

    internal static void MarkForDeletion(FileStream stream, string path)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        path = Path.GetFullPath(path);
        string parentDir = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("Parent directory not found for secure deletion target.");

        string canonicalParent = MacSafeFileSystem.ResolveExistingRealPath(parentDir);
        using SafeFileHandle parentHandle = MacSafeFileSystem.OpenDirectoryHandle(canonicalParent);

        string oldName = Path.GetFileName(path);
        string quarantineName = ".keepvault_erase_" + Guid.NewGuid().ToString("N");

        MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, path);

        TestHookBeforeRename?.Invoke();

        // Atomically rename via parent directory descriptor
        MacSafeFileSystem.RenameAt(parentHandle, oldName, parentHandle, quarantineName);

        // Verify that the open file descriptor matches the quarantined directory entry
        MacFileIdentity handleIdentity = MacSafeFileSystem.GetIdentity(stream.SafeFileHandle);
        MacFileIdentity quarantineIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, quarantineName);

        if (!handleIdentity.SameObject(quarantineIdentity))
        {
            // Identity mismatch indicates a race substitution. NEVER unlink the quarantine entry!
            // Attempt descriptor-relative rollback if the original name is free.
            bool restored = false;
            bool oldNameOccupied = false;
            try
            {
                _ = MacSafeFileSystem.GetIdentityAt(parentHandle, oldName);
                oldNameOccupied = true;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 2 /* ENOENT */)
            {
                oldNameOccupied = false;
            }

            if (!oldNameOccupied)
            {
                try
                {
                    MacSafeFileSystem.RenameAt(parentHandle, quarantineName, parentHandle, oldName);
                    restored = true;
                }
                catch
                {
                    restored = false;
                }
            }

            if (restored)
            {
                throw new InvalidOperationException(
                    $"Quarantined file identity mismatch after rename for '{path}'. Foreign item restored to original location; deletion aborted.");
            }
            else
            {
                throw new InvalidOperationException(
                    $"Quarantined file identity mismatch after rename for '{path}'. Original path '{oldName}' is occupied or restore failed. "
                    + $"Foreign item preserved safely in quarantine under '{quarantineName}'; deletion aborted.");
            }
        }

        // Flush and sync descriptor before unlinking
        MacSafeFileSystem.FullSync(stream.SafeFileHandle);

        // Unlink via parent directory descriptor
        MacSafeFileSystem.UnlinkAt(parentHandle, quarantineName);
    }
}
