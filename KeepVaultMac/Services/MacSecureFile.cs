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
    internal static Action? TestHookBeforeRollback { get; set; }

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
            TestHookBeforeRollback?.Invoke();
            // Identity mismatch indicates a race substitution. NEVER unlink the quarantine entry!
            // Attempt descriptor-relative exclusive rollback if the original name is free.
            bool restored = false;
            try
            {
                MacSafeFileSystem.RenameAtExclusive(parentHandle, quarantineName, parentHandle, oldName);
                restored = true;
            }
            catch
            {
                restored = false;
            }

            if (restored)
            {
                throw new InvalidOperationException(
                    $"Quarantined file identity mismatch after rename for '{path}'. Foreign item restored to original location; deletion aborted.");
            }
            else
            {
                string fullQuarantinePath = Path.Combine(canonicalParent, quarantineName);
                throw new InvalidOperationException(
                    $"Quarantined file identity mismatch after rename for '{path}'. Original path '{oldName}' is occupied or restore failed. "
                    + $"Foreign item preserved safely in quarantine under '{fullQuarantinePath}'; deletion aborted.");
            }
        }

        // Flush and sync descriptor before unlinking
        MacSafeFileSystem.FullSync(stream.SafeFileHandle);

        // Move to a unique, private cleanup subdirectory inside parent directory to eliminate any final race window
        string cleanDirName = ".keepvault_clean_" + Guid.NewGuid().ToString("N");
        bool cleanDirCreated = false;
        bool targetMoved = false;
        bool targetUnlinked = false;
        try
        {
            MacSafeFileSystem.MkdirAt(parentHandle, cleanDirName, 0x1C0 /* 0700 */);
            cleanDirCreated = true;
            using (SafeFileHandle cleanDirHandle = MacSafeFileSystem.OpenDirectoryHandleAt(parentHandle, cleanDirName))
            {
                const string cleanTargetName = "target";
                MacSafeFileSystem.RenameAtExclusive(parentHandle, quarantineName, cleanDirHandle, cleanTargetName);
                targetMoved = true;

                MacFileIdentity cleanEntryIdentity = MacSafeFileSystem.GetIdentityAt(cleanDirHandle, cleanTargetName);
                if (!cleanEntryIdentity.SameObject(handleIdentity))
                {
                    throw new InvalidOperationException(
                        $"Final cleanup entry identity mismatch; deletion aborted. Target preserved safely in '{Path.Combine(canonicalParent, cleanDirName, cleanTargetName)}'.");
                }

                MacSafeFileSystem.UnlinkAt(cleanDirHandle, cleanTargetName);
                targetUnlinked = true;
            }
        }
        finally
        {
            if (cleanDirCreated)
            {
                if (targetMoved && !targetUnlinked)
                {
                    try
                    {
                        using SafeFileHandle cleanDirHandle = MacSafeFileSystem.OpenDirectoryHandleAt(parentHandle, cleanDirName);
                        const string cleanTargetName = "target";
                        MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(cleanDirHandle, cleanTargetName);
                        if (entryIdentity.SameObject(handleIdentity))
                        {
                            MacSafeFileSystem.UnlinkAt(cleanDirHandle, cleanTargetName);
                            targetUnlinked = true;
                        }
                    }
                    catch
                    {
                    }
                }

                if (!targetMoved || targetUnlinked)
                {
                    try
                    {
                        MacSafeFileSystem.UnlinkAt(parentHandle, cleanDirName, 0x0080 /* AT_REMOVEDIR */);
                    }
                    catch
                    {
                    }
                }
            }
        }
    }
}
