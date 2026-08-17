using System.IO;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

public sealed class CryptographicEraseService
{
    private const int CorruptionBytes = 1024 * 1024;
    private readonly KalynaContainerService _containers = new();

    public async Task<CryptoEraseAnalysis> AnalyzeAsync(string path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new CryptoEraseAnalysis(false, false, "File not found.", HardwareEraseNotice(path));
        }

        bool encrypted;
        try
        {
            _ = await _containers.ReadContainerInfoAsync(path, cancellationToken).ConfigureAwait(false);
            encrypted = true;
        }
        catch (InvalidDataException)
        {
            encrypted = false;
        }

        string message = encrypted
            ? "Encrypted v8 container detected. Cryptographic erase can delete the encrypted container, but hardware per-file secure erase is not guaranteed on SSDs."
            : "This is not an encrypted v8 container. Plain files cannot be cryptographically erased by deleting a key.";
        return new CryptoEraseAnalysis(true, encrypted, message, HardwareEraseNotice(path));
    }

    public async Task<CryptoEraseResult> EraseEncryptedContainerAsync(string path, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            throw new FileNotFoundException("Die Datei wurde nicht gefunden.", path);
        }

        string fullPath = Path.GetFullPath(path);
        await using (FileStream stream = SecureFile.OpenVerifiedSingleLinkFileForDestruction(fullPath))
        {
            try
            {
                _ = await _containers.ReadContainerInfoAsync(stream, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidDataException ex)
            {
                throw new InvalidOperationException(
                    "Cryptographic erase is only available for a valid encrypted .kzpaq container.",
                    ex);
            }

            // Remove recoverable parity before touching the container. If this step fails,
            // abort with the still-intact container instead of leaving a header that the
            // surviving RS sidecar could reconstruct after a crash.
            progress?.Report("Overwriting and deleting recovery sidecar ...");
            RecoveryService.SecureDeleteRecoverySidecar(fullPath);
            progress?.Report("Corrupting encrypted container header with write-through I/O ...");
            await CorruptContainerStartAsync(stream, cancellationToken).ConfigureAwait(false);

            // The handle was opened with DELETE access and without sharing. Marking that
            // same file object for deletion closes the path-swap window between corruption
            // and deletion; the file disappears when this exclusive handle is disposed.
            progress?.Report("Marking the securely corrupted container for deletion ...");
#if KEEPVAULT_MACOS
            SecureFile.MarkForDeletion(stream, fullPath);
#else
            SecureFile.MarkForDeletion(stream);
#endif
        }

        return new CryptoEraseResult(fullPath, true, "Encrypted container was corrupted and deleted through the same exclusive file handle. SSD remanence cannot be ruled out per file; destroy saved/printed key sheets separately.");
    }

    private static async Task CorruptContainerStartAsync(FileStream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[CorruptionBytes];
        using IDisposable bufferLock = SecureMemory.TryLock(buffer);
        RandomNumberGenerator.Fill(buffer);
        try
        {
            int count = (int)Math.Min(buffer.Length, stream.Length);
            stream.Position = 0;
            await stream.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) is the durability boundary before deletion.
            stream.Flush(flushToDisk: true);
#pragma warning restore CA1849
#if KEEPVAULT_MACOS
            MacSafeFileSystem.FullSync(stream.SafeFileHandle);
#endif
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static string HardwareEraseNotice(string path)
    {
        string root = string.Empty;
        try
        {
            root = string.IsNullOrWhiteSpace(path)
                ? string.Empty
                : Path.GetPathRoot(Path.GetFullPath(path)) ?? string.Empty;
        }
        catch
        {
        }

        string drive = string.IsNullOrWhiteSpace(root) ? "the target drive" : root;
        return $"Hardware SSD secure erase is not a per-file operation on {drive}. Real hardware erase means whole-drive ATA Secure Erase or NVMe Format/Crypto Erase via firmware/vendor/admin tooling, after backup and explicit operator confirmation.";
    }
}

public sealed record CryptoEraseAnalysis(bool Exists, bool IsEncryptedContainer, string Message, string HardwareNotice);

public sealed record CryptoEraseResult(string Path, bool Deleted, string Message);
