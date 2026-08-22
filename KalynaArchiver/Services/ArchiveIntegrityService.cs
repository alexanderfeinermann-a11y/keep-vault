using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KalynaArchiver.Services;

/// <summary>
/// Manages unkeyed dual integrity manifests (.sha3 and .skein) for plain ZPAQ archives.
/// </summary>
/// <remarks>
/// IMPORTANT SECURITY NOTICE:
/// The companion .sha3 (SHA3-512) and .skein (Skein-1024) manifest files provide unkeyed cryptographic
/// checksums designed to detect storage degradation, transmission corruption, and accidental bit rot.
/// Because they are unkeyed hashes without digital signatures or secret-key MACs, they do NOT provide
/// cryptographic origin authenticity or anti-tamper security against an active adversary who has write access
/// to overwrite both the archive and its companion manifest files.
/// Full cryptographic tamper rejection and origin authenticity is provided exclusively by authenticated
/// encrypted containers (.kzpaq) or digital hybrid signatures (.khsig).
/// </remarks>
public sealed class ArchiveIntegrityService
{
    private const int MaxManifestBytes = 4096;
    public static string GetSha3ManifestPath(string archivePath) => $"{archivePath}.sha3";

    public static string GetSkeinManifestPath(string archivePath) => $"{archivePath}.skein";

    public async Task CreateAsync(string archivePath, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(archivePath);
        byte[] sha3;
        byte[] skein;
        await using (FileStream stream =
#if KEEPVAULT_MACOS
            MacSafeFileSystem.OpenReadNoSymlinks(fullPath))
#else
            new(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
#endif
        {
            fullPath = ResolveCanonicalArchivePath(stream, fullPath);
            (sha3, skein) = await IntegrityService.HashStreamAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            await WriteManifestAsync(GetSha3ManifestPath(fullPath), Convert.ToHexString(sha3), cancellationToken).ConfigureAwait(false);
            await WriteManifestAsync(GetSkeinManifestPath(fullPath), Convert.ToHexString(skein), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    public async Task VerifyAsync(string archivePath, CancellationToken cancellationToken)
    {
        using ArchiveIntegrityLease lease = await AcquireVerifiedAsync(archivePath, cancellationToken).ConfigureAwait(false);
    }

    internal async Task CreateFromVerifiedDigestsAsync(
        string archivePath,
        string sha3Hex,
        string skeinHex,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        byte[] sha3 = ParseManifest(sha3Hex, 64, "SHA3-512");
        byte[] skein = ParseManifest(skeinHex, 128, "Skein-1024");
        try
        {
            string fullPath = Path.GetFullPath(archivePath);
            await WriteManifestAsync(
                GetSha3ManifestPath(fullPath),
                Convert.ToHexString(sha3),
                cancellationToken).ConfigureAwait(false);
            await WriteManifestAsync(
                GetSkeinManifestPath(fullPath),
                Convert.ToHexString(skein),
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            DeleteManifests(archivePath);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    internal async Task<ArchiveIntegrityLease> AcquireVerifiedAsync(
        string archivePath,
        CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(archivePath);
        string sha3Path = GetSha3ManifestPath(fullPath);
        string skeinPath = GetSkeinManifestPath(fullPath);
        if (!File.Exists(sha3Path) || !File.Exists(skeinPath))
        {
            throw new InvalidDataException("Plain ZPAQ archive requires both SHA3-512 and Skein-1024 manifests.");
        }

        byte[] expectedSha3 = ParseManifest(await ReadManifestAsync(sha3Path, cancellationToken).ConfigureAwait(false), 64, "SHA3-512");
        byte[] expectedSkein = ParseManifest(await ReadManifestAsync(skeinPath, cancellationToken).ConfigureAwait(false), 128, "Skein-1024");
        byte[] actualSha3 = [];
        byte[] actualSkein = [];
#if KEEPVAULT_MACOS
        MacPrivateFileSnapshot? snapshot = await MacPrivateFileSnapshot
            .CaptureAsync(fullPath, cancellationToken)
            .ConfigureAwait(false);
        FileStream? stream = snapshot.Stream;
#else
        FileStream? stream = new(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
#endif
        try
        {
#if KEEPVAULT_MACOS
            string resolvedPath = snapshot.SnapshotPath;
#else
            string resolvedPath = ResolveCanonicalArchivePath(stream, fullPath);
#endif
            (actualSha3, actualSkein) = await IntegrityService.HashStreamAsync(stream, cancellationToken).ConfigureAwait(false);
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3, actualSha3);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkein, actualSkein);
            if (!(sha3Matches & skeinMatches))
            {
                throw new InvalidDataException("Plain ZPAQ archive failed its SHA3-512/Skein-1024 dual-integrity check.");
            }

            var lease = new ArchiveIntegrityLease(
                resolvedPath,
                stream,
#if KEEPVAULT_MACOS
                snapshot
#else
                owner: null
#endif
            );
            stream = null;
#if KEEPVAULT_MACOS
            snapshot = null;
#endif
            return lease;
        }
        finally
        {
#if KEEPVAULT_MACOS
            if (snapshot is not null)
            {
                snapshot.Dispose();
                stream = null;
            }
#endif
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }

            CryptographicOperations.ZeroMemory(expectedSha3);
            CryptographicOperations.ZeroMemory(expectedSkein);
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
        }
    }

    public static void DeleteManifests(string archivePath)
    {
        File.Delete(GetSha3ManifestPath(archivePath));
        File.Delete(GetSkeinManifestPath(archivePath));
    }

    private static byte[] ParseManifest(string text, int expectedBytes, string algorithm)
    {
        string normalized = new(text.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.Length != expectedBytes * 2 || normalized.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new InvalidDataException($"Invalid {algorithm} archive manifest.");
        }

        return Convert.FromHexString(normalized);
    }

    private static async Task<string> ReadManifestAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream =
#if KEEPVAULT_MACOS
            MacSafeFileSystem.OpenReadNoSymlinks(path);
#else
            new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
#endif
        if (stream.Length is <= 0 or > MaxManifestBytes)
        {
            throw new InvalidDataException($"Archive integrity manifest has an invalid length: {Path.GetFileName(path)}");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return Encoding.ASCII.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static async Task WriteManifestAsync(string path, string hex, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        string temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.integrity-part");
        byte[] bytes = Encoding.ASCII.GetBytes(hex);
        try
        {
            await using (FileStream output = new(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough))
            {
                await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) is required to request durable media persistence before the atomic move.
                output.Flush(flushToDisk: true);
#if KEEPVAULT_MACOS
                MacSafeFileSystem.FullSync(output.SafeFileHandle);
#endif
#pragma warning restore CA1849
            }

            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            File.Delete(temporaryPath);
        }
    }

    private static string ResolveCanonicalArchivePath(FileStream stream, string expectedPath)
    {
        return NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, expectedPath, "Archive");
    }
}

internal sealed class ArchiveIntegrityLease : IDisposable
{
    private FileStream? _stream;
    private IDisposable? _owner;

    internal ArchiveIntegrityLease(string path, FileStream stream, IDisposable? owner = null)
    {
        Path = path;
        _stream = stream;
        _owner = owner;
    }

    public string Path { get; }

    public void Dispose()
    {
        IDisposable? owner = Interlocked.Exchange(ref _owner, null);
        if (owner is not null)
        {
            _stream = null;
            owner.Dispose();
        }
        else
        {
            Interlocked.Exchange(ref _stream, null)?.Dispose();
        }
    }
}
