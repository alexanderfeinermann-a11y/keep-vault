using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// Proves an archive reproduces its inputs byte for byte before any original is
/// deleted.
/// </summary>
/// <remarks>
/// Deleting the only copy of a file on the strength of "the archiver reported
/// success" is not good enough. A compression or encryption bug, a truncated
/// write, a full disk or a silently dropped input would all still report
/// success, and the loss would only be discovered when the archive is finally
/// needed — which for this kind of tool may be years later.
///
/// So the archive is extracted again into a private directory and compared
/// against the originals byte for byte. Only a complete match permits deletion,
/// and the comparison reads the archive that was actually written, not the
/// buffers it was written from.
/// </remarks>
internal sealed class MacOriginalDeletionService
{
    private const int CompareBufferBytes = 1024 * 1024;

    internal sealed record VerificationResult(
        bool Verified,
        int FilesCompared,
        long BytesCompared,
        string? Failure);

    /// <summary>
    /// Compares every file below <paramref name="extractedRoot"/> with its
    /// counterpart among the originals.
    /// </summary>
    /// <remarks>
    /// The check runs in both directions: every original must be present in the
    /// extraction, and the extraction must contain nothing else. A one-way
    /// check would accept an archive that silently dropped a file.
    /// </remarks>
    internal static async Task<VerificationResult> VerifyExtractionAsync(
        IReadOnlyList<string> originals,
        string extractedRoot,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(originals);
        ArgumentException.ThrowIfNullOrWhiteSpace(extractedRoot);

        var expected = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string original in originals)
        {
            string full = Path.GetFullPath(original);
            if (File.Exists(full))
            {
                expected[Path.GetFileName(full)] = full;
            }
            else if (Directory.Exists(full))
            {
                string parent = Path.TrimEndingDirectorySeparator(full);
                foreach (string file in Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories))
                {
                    if (new FileInfo(file).LinkTarget is not null)
                    {
                        return new VerificationResult(false, 0, 0,
                            $"Der Eingabeordner enthält einen symbolischen Link: {file}");
                    }

                    string relative = Path.Combine(
                        Path.GetFileName(parent),
                        Path.GetRelativePath(parent, file));
                    expected[relative] = file;
                }
            }
            else
            {
                return new VerificationResult(false, 0, 0, $"Die Eingabe existiert nicht mehr: {full}");
            }
        }

        if (expected.Count == 0)
        {
            return new VerificationResult(false, 0, 0, "Es wurden keine Originaldateien zum Vergleich gefunden.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        int compared = 0;
        long bytes = 0;
        foreach (string extracted in Directory.EnumerateFiles(extractedRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string relative = Path.GetRelativePath(extractedRoot, extracted);
            if (!expected.TryGetValue(relative, out string? original))
            {
                return new VerificationResult(false, compared, bytes,
                    $"Das Archiv enthält eine unerwartete Datei: {relative}");
            }

            progress?.Report(relative);
            long length = await CompareAsync(original, extracted, cancellationToken).ConfigureAwait(false);
            if (length < 0)
            {
                return new VerificationResult(false, compared, bytes,
                    $"Der bitweise Vergleich schlug fehl: {relative}");
            }

            seen.Add(relative);
            compared++;
            bytes += length;
        }

        if (seen.Count != expected.Count)
        {
            string missing = expected.Keys.Except(seen, StringComparer.Ordinal).First();
            return new VerificationResult(false, compared, bytes,
                $"Das Archiv enthält eine Originaldatei nicht: {missing}");
        }

        return new VerificationResult(true, compared, bytes, null);
    }

    /// <summary>
    /// Compares two files byte for byte, returning the length on a match and
    /// -1 otherwise.
    /// </summary>
    /// <remarks>
    /// A hash comparison would be enough in practice, but comparing the bytes
    /// removes the question entirely and costs nothing here: both files are
    /// being read from disk regardless.
    /// </remarks>
    private static async Task<long> CompareAsync(
        string original,
        string extracted,
        CancellationToken cancellationToken)
    {
        using FileStream left = MacSafeFileSystem.OpenReadNoSymlinks(original);
        using FileStream right = MacSafeFileSystem.OpenReadNoSymlinks(extracted);
        if (left.Length != right.Length)
        {
            return -1;
        }

        byte[] leftBuffer = new byte[CompareBufferBytes];
        byte[] rightBuffer = new byte[CompareBufferBytes];
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int leftRead = await left.ReadAsync(leftBuffer, cancellationToken).ConfigureAwait(false);
                if (leftRead == 0)
                {
                    break;
                }

                await right.ReadExactlyAsync(rightBuffer.AsMemory(0, leftRead), cancellationToken).ConfigureAwait(false);
                if (!leftBuffer.AsSpan(0, leftRead).SequenceEqual(rightBuffer.AsSpan(0, leftRead)))
                {
                    return -1;
                }
            }

            return left.Length;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBuffer);
            CryptographicOperations.ZeroMemory(rightBuffer);
        }
    }

    /// <summary>
    /// Deletes the originals once verification has succeeded.
    /// </summary>
    /// <remarks>
    /// Ordinary deletion, not a secure erase: the point of this option is to
    /// leave only the archive, and the archive's own contents are the same
    /// data. Cryptographic erase remains a separate, explicit action for
    /// destroying a container.
    /// </remarks>
    internal static IReadOnlyList<string> DeleteOriginals(IReadOnlyList<string> originals)
    {
        ArgumentNullException.ThrowIfNull(originals);
        var failures = new List<string>();
        foreach (string original in originals)
        {
            string full = Path.GetFullPath(original);
            try
            {
                if (File.Exists(full))
                {
                    File.Delete(full);
                }
                else if (Directory.Exists(full))
                {
                    Directory.Delete(full, recursive: true);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                failures.Add($"{Path.GetFileName(full)}: {exception.Message}");
            }
        }

        return failures;
    }
}
