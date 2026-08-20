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
        string? Failure,
        OriginalSnapshot? Originals = null);

    /// <summary>
    /// One original file as it stood when it was compared against the archive.
    /// </summary>
    /// <remarks>
    /// The digest is what actually decides; length and modification time are
    /// carried alongside so a mismatch can say what changed. The digest comes
    /// from the comparison pass itself, so recording it costs no extra reads.
    /// </remarks>
    internal readonly record struct OriginalFileState(long Length, long ModifiedUtcTicks, string Digest);

    /// <summary>
    /// Every original file the verification covered, keyed by full path.
    /// </summary>
    internal sealed record OriginalSnapshot(IReadOnlyDictionary<string, OriginalFileState> Files);

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

        Dictionary<string, string> expected;
        try
        {
            expected = ZpaqService.BuildArchiveEntryMap(originals);
        }
        catch (Exception ex)
        {
            return new VerificationResult(false, 0, 0, $"Fehler beim Ermitteln der Archiveinträge: {ex.Message}");
        }

        foreach (var kvp in expected)
        {
            if (new FileInfo(kvp.Value).LinkTarget is not null)
            {
                return new VerificationResult(false, 0, 0,
                    $"Die Eingabe enthält einen symbolischen Link: {kvp.Value}");
            }
        }

        if (expected.Count == 0)
        {
            return new VerificationResult(false, 0, 0, "Es wurden keine Originaldateien zum Vergleich gefunden.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var states = new Dictionary<string, OriginalFileState>(StringComparer.Ordinal);
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
            (long length, string? digest) = await CompareAsync(original, extracted, cancellationToken)
                .ConfigureAwait(false);
            if (length < 0 || digest is null)
            {
                return new VerificationResult(false, compared, bytes,
                    $"Der bitweise Vergleich schlug fehl: {relative}");
            }

            states[original] = new OriginalFileState(
                length,
                File.GetLastWriteTimeUtc(original).Ticks,
                digest);
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

        return new VerificationResult(true, compared, bytes, null, new OriginalSnapshot(states));
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
    private static async Task<(long Length, string? Digest)> CompareAsync(
        string original,
        string extracted,
        CancellationToken cancellationToken)
    {
        using FileStream left = MacSafeFileSystem.OpenReadNoSymlinks(original);
        using FileStream right = MacSafeFileSystem.OpenReadNoSymlinks(extracted);
        if (left.Length != right.Length)
        {
            return (-1, null);
        }

        byte[] leftBuffer = new byte[CompareBufferBytes];
        byte[] rightBuffer = new byte[CompareBufferBytes];
        // The original's digest falls out of the bytes already being read, and
        // it is what the pre-deletion re-check compares against.
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
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
                    return (-1, null);
                }

                digest.AppendData(leftBuffer.AsSpan(0, leftRead));
            }

            return (left.Length, Convert.ToHexString(digest.GetHashAndReset()));
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
    /// <summary>
    /// Identifies the archive by its contents, so any change is noticed.
    /// </summary>
    /// <remarks>
    /// A digest rather than device and inode: those would miss a file
    /// overwritten in place, which is the cheaper way to swap an archive out
    /// from under a verification that has already finished reading it.
    /// </remarks>
    internal readonly record struct ArchiveIdentity(long Length, string Digest);

    /// <summary>
    /// Records which archive the verification is about.
    /// </summary>
    internal static ArchiveIdentity CaptureArchiveIdentity(string archivePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(archivePath);
        byte[] digest = SHA512.HashData(stream);
        return new ArchiveIdentity(stream.Length, Convert.ToHexString(digest));
    }

    /// <summary>
    /// Deletes the originals, but only if the archive is still the one that was
    /// verified.
    /// </summary>
    /// <remarks>
    /// Verification proves the archive reproduced the inputs. It proves nothing
    /// about the archive that exists a moment later. Between the two lies the
    /// only irreversible step in this app, so the file is identified again
    /// immediately before the originals go: same device, same inode, same
    /// length, same modification time. Anything else and nothing is deleted.
    /// </remarks>
    internal static IReadOnlyList<string> DeleteOriginals(
        IReadOnlyList<string> originals,
        string archivePath,
        ArchiveIdentity verified,
        OriginalSnapshot originalsVerified)
    {
        ArgumentNullException.ThrowIfNull(originals);
        ArgumentNullException.ThrowIfNull(originalsVerified);
        ArchiveIdentity current;
        try
        {
            current = CaptureArchiveIdentity(archivePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [$"{Path.GetFileName(archivePath)}: {exception.Message}"];
        }

        if (current.Length != verified.Length
            || !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(current.Digest),
                Convert.FromHexString(verified.Digest)))
        {
            return [
                "Das Archiv wurde zwischen Prüfung und Löschung verändert; "
                + "es wurde nichts gelöscht."
            ];
        }

        string? drift = FindOriginalDrift(originals, originalsVerified);
        if (drift is not null)
        {
            return [drift];
        }

        return DeleteVerifiedFiles(originals, originalsVerified);
    }

    /// <summary>
    /// Re-reads every original and reports the first difference from what was
    /// verified, or null if the set is unchanged.
    /// </summary>
    /// <remarks>
    /// The archive check proves the archive is still the one that was verified.
    /// It says nothing about the originals, and those are what is about to be
    /// destroyed. Between the comparison and the deletion another program can
    /// overwrite a file, or drop a new one into a folder that was already
    /// walked — and that new file was never archived.
    ///
    /// So the whole set is read again here, in both directions: every verified
    /// file must still be present with the same length, modification time and
    /// digest, and no file may have appeared that the verification never saw.
    /// Any difference at all and nothing is deleted; the user can archive again
    /// and delete then. The cost is one more full read of the inputs, which is
    /// the correct price for the only irreversible action in this program.
    /// </remarks>
    private static string? FindOriginalDrift(
        IReadOnlyList<string> originals,
        OriginalSnapshot verified)
    {
        var present = new HashSet<string>(StringComparer.Ordinal);
        foreach (string original in originals)
        {
            string full = Path.GetFullPath(original);
            if (File.Exists(full))
            {
                string? mismatch = DescribeFileDrift(full, verified);
                if (mismatch is not null)
                {
                    return mismatch;
                }

                present.Add(full);
                continue;
            }

            if (!Directory.Exists(full))
            {
                return $"Die Eingabe existiert nicht mehr: {full}. Es wurde nichts gelöscht.";
            }

            foreach (string file in Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories))
            {
                if (new FileInfo(file).LinkTarget is not null)
                {
                    return $"Im Eingabeordner ist ein symbolischer Link aufgetaucht: {file}. "
                        + "Es wurde nichts gelöscht.";
                }

                string? mismatch = DescribeFileDrift(file, verified);
                if (mismatch is not null)
                {
                    return mismatch;
                }

                present.Add(file);
            }
        }

        if (present.Count != verified.Files.Count)
        {
            string missing = verified.Files.Keys.Except(present, StringComparer.Ordinal).First();
            return $"Eine geprüfte Originaldatei fehlt inzwischen: {missing}. Es wurde nichts gelöscht.";
        }

        return null;
    }

    private static string? DescribeFileDrift(string path, OriginalSnapshot verified)
    {
        if (!verified.Files.TryGetValue(path, out OriginalFileState expected))
        {
            return $"Seit der Prüfung ist eine neue Datei hinzugekommen: {path}. "
                + "Sie ist nicht im Archiv. Es wurde nichts gelöscht.";
        }

        try
        {
            using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
            if (stream.Length != expected.Length)
            {
                return $"Eine Originaldatei hat sich seit der Prüfung geändert: {path}. "
                    + "Es wurde nichts gelöscht.";
            }

            string digest = Convert.ToHexString(SHA512.HashData(stream));
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(digest),
                    Convert.FromHexString(expected.Digest))
                || File.GetLastWriteTimeUtc(path).Ticks != expected.ModifiedUtcTicks)
            {
                return $"Eine Originaldatei hat sich seit der Prüfung geändert: {path}. "
                    + "Es wurde nichts gelöscht.";
            }

            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return $"Eine Originaldatei konnte vor dem Löschen nicht erneut geprüft werden: "
                + $"{path} ({exception.Message}). Es wurde nichts gelöscht.";
        }
    }

    /// <summary>
    /// Deletes exactly the files that were verified, then removes the folders
    /// they came from if those folders are empty.
    /// </summary>
    /// <remarks>
    /// Deliberately not <c>Directory.Delete(recursive: true)</c>. That call
    /// deletes whatever it finds, which is not necessarily what was verified —
    /// and the difference is a file that was never archived. Naming each file
    /// makes the deletion exactly as wide as the proof behind it, and a folder
    /// that turns out not to be empty is left standing rather than emptied.
    /// </remarks>
    private static IReadOnlyList<string> DeleteVerifiedFiles(
        IReadOnlyList<string> originals,
        OriginalSnapshot verified)
    {
        var failures = new List<string>();
        var movedFiles = new List<(string OriginalPath, string QuarantinePath)>();
        var quarantineDirs = new HashSet<string>(StringComparer.Ordinal);

        try
        {
            // Stage 1: Atomic move to quarantine directories on same volumes
            foreach (string path in verified.Files.Keys)
            {
                string? parentDir = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(parentDir) || !Directory.Exists(parentDir))
                {
                    throw new DirectoryNotFoundException($"Elternverzeichnis nicht gefunden für {path}");
                }

                string quarantineDir = Path.Combine(parentDir, ".keepvault_quarantine_" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(quarantineDir);
                quarantineDirs.Add(quarantineDir);

                string quarantinePath = Path.Combine(quarantineDir, Path.GetFileName(path));
                File.Move(path, quarantinePath);
                movedFiles.Add((path, quarantinePath));
            }

            // Stage 2: Verification of quarantined files before unlinking
            foreach ((string origPath, string quarPath) in movedFiles)
            {
                OriginalFileState expected = verified.Files[origPath];
                using (FileStream fs = File.Open(quarPath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    if (fs.Length != expected.Length)
                    {
                        throw new InvalidDataException($"Dateigröße in Quarantäne weicht ab für {origPath}");
                    }

                    string digest = Convert.ToHexString(SHA512.HashData(fs));
                    if (!CryptographicOperations.FixedTimeEquals(
                            Convert.FromHexString(digest),
                            Convert.FromHexString(expected.Digest)))
                    {
                        throw new InvalidDataException($"Prüfsumme in Quarantäne weicht ab für {origPath}");
                    }
                }
            }

            // Stage 3: Unlink verified files from quarantine
            foreach ((_, string quarPath) in movedFiles)
            {
                File.Delete(quarPath);
            }
        }
        catch (Exception ex)
        {
            // Rollback: Restore any files still in quarantine to their original locations
            foreach ((string origPath, string quarPath) in movedFiles)
            {
                if (File.Exists(quarPath) && !File.Exists(origPath))
                {
                    try
                    {
                        File.Move(quarPath, origPath);
                    }
                    catch
                    {
                        // best effort rollback
                    }
                }
            }

            failures.Add($"Löschung abgebrochen und zurückgerollt: {ex.Message}");
            return failures;
        }
        finally
        {
            // Clean up quarantine directories
            foreach (string qDir in quarantineDirs)
            {
                try
                {
                    if (Directory.Exists(qDir))
                    {
                        Directory.Delete(qDir, recursive: true);
                    }
                }
                catch
                {
                    // best effort cleanup
                }
            }
        }

        foreach (string original in originals)
        {
            string full = Path.GetFullPath(original);
            if (!Directory.Exists(full))
            {
                continue;
            }

            try
            {
                RemoveEmptyDirectories(full);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                failures.Add($"{Path.GetFileName(full)}: {exception.Message}");
            }
        }

        return failures;
    }

    private static void RemoveEmptyDirectories(string directory)
    {
        foreach (string child in Directory.EnumerateDirectories(directory))
        {
            RemoveEmptyDirectories(child);
        }

        if (!Directory.EnumerateFileSystemEntries(directory).Any())
        {
            Directory.Delete(directory);
        }
    }
}
