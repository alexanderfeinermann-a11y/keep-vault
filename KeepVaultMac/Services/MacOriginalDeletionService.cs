using System.ComponentModel;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

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
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        FileStream archiveStream;
        MacFileIdentity archiveIdentity;
        try
        {
            archiveStream = MacSafeFileSystem.OpenReadNoSymlinks(archivePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [$"{Path.GetFileName(archivePath)}: {exception.Message}"];
        }

        using (archiveStream)
        {
            try
            {
                archiveIdentity = MacSafeFileSystem.GetIdentity(archiveStream.SafeFileHandle);
                byte[] digest = SHA512.HashData(archiveStream);
                if (archiveStream.Length != verified.Length
                    || !CryptographicOperations.FixedTimeEquals(
                        digest,
                        Convert.FromHexString(verified.Digest)))
                {
                    return [
                        "Das Archiv wurde zwischen Prüfung und Löschung verändert; "
                        + "es wurde nichts gelöscht."
                    ];
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return [$"{Path.GetFileName(archivePath)}: {exception.Message}"];
            }

            string? drift = FindOriginalDrift(originals, originalsVerified);
            if (drift is not null)
            {
                return [drift];
            }

            return DeleteVerifiedFiles(originals, originalsVerified, archivePath, archiveStream, archiveIdentity, verified);
        }
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

            List<(string FullPath, string RelativePath)> treeFiles;
            try
            {
                treeFiles = MacSafeFileSystem.EnumerateDirectoryTreeNoFollow(full);
            }
            catch (Exception ex)
            {
                return $"Fehler bei der Sicherheitsprüfung des Eingabeordners: {full} ({ex.Message}). Es wurde nichts gelöscht.";
            }

            foreach (var (file, _) in treeFiles)
            {
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
        OriginalSnapshot verified,
        string archivePath,
        FileStream archiveStream,
        MacFileIdentity archiveIdentity,
        ArchiveIdentity verifiedArchive)
    {
        var failures = new List<string>();
        var quarantined = new List<QuarantinedItem>();
        var parentContexts = new Dictionary<string, QuarantineParentContext>(StringComparer.Ordinal);

        try
        {
            // Stage 1: Atomic move to private quarantine directories per canonical parent directory
            foreach (string path in verified.Files.Keys)
            {
                string? parentDir = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(parentDir) || !Directory.Exists(parentDir))
                {
                    throw new DirectoryNotFoundException($"Elternverzeichnis nicht gefunden für {path}");
                }

                string canonicalParent = MacSafeFileSystem.ResolveExistingRealPath(parentDir);
                if (!parentContexts.TryGetValue(canonicalParent, out QuarantineParentContext? context))
                {
                    using SafeFileHandle parentHandle = MacSafeFileSystem.OpenDirectoryHandle(canonicalParent);
                    MacFileIdentity parentIdentity = MacSafeFileSystem.GetIdentity(parentHandle);
                    string qDirName = ".keepvault_quarantine_" + Guid.NewGuid().ToString("N");
                    string qDirPath = Path.Combine(canonicalParent, qDirName);
                    bool qDirCreated = false;
                    SafeFileHandle? qDirHandle = null;
                    try
                    {
                        MacSafeFileSystem.MkdirAt(parentHandle, qDirName, 0x1C0 /* 0700 */);
                        qDirCreated = true;

                        qDirHandle = MacSafeFileSystem.OpenDirectoryHandleAt(parentHandle, qDirName);
                        context = new QuarantineParentContext(canonicalParent, qDirPath, qDirName, qDirHandle, parentIdentity);
                        parentContexts.Add(canonicalParent, context);
                        qDirHandle = null;   // Ownership transferred to context
                        qDirCreated = false; // Context now owns directory
                    }
                    finally
                    {
                        qDirHandle?.Dispose();
                        if (qDirCreated)
                        {
                            try
                            {
                                MacSafeFileSystem.UnlinkAt(parentHandle, qDirName, 0x0080 /* AT_REMOVEDIR */);
                            }
                            catch
                            {
                                // best-effort removal of newly created unreferenced directory
                            }
                        }
                    }
                }

                string fileName = Path.GetFileName(path);
                MacFileIdentity sourceIdentity;
                using (SafeFileHandle parentHandle = MacSafeFileSystem.OpenDirectoryHandle(canonicalParent))
                {
                    sourceIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, fileName);
                    // Atomically move from parent directory to quarantine directory
                    MacSafeFileSystem.RenameAt(parentHandle, fileName, context.QuarantineDirHandle, fileName);
                }

                // Verify identity after move immediately
                MacFileIdentity qIdentity = MacSafeFileSystem.GetIdentityAt(context.QuarantineDirHandle, fileName);
                if (!qIdentity.SameObject(sourceIdentity))
                {
                    throw new InvalidOperationException($"Quarantänisierte Datei weicht vom Original ab für {path}");
                }

                // Register rollback entry immediately following successful rename and proven identity
                var item = new QuarantinedItem(path, fileName, context, qIdentity);
                quarantined.Add(item);
            }

            // Stage 2: Descriptor-bound verification of quarantined files before committing to unlink
            foreach (var item in quarantined)
            {
                OriginalFileState expected = verified.Files[item.OriginalPath];
                string quarPath = Path.Combine(item.ParentContext.QuarantineDirectoryPath, item.FileName);

                using (FileStream fs = MacSafeFileSystem.OpenReadNoSymlinks(quarPath))
                {
                    MacFileIdentity streamIdentity = MacSafeFileSystem.GetIdentity(fs.SafeFileHandle);
                    if (!streamIdentity.SameObject(item.Identity))
                    {
                        throw new InvalidDataException($"Identität in Quarantäne weicht ab für {item.OriginalPath}");
                    }

                    if (fs.Length != expected.Length)
                    {
                        throw new InvalidDataException($"Dateigröße in Quarantäne weicht ab für {item.OriginalPath}");
                    }

                    string digest = Convert.ToHexString(SHA512.HashData(fs));
                    if (!CryptographicOperations.FixedTimeEquals(
                            Convert.FromHexString(digest),
                            Convert.FromHexString(expected.Digest)))
                    {
                        throw new InvalidDataException($"Prüfsumme in Quarantäne weicht ab für {item.OriginalPath}");
                    }
                }

                // Verify entry identity under directory handle
                MacFileIdentity dirEntryIdentity = MacSafeFileSystem.GetIdentityAt(item.ParentContext.QuarantineDirHandle, item.FileName);
                if (!dirEntryIdentity.SameObject(item.Identity))
                {
                    throw new InvalidDataException($"Verzeichniseintrag in Quarantäne wurde modifiziert für {item.OriginalPath}");
                }
            }

            // Stage 2.5: Descriptor-bound verification of archive before irreversible commit
            MacSafeFileSystem.RequirePathStillNamesHandle(archiveStream.SafeFileHandle, archivePath);
            MacFileIdentity currentPathIdentity = MacSafeFileSystem.GetPathIdentityNoFollow(archivePath);
            if (!currentPathIdentity.SameObject(archiveIdentity))
            {
                throw new InvalidOperationException("Das Archiv wurde vor dem endgültigen Lösch-Commit ausgetauscht.");
            }

            archiveStream.Position = 0;
            byte[] finalArchiveDigest = SHA512.HashData(archiveStream);
            if (archiveStream.Length != verifiedArchive.Length
                || !CryptographicOperations.FixedTimeEquals(
                    finalArchiveDigest,
                    Convert.FromHexString(verifiedArchive.Digest)))
            {
                throw new InvalidOperationException("Das Archiv wurde vor dem endgültigen Lösch-Commit modifiziert.");
            }
        }
        catch (Exception ex)
        {
            // Pre-Commit Rollback: Restore all quarantined files to their original locations exclusively
            var rollbackErrors = new List<string>();
            foreach (var item in quarantined)
            {
                try
                {
                    using SafeFileHandle parentHandle = MacSafeFileSystem.OpenDirectoryHandle(item.ParentContext.CanonicalParentDir);
                    MacFileIdentity reopenedParent = MacSafeFileSystem.GetIdentity(parentHandle);
                    if (!reopenedParent.SameObject(item.ParentContext.ParentIdentity))
                    {
                        rollbackErrors.Add(
                            $"Elternverzeichnis wurde vor Rollback ausgetauscht für {item.OriginalPath}. " +
                            $"Originaldatei verbleibt geschützt in Quarantäne: {Path.Combine(item.ParentContext.QuarantineDirectoryPath, item.FileName)}");
                        continue;
                    }

                    MacFileIdentity currentEntry = MacSafeFileSystem.GetIdentityAt(
                        item.ParentContext.QuarantineDirHandle,
                        item.FileName);
                    if (!currentEntry.SameObject(item.Identity))
                    {
                        rollbackErrors.Add(
                            $"Quarantäneeintrag wurde vor Rollback modifiziert für {item.OriginalPath}. " +
                            $"Originaldatei verbleibt geschützt in Quarantäne: {Path.Combine(item.ParentContext.QuarantineDirectoryPath, item.FileName)}");
                        continue;
                    }

                    bool restored = false;
                    try
                    {
                        MacSafeFileSystem.RenameAtExclusive(item.ParentContext.QuarantineDirHandle, item.FileName, parentHandle, item.FileName);
                        restored = true;
                    }
                    catch (Win32Exception wEx) when (wEx.NativeErrorCode == 17 /* EEXIST */)
                    {
                        restored = false;
                    }

                    if (!restored)
                    {
                        rollbackErrors.Add(
                            $"Originalpfad belegt für {item.OriginalPath}. " +
                            $"Originaldatei verbleibt geschützt in Quarantäne: {Path.Combine(item.ParentContext.QuarantineDirectoryPath, item.FileName)}");
                    }
                }
                catch (Exception moveEx)
                {
                    rollbackErrors.Add(
                        $"Wiederherstellung aus Quarantäne fehlgeschlagen für {item.OriginalPath}: {moveEx.Message}. " +
                        $"Originaldatei verbleibt geschützt in Quarantäne: {Path.Combine(item.ParentContext.QuarantineDirectoryPath, item.FileName)}");
                }
            }

            failures.Add($"Löschung vor dem Commit abgebrochen: {ex.Message}");
            if (rollbackErrors.Count > 0)
            {
                failures.AddRange(rollbackErrors);
            }

            foreach (var ctx in parentContexts.Values) ctx.Dispose();
            CleanupQuarantineDirectories(parentContexts.Values.Select(c => c.QuarantineDirectoryPath));
            return failures;
        }

        // Stage 3: Irreversible Commit (strictly verify identity then unlink via directory descriptor)
        foreach (var item in quarantined)
        {
            try
            {
                MacFileIdentity commitIdentity = MacSafeFileSystem.GetIdentityAt(item.ParentContext.QuarantineDirHandle, item.FileName);
                if (!commitIdentity.SameObject(item.Identity))
                {
                    failures.Add($"Commit-Fehler: Quarantäneeintrag wurde vor dem Löschen ausgetauscht ({item.OriginalPath}). Löschen verweigert.");
                    continue;
                }

                MacSafeFileSystem.UnlinkAt(item.ParentContext.QuarantineDirHandle, item.FileName);
            }
            catch (Exception ex)
            {
                failures.Add($"Commit-Fehler: Quarantänedatei konnte nicht gelöscht werden ({item.OriginalPath}): {ex.Message}.");
            }
        }

        foreach (var ctx in parentContexts.Values) ctx.Dispose();
        CleanupQuarantineDirectories(parentContexts.Values.Select(c => c.QuarantineDirectoryPath));

        return failures;
    }

    private static void CleanupQuarantineDirectories(IEnumerable<string> quarantineDirs)
    {
        foreach (string qDir in quarantineDirs)
        {
            try
            {
                if (Directory.Exists(qDir) && !Directory.EnumerateFileSystemEntries(qDir).Any())
                {
                    Directory.Delete(qDir, recursive: false);
                }
            }
            catch
            {
                // best effort non-recursive cleanup
            }
        }
    }

    private sealed class QuarantineParentContext : IDisposable
    {
        public string CanonicalParentDir { get; }
        public string QuarantineDirectoryPath { get; }
        public string QuarantineDirectoryName { get; }
        public SafeFileHandle QuarantineDirHandle { get; }
        public MacFileIdentity ParentIdentity { get; }

        public QuarantineParentContext(
            string canonicalParentDir,
            string quarantineDirectoryPath,
            string quarantineDirectoryName,
            SafeFileHandle quarantineDirHandle,
            MacFileIdentity parentIdentity)
        {
            CanonicalParentDir = canonicalParentDir;
            QuarantineDirectoryPath = quarantineDirectoryPath;
            QuarantineDirectoryName = quarantineDirectoryName;
            QuarantineDirHandle = quarantineDirHandle;
            ParentIdentity = parentIdentity;
        }

        public void Dispose()
        {
            QuarantineDirHandle?.Dispose();
        }
    }

    private sealed class QuarantinedItem
    {
        public string OriginalPath { get; }
        public string FileName { get; }
        public QuarantineParentContext ParentContext { get; }
        public MacFileIdentity Identity { get; set; }

        public QuarantinedItem(
            string originalPath,
            string fileName,
            QuarantineParentContext parentContext,
            MacFileIdentity identity)
        {
            OriginalPath = originalPath;
            FileName = fileName;
            ParentContext = parentContext;
            Identity = identity;
        }
    }
}

