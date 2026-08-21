using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace KalynaArchiver.Services;

public sealed partial class ZpaqService
{
    private const int StreamMethodBlockSize = 4;
    private const int MaxCapturedProcessTextCharacters = 1024 * 1024;
    private const int MaxProcessLineCharacters = 16 * 1024;
    internal const int MaxProgressLinesPerStream = 2_000;
    private const int MaxProgressCharactersPerStream = 256 * 1024;
#if KEEPVAULT_MACOS
    private const StringComparison FileSystemPathComparison = StringComparison.Ordinal;
#else
    private const StringComparison FileSystemPathComparison = StringComparison.OrdinalIgnoreCase;
#endif
    private readonly string? _configuredPath;
    private readonly ArchiveIntegrityService _archiveIntegrity = new();

    public ZpaqService(string? configuredPath = null)
    {
        _configuredPath = configuredPath;
    }

#if KEEPVAULT_MACOS
    internal static void ValidatePortableInputTreeForTests(string root) =>
        MacInputSnapshot.ValidatePortableTree(root);

    internal static IDisposable CaptureInputSnapshotForTests(
        string workingDirectory,
        IReadOnlyList<string> inputPaths,
        out string snapshotWorkingDirectory,
        out string[] snapshotPaths)
    {
        MacInputSnapshot snapshot = MacInputSnapshot.Create(workingDirectory, inputPaths);
        snapshotWorkingDirectory = snapshot.WorkingDirectory;
        snapshotPaths = snapshot.InputPaths;
        return snapshot;
    }
#endif

    public string? ResolveExecutable()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string[] candidates =
        [
            _configuredPath ?? string.Empty,
#if KEEPVAULT_MACOS
            Path.Combine(baseDirectory, "Native", "zpaq"),
            Path.Combine(baseDirectory, "Resources", "Native", "zpaq"),
            Path.Combine(baseDirectory, "zpaq"),
#else
            Path.Combine(baseDirectory, "tools", "zpaq.exe"),
            Path.Combine(baseDirectory, "zpaq.exe"),
#endif
        ];

        foreach (string candidate in candidates)
        {
            if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public async Task<ProcessResult> AddAsync(
        string archivePath,
        IReadOnlyList<string> inputPaths,
        int compressionLevel,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputPaths);
        if (inputPaths.Count == 0)
        {
            throw new ArgumentException("Mindestens eine Eingabedatei oder ein Ordner ist erforderlich.", nameof(inputPaths));
        }

        ValidateCompressionLevel(compressionLevel);
        string workingDirectory = GetArchiveWorkingDirectory(inputPaths);
        string[] normalizedInputs = NormalizeAndValidateInputPaths(inputPaths);
        string fullArchivePath = Path.GetFullPath(archivePath);
        ValidateArchiveTarget(fullArchivePath, normalizedInputs);
        if (File.Exists(fullArchivePath) || Directory.Exists(fullArchivePath))
        {
            throw new IOException("The ZPAQ archive target already exists.");
        }

        string targetDirectory = Path.GetDirectoryName(fullArchivePath) ?? Environment.CurrentDirectory;
        if (!Directory.Exists(targetDirectory))
        {
            throw new DirectoryNotFoundException($"The ZPAQ archive target directory does not exist: {targetDirectory}");
        }

        string temporaryArchivePath = Path.Combine(
            targetDirectory,
            $".{Path.GetFileName(fullArchivePath)}.{Guid.NewGuid():N}.zpaq-part");
        string temporarySha3Path = ArchiveIntegrityService.GetSha3ManifestPath(temporaryArchivePath);
        string temporarySkeinPath = ArchiveIntegrityService.GetSkeinManifestPath(temporaryArchivePath);
        string finalSha3Path = ArchiveIntegrityService.GetSha3ManifestPath(fullArchivePath);
        string finalSkeinPath = ArchiveIntegrityService.GetSkeinManifestPath(fullArchivePath);
        bool sha3Installed = false;
        bool skeinInstalled = false;
        bool archiveInstalled = false;
#if KEEPVAULT_MACOS
        using MacInputSnapshot inputSnapshot = MacInputSnapshot.Create(workingDirectory, normalizedInputs);
        workingDirectory = inputSnapshot.WorkingDirectory;
        normalizedInputs = inputSnapshot.InputPaths;
#else
        using InputFileLeaseSet inputLeases = InputFileLeaseSet.Acquire(normalizedInputs);
#endif
        using TrustedNativeFileLease executable = AcquireExecutable();
        var arguments = new List<string> { "add", temporaryArchivePath };
        arguments.AddRange(normalizedInputs.Select(path => Path.GetRelativePath(workingDirectory, path)));
        arguments.Add($"-m{compressionLevel}");
        try
        {
            ProcessResult result = await RunTextProcessAsync(executable.Path, arguments, workingDirectory, progress, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return result;
            }

            await _archiveIntegrity.CreateAsync(temporaryArchivePath, cancellationToken).ConfigureAwait(false);
            if (File.Exists(fullArchivePath)
                || Directory.Exists(fullArchivePath)
                || File.Exists(finalSha3Path)
                || Directory.Exists(finalSha3Path)
                || File.Exists(finalSkeinPath)
                || Directory.Exists(finalSkeinPath))
            {
                throw new IOException("The ZPAQ archive target or one of its integrity manifests appeared before installation.");
            }

            File.Move(temporarySha3Path, finalSha3Path, overwrite: false);
            sha3Installed = true;
            File.Move(temporarySkeinPath, finalSkeinPath, overwrite: false);
            skeinInstalled = true;
            File.Move(temporaryArchivePath, fullArchivePath, overwrite: false);
            archiveInstalled = true;
            return result;
        }
        catch
        {
            if (archiveInstalled) SecureFile.DeleteIfExists(fullArchivePath);
            if (skeinInstalled) SecureFile.DeleteIfExists(finalSkeinPath);
            if (sha3Installed) SecureFile.DeleteIfExists(finalSha3Path);
            throw;
        }
        finally
        {
            SecureFile.DeleteIfExists(temporaryArchivePath);
            SecureFile.DeleteIfExists(temporarySha3Path);
            SecureFile.DeleteIfExists(temporarySkeinPath);
        }
    }

    public async Task<ProcessResult> ExtractAsync(
        string archivePath,
        string outputFolder,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using ArchiveIntegrityLease archive = await _archiveIntegrity.AcquireVerifiedAsync(archivePath, cancellationToken).ConfigureAwait(false);
        using TrustedNativeFileLease executable = AcquireExecutable();
#if KEEPVAULT_MACOS
        using var staging = new MacExtractionStaging(outputFolder);
        try
        {
            ProcessResult result = await RunTextProcessAsync(
                executable.Path,
                new[] { "extract", archive.Path },
                staging.StagingPath,
                progress,
                cancellationToken,
                monitorStagingDirectory: staging.StagingPath,
                expectedDirectoryIdentity: staging.StagingIdentity).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(staging.StagingPath);
                staging.Install();
            }
            else
            {
                staging.Cleanup();
            }

            return result;
        }
        catch
        {
            staging.Cleanup();
            throw;
        }
#else
        ExtractionTarget target = PrepareExtractionTarget(outputFolder);
        try
        {
            ProcessResult result = await RunTextProcessAsync(
                executable.Path,
                new[] { "extract", archive.Path },
                target.StagingPath,
                progress,
                cancellationToken,
                monitorStagingDirectory: target.StagingPath).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(target.StagingPath);
                InstallExtractedDirectory(target);
            }
            else
            {
                CleanupFailedExtractionDirectory(target.StagingPath);
            }

            return result;
        }
        catch
        {
            CleanupFailedExtractionDirectory(target.StagingPath);
            throw;
        }
#endif
    }

    public async Task<ProcessResult> ListAsync(
        string archivePath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using ArchiveIntegrityLease archive = await _archiveIntegrity.AcquireVerifiedAsync(archivePath, cancellationToken).ConfigureAwait(false);
        using TrustedNativeFileLease executable = AcquireExecutable();
        return await RunTextProcessAsync(executable.Path, new[] { "list", archive.Path }, Environment.CurrentDirectory, progress, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProcessResult> AddStreamingAsync(
        IReadOnlyList<string> inputPaths,
        int compressionLevel,
        Func<Stream, CancellationToken, Task> consumeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputPaths);
        ArgumentNullException.ThrowIfNull(consumeArchive);
        if (inputPaths.Count == 0)
        {
            throw new ArgumentException("Mindestens eine Eingabedatei oder ein Ordner ist erforderlich.", nameof(inputPaths));
        }

        ValidateCompressionLevel(compressionLevel);
        string workingDirectory = GetArchiveWorkingDirectory(inputPaths);
        string[] normalizedInputs = NormalizeAndValidateInputPaths(inputPaths);
#if KEEPVAULT_MACOS
        using MacInputSnapshot inputSnapshot = MacInputSnapshot.Create(workingDirectory, normalizedInputs);
        workingDirectory = inputSnapshot.WorkingDirectory;
        normalizedInputs = inputSnapshot.InputPaths;
#else
        using InputFileLeaseSet inputLeases = InputFileLeaseSet.Acquire(normalizedInputs);
#endif
        using TrustedNativeFileLease executable = AcquireExecutable();
        var arguments = new List<string> { "--pipe", "add", "-" };
        arguments.AddRange(normalizedInputs.Select(path => Path.GetRelativePath(workingDirectory, path)));
        arguments.Add("-method");
        arguments.Add(GetStreamingMethod(compressionLevel));
        return await RunStdoutPipeAsync(executable.Path, arguments, workingDirectory, consumeArchive, progress, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProcessResult> ExtractStreamingAsync(
        Func<Stream, CancellationToken, Task> writeArchive,
        string outputFolder,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writeArchive);
        using TrustedNativeFileLease executable = AcquireExecutable();
#if KEEPVAULT_MACOS
        using var staging = new MacExtractionStaging(outputFolder);
        try
        {
            ProcessResult result = await RunStdinPipeAsync(
                executable.Path,
                new[] { "--pipe", "extract", "-" },
                staging.StagingPath,
                writeArchive,
                progress,
                cancellationToken,
                monitorStagingDirectory: staging.StagingPath,
                expectedDirectoryIdentity: staging.StagingIdentity).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(staging.StagingPath);
                staging.Install();
            }
            else
            {
                staging.Cleanup();
            }

            return result;
        }
        catch
        {
            staging.Cleanup();
            throw;
        }
#else
        ExtractionTarget target = PrepareExtractionTarget(outputFolder);
        try
        {
            ProcessResult result = await RunStdinPipeAsync(
                executable.Path,
                new[] { "--pipe", "extract", "-" },
                target.StagingPath,
                writeArchive,
                progress,
                cancellationToken,
                monitorStagingDirectory: target.StagingPath).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(target.StagingPath);
                InstallExtractedDirectory(target);
            }
            else
            {
                CleanupFailedExtractionDirectory(target.StagingPath);
            }

            return result;
        }
        catch
        {
            CleanupFailedExtractionDirectory(target.StagingPath);
            throw;
        }
#endif
    }

    public async Task<ProcessResult> ListStreamingAsync(
        Func<Stream, CancellationToken, Task> writeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writeArchive);
        using TrustedNativeFileLease executable = AcquireExecutable();
        return await RunStdinPipeAsync(executable.Path, new[] { "--pipe", "list", "-" }, Environment.CurrentDirectory, writeArchive, progress, cancellationToken).ConfigureAwait(false);
    }

    private TrustedNativeFileLease AcquireExecutable()
    {
        string executable = ResolveExecutable()
            ?? throw new FileNotFoundException("Die fest eingebundene ZPAQ-Komponente wurde nicht gefunden.");
        return NativeToolIntegrity.AcquireTrustedFile(executable);
    }

    private static ExtractionTarget PrepareExtractionTarget(string outputFolder)
    {
        string fullPath = Path.GetFullPath(outputFolder);
        if (File.Exists(fullPath))
        {
            throw new InvalidOperationException("Extraction target must be a directory path.");
        }

        if (Directory.Exists(fullPath))
        {
            FileAttributes attributes = File.GetAttributes(fullPath);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Extraction target must not be a symbolic link or junction.");
            }

            if (Directory.EnumerateFileSystemEntries(fullPath).Any())
            {
                throw new InvalidOperationException("Extraction target must be a new or empty directory.");
            }
        }

        string parent = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        Directory.CreateDirectory(parent);
        string stagingPath = Path.Combine(
            parent,
            $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.extract-part");
        try
        {
            Directory.CreateDirectory(stagingPath);
            if ((File.GetAttributes(stagingPath) & FileAttributes.ReparsePoint) != 0)
            {
                Directory.Delete(stagingPath);
                throw new InvalidOperationException("Extraction staging directory resolved to a symbolic link or junction.");
            }

            return new ExtractionTarget(fullPath, stagingPath);
        }
        catch
        {
            CleanupFailedExtractionDirectory(stagingPath);
            throw;
        }
    }

    private static void InstallExtractedDirectory(ExtractionTarget target)
    {
        if (File.Exists(target.DestinationPath))
        {
            throw new IOException("A file appeared at the extraction target before installation.");
        }

        if (Directory.Exists(target.DestinationPath))
        {
            FileAttributes attributes = File.GetAttributes(target.DestinationPath);
            if ((attributes & FileAttributes.ReparsePoint) != 0
                || Directory.EnumerateFileSystemEntries(target.DestinationPath).Any())
            {
                throw new IOException("The extraction target changed while extraction was running.");
            }

            Directory.Delete(target.DestinationPath);
        }

        Directory.Move(target.StagingPath, target.DestinationPath);
    }

    private static void CleanupFailedExtractionDirectory(string fullOutputFolder)
    {
        string fullPath = Path.GetFullPath(fullOutputFolder);
        if (!Directory.Exists(fullPath))
        {
            return;
        }

        FileAttributes attributes = File.GetAttributes(fullPath);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(fullPath);
            return;
        }

        Directory.Delete(fullPath, recursive: true);
    }

    public static Dictionary<string, string> BuildArchiveEntryMap(IReadOnlyList<string> inputPaths)
    {
        ArgumentNullException.ThrowIfNull(inputPaths);
        if (inputPaths.Count == 0)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        string[] normalized = NormalizeAndValidateInputPaths(inputPaths);
        string workingDirectory = GetArchiveWorkingDirectory(normalized);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string full in normalized)
        {
            if (File.Exists(full))
            {
                string rel = Path.GetRelativePath(workingDirectory, full);
                map[rel] = full;
            }
            else if (Directory.Exists(full))
            {
                foreach (string file in Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories))
                {
                    string rel = Path.GetRelativePath(workingDirectory, file);
                    map[rel] = file;
                }
            }
        }

        return map;
    }

    private static string GetArchiveWorkingDirectory(IEnumerable<string> inputPaths)
    {
        string[] anchors = inputPaths
            .Select(path =>
            {
                string fullPath = Path.GetFullPath(path);
                return Directory.Exists(fullPath)
                    ? Directory.GetParent(fullPath)?.FullName ?? fullPath
                    : Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
            })
            .ToArray();

        if (anchors.Length == 0)
        {
            return Environment.CurrentDirectory;
        }

        string root = Path.GetPathRoot(anchors[0]) ?? string.Empty;
        if (anchors.Any(anchor => !string.Equals(Path.GetPathRoot(anchor), root, FileSystemPathComparison)))
        {
            throw new ArgumentException(
                "All ZPAQ inputs must be located on the same volume so archive entry names remain relative.",
                nameof(inputPaths));
        }

        string[] firstParts = anchors[0].TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        int commonLength = firstParts.Length;

        foreach (string anchor in anchors.Skip(1))
        {
            string[] parts = anchor.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            commonLength = Math.Min(commonLength, parts.Length);
            for (int i = 0; i < commonLength; i++)
            {
                if (!string.Equals(firstParts[i], parts[i], FileSystemPathComparison))
                {
                    commonLength = i;
                    break;
                }
            }
        }

        string common = string.Join(Path.DirectorySeparatorChar, firstParts.Take(commonLength));
        if (commonLength <= 1 && !string.IsNullOrWhiteSpace(root))
        {
            return root;
        }

        return string.IsNullOrWhiteSpace(common) ? root : common;
    }

    private static string[] NormalizeAndValidateInputPaths(IReadOnlyList<string> inputPaths)
    {
        var normalized = new string[inputPaths.Count];
        for (int index = 0; index < inputPaths.Count; index++)
        {
            string path = inputPaths[index];
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("ZPAQ input paths must not be empty.", nameof(inputPaths));
            }

            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
            {
                throw new FileNotFoundException("ZPAQ input does not exist.", fullPath);
            }

            normalized[index] = fullPath;
        }

        return normalized;
    }

    private static void ValidateArchiveTarget(string archivePath, IReadOnlyList<string> inputPaths)
    {
        if (Directory.Exists(archivePath))
        {
            throw new ArgumentException("The ZPAQ archive target must be a file path.", nameof(archivePath));
        }

        foreach (string inputPath in inputPaths)
        {
            if (PathsEqual(archivePath, inputPath))
            {
                throw new ArgumentException("The ZPAQ archive target must differ from every input path.", nameof(archivePath));
            }

            if (Directory.Exists(inputPath) && IsPathWithinDirectory(archivePath, inputPath))
            {
                throw new ArgumentException("The ZPAQ archive target must not be located inside an input directory.", nameof(archivePath));
            }
        }
    }

    private static bool IsPathWithinDirectory(string candidatePath, string directoryPath)
    {
        string candidate = Path.GetFullPath(candidatePath);
        string directory = Path.GetFullPath(directoryPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string prefix = directory.EndsWith(Path.DirectorySeparatorChar)
            ? directory
            : directory + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, FileSystemPathComparison);
    }

    private static bool PathsEqual(string first, string second)
    {
        return string.Equals(Path.GetFullPath(first), Path.GetFullPath(second), FileSystemPathComparison);
    }

    public const long DefaultMaxExtractedBytes = 500L * 1024 * 1024 * 1024; // 500 GiB
    public const long DefaultMaxSingleFileBytes = 500L * 1024 * 1024 * 1024; // 500 GiB
    public const int DefaultMaxExtractedFiles = 500_000;
    public const long DefaultMinFreeDiskSpaceBytes = 256L * 1024 * 1024; // 256 MiB

    internal static long MaxExtractedBytesOverride = -1;
    internal static long MaxSingleFileBytesOverride = -1;
    internal static int MaxExtractedFilesOverride = -1;
    internal static long MinFreeDiskSpaceBytesOverride = -1;

    internal static void ValidateExtractedDirectoryLimits(string stagingDirectory)
    {
        if (!Directory.Exists(stagingDirectory))
        {
            return;
        }

        long maxBytes = MaxExtractedBytesOverride > 0 ? MaxExtractedBytesOverride : DefaultMaxExtractedBytes;
        long maxSingleBytes = MaxSingleFileBytesOverride > 0 ? MaxSingleFileBytesOverride : DefaultMaxSingleFileBytes;
        int maxFiles = MaxExtractedFilesOverride > 0 ? MaxExtractedFilesOverride : DefaultMaxExtractedFiles;
        long minFreeSpace = MinFreeDiskSpaceBytesOverride > 0 ? MinFreeDiskSpaceBytesOverride : DefaultMinFreeDiskSpaceBytes;

        long totalBytes = 0;
        int fileCount = 0;

        foreach (string file in Directory.EnumerateFiles(stagingDirectory, "*", SearchOption.AllDirectories))
        {
            fileCount++;
            var info = new FileInfo(file);
            totalBytes += info.Length;

            if (info.Length > maxSingleBytes)
            {
                throw new InvalidDataException($"ZPAQ-Extraktionsgrenze für Einzeldateigröße überschritten ({maxSingleBytes} Bytes). Mögliche Decompression-Bomb abgelehnt.");
            }

            if (fileCount > maxFiles)
            {
                throw new InvalidDataException($"ZPAQ-Extraktionsgrenze für Dateianzahl überschritten ({maxFiles}). Mögliche Decompression-Bomb abgelehnt.");
            }

            if (totalBytes > maxBytes)
            {
                throw new InvalidDataException($"ZPAQ-Extraktionsgrenze für Gesamtgröße überschritten ({maxBytes} Bytes). Mögliche Decompression-Bomb abgelehnt.");
            }
        }

#if KEEPVAULT_MACOS
        long freeSpace = MacSafeFileSystem.GetFreeDiskSpaceBytes(stagingDirectory);
        if (freeSpace < 0 || freeSpace < minFreeSpace)
        {
            throw new IOException($"ZPAQ-Extraktion abgebrochen: Unzureichender freier Speicherplatz auf dem Ziellaufwerk ({freeSpace} Bytes verbleibend).");
        }
#endif
    }

    private static async Task MonitorExtractionLimitsAsync(
        string stagingDirectory,
        Process process,
        CancellationTokenSource linkedCts,
        CancellationToken cancellationToken
#if KEEPVAULT_MACOS
        , MacFileIdentity? boundDirectoryIdentity = null
#endif
    )
    {
        long maxBytes = MaxExtractedBytesOverride > 0 ? MaxExtractedBytesOverride : DefaultMaxExtractedBytes;
        long maxSingleBytes = MaxSingleFileBytesOverride > 0 ? MaxSingleFileBytesOverride : DefaultMaxSingleFileBytes;
        int maxFiles = MaxExtractedFilesOverride > 0 ? MaxExtractedFilesOverride : DefaultMaxExtractedFiles;
        long minFreeSpace = MinFreeDiskSpaceBytesOverride > 0 ? MinFreeDiskSpaceBytesOverride : DefaultMinFreeDiskSpaceBytes;

        Exception? limitViolation = null;
        int consecutiveErrors = 0;
        const int maxConsecutiveTransientErrors = 3;
        object checkLock = new object();

#if KEEPVAULT_MACOS
        MacFileIdentity? expectedDirectoryIdentity = boundDirectoryIdentity;
        if (!expectedDirectoryIdentity.HasValue)
        {
            try
            {
                if (Directory.Exists(stagingDirectory))
                {
                    expectedDirectoryIdentity = MacSafeFileSystem.GetPathIdentityNoFollow(stagingDirectory);
                }
            }
            catch (Exception ex)
            {
                linkedCts.Cancel();
                try { process.Kill(entireProcessTree: true); } catch { }
                limitViolation = new InvalidOperationException($"Konnte Identität des Staging-Verzeichnisses nicht ermitteln: {ex.Message}", ex);
                throw limitViolation;
            }
        }
#endif

        void CheckLimits()
        {
            bool hasExited;
            try
            {
                hasExited = process.HasExited;
            }
            catch (InvalidOperationException)
            {
                return;
            }

            if (hasExited || !Directory.Exists(stagingDirectory))
            {
                return;
            }

            if (!Monitor.TryEnter(checkLock))
            {
                return; // Another check is currently running (debounced)
            }

            try
            {
#if KEEPVAULT_MACOS
                if (expectedDirectoryIdentity.HasValue)
                {
                    MacFileIdentity currentIdentity = MacSafeFileSystem.GetPathIdentityNoFollow(stagingDirectory);
                    if (!currentIdentity.SameObject(expectedDirectoryIdentity.Value))
                    {
                        linkedCts.Cancel();
                        try { process.Kill(entireProcessTree: true); } catch { }
                        limitViolation ??= new InvalidOperationException("Staging-Verzeichnis wurde während der Extraktion ausgetauscht. Prozess abgebrochen.");
                        return;
                    }
                }
#endif

                long totalBytes = 0;
                int fileCount = 0;

                foreach (string file in Directory.EnumerateFiles(stagingDirectory, "*", SearchOption.AllDirectories))
                {
                    fileCount++;
                    var info = new FileInfo(file);
                    totalBytes += info.Length;

                    if (info.Length > maxSingleBytes)
                    {
                        linkedCts.Cancel();
                        try { process.Kill(entireProcessTree: true); } catch { }
                        limitViolation ??= new InvalidDataException($"ZPAQ-Extraktionsgrenze für Einzeldateigröße überschritten ({maxSingleBytes} Bytes). Mögliche Decompression-Bomb abgelehnt.");
                        return;
                    }

                    if (fileCount > maxFiles)
                    {
                        linkedCts.Cancel();
                        try { process.Kill(entireProcessTree: true); } catch { }
                        limitViolation ??= new InvalidDataException($"ZPAQ-Extraktionsgrenze für Dateianzahl überschritten ({maxFiles}). Mögliche Decompression-Bomb abgelehnt.");
                        return;
                    }

                    if (totalBytes > maxBytes)
                    {
                        linkedCts.Cancel();
                        try { process.Kill(entireProcessTree: true); } catch { }
                        limitViolation ??= new InvalidDataException($"ZPAQ-Extraktionsgrenze für Gesamtgröße überschritten ({maxBytes} Bytes). Mögliche Decompression-Bomb abgelehnt.");
                        return;
                    }
                }

#if KEEPVAULT_MACOS
                long freeSpace = MacSafeFileSystem.GetFreeDiskSpaceBytes(stagingDirectory);
                if (freeSpace < 0 || freeSpace < minFreeSpace)
                {
                    linkedCts.Cancel();
                    try { process.Kill(entireProcessTree: true); } catch { }
                    limitViolation ??= new IOException($"ZPAQ-Extraktion abgebrochen: Unzureichender freier Speicherplatz auf dem Ziellaufwerk ({freeSpace} Bytes verbleibend).");
                    return;
                }
#endif
                consecutiveErrors = 0;
            }
            catch (Exception ex) when (ex is not InvalidDataException && ex is not IOException)
            {
                consecutiveErrors++;
                if (consecutiveErrors > maxConsecutiveTransientErrors)
                {
                    linkedCts.Cancel();
                    try { process.Kill(entireProcessTree: true); } catch { }
                    limitViolation ??= new InvalidOperationException($"Decompression-Überwachung nach wiederholten Fehlern abgebrochen: {ex.Message}", ex);
                }
            }
            catch (Exception ex)
            {
                linkedCts.Cancel();
                try { process.Kill(entireProcessTree: true); } catch { }
                limitViolation ??= ex;
            }
            finally
            {
                Monitor.Exit(checkLock);
            }
        }

        using var watcher = new FileSystemWatcher();
        if (Directory.Exists(stagingDirectory))
        {
            try
            {
                watcher.Path = stagingDirectory;
                watcher.IncludeSubdirectories = true;
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite;
                watcher.Created += (_, _) => CheckLimits();
                watcher.Changed += (_, _) => CheckLimits();
                watcher.EnableRaisingEvents = true;
            }
            catch
            {
                // Fallback to high-frequency polling
            }
        }

        while (!process.HasExited && !cancellationToken.IsCancellationRequested)
        {
            if (limitViolation != null)
            {
                throw limitViolation;
            }

            try
            {
                await Task.Delay(20, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (limitViolation != null)
            {
                throw limitViolation;
            }

            if (process.HasExited)
            {
                break;
            }

            CheckLimits();

            if (limitViolation != null)
            {
                throw limitViolation;
            }
        }

        if (limitViolation != null)
        {
            throw limitViolation;
        }
    }

    internal static async Task<ProcessResult> RunTextProcessAsync(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        string? monitorStagingDirectory = null
#if KEEPVAULT_MACOS
        , MacFileIdentity? expectedDirectoryIdentity = null
#endif
    )
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var process = CreateProcess(executable, arguments, workingDirectory);
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        var output = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);
        var errors = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);

        if (!process.Start())
        {
            throw new InvalidOperationException("zpaq konnte nicht gestartet werden.");
        }

        Task outputTask = ReadLinesAsync(process.StandardOutput, output, progress, linkedCts.Token);
        Task errorTask = ReadLinesAsync(process.StandardError, errors, progress, linkedCts.Token);
        Task? monitorTask = monitorStagingDirectory != null
            ? MonitorExtractionLimitsAsync(
                monitorStagingDirectory,
                process,
                linkedCts,
                linkedCts.Token
#if KEEPVAULT_MACOS
                , expectedDirectoryIdentity
#endif
              )
            : null;

        var tasks = monitorTask != null
            ? new[] { process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask, monitorTask }
            : new[] { process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask };

        await AwaitProcessTasksFailFastAsync(process, tasks).ConfigureAwait(false);

        return new ProcessResult(process.ExitCode, output.ToString(), errors.ToString());
    }

    private static async Task<ProcessResult> RunStdoutPipeAsync(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory,
        Func<Stream, CancellationToken, Task> consumeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using var process = CreateProcess(executable, arguments, workingDirectory);
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;

        var errors = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);

        if (!process.Start())
        {
            throw new InvalidOperationException("zpaq konnte nicht gestartet werden.");
        }

        Task consumeTask = consumeArchive(process.StandardOutput.BaseStream, cancellationToken);
        Task errorTask = ReadLinesAsync(process.StandardError, errors, progress, cancellationToken);

        await AwaitProcessTasksFailFastAsync(
            process,
            consumeTask,
            process.WaitForExitAsync(cancellationToken),
            errorTask).ConfigureAwait(false);

        return new ProcessResult(process.ExitCode, string.Empty, errors.ToString());
    }

    private static async Task<ProcessResult> RunStdinPipeAsync(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory,
        Func<Stream, CancellationToken, Task> writeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        string? monitorStagingDirectory = null
#if KEEPVAULT_MACOS
        , MacFileIdentity? expectedDirectoryIdentity = null
#endif
    )
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var process = CreateProcess(executable, arguments, workingDirectory);
        process.StartInfo.RedirectStandardInput = true;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;

        var output = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);
        var errors = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);

        if (!process.Start())
        {
            throw new InvalidOperationException("zpaq konnte nicht gestartet werden.");
        }

        Task inputTask = WriteInputAndCloseAsync(process.StandardInput, writeArchive, linkedCts.Token);
        Task outputTask = ReadLinesAsync(process.StandardOutput, output, progress, linkedCts.Token);
        Task errorTask = ReadLinesAsync(process.StandardError, errors, progress, linkedCts.Token);
        Task? monitorTask = monitorStagingDirectory != null
            ? MonitorExtractionLimitsAsync(
                monitorStagingDirectory,
                process,
                linkedCts,
                linkedCts.Token
#if KEEPVAULT_MACOS
                , expectedDirectoryIdentity
#endif
              )
            : null;

        var tasks = monitorTask != null
            ? new[] { inputTask, process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask, monitorTask }
            : new[] { inputTask, process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask };

        await AwaitProcessTasksFailFastAsync(process, tasks).ConfigureAwait(false);

        return new ProcessResult(process.ExitCode, output.ToString(), errors.ToString());
    }

    private static Process CreateProcess(string executable, IEnumerable<string> arguments, string workingDirectory)
    {
        var process = new Process();
        process.StartInfo.FileName = executable;
        process.StartInfo.WorkingDirectory = workingDirectory;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        return process;
    }

    private static async Task WriteInputAndCloseAsync(
        StreamWriter standardInput,
        Func<Stream, CancellationToken, Task> writeArchive,
        CancellationToken cancellationToken)
    {
        try
        {
            await writeArchive(standardInput.BaseStream, cancellationToken).ConfigureAwait(false);
            await standardInput.BaseStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            standardInput.Close();
        }
    }

    private static async Task ReadLinesAsync(
        StreamReader reader,
        BoundedTextBuffer destination,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        char[] readBuffer = new char[4096];
        char[] lineBuffer = new char[MaxProcessLineCharacters];
        int lineLength = 0;
        bool lineTruncated = false;
        int progressLines = 0;
        int progressCharacters = 0;
        bool progressTruncationReported = false;
        try
        {
            int read;
            while ((read = await reader.ReadAsync(readBuffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
            {
                for (int index = 0; index < read; index++)
                {
                    char character = readBuffer[index];
                    if (character == '\r')
                    {
                        continue;
                    }

                    if (character == '\n')
                    {
                        ReportLine(
                            destination,
                            progress,
                            lineBuffer,
                            lineLength,
                            lineTruncated,
                            ref progressLines,
                            ref progressCharacters,
                            ref progressTruncationReported);
                        lineLength = 0;
                        lineTruncated = false;
                        continue;
                    }

                    if (lineLength < lineBuffer.Length)
                    {
                        lineBuffer[lineLength++] = character;
                    }
                    else
                    {
                        lineTruncated = true;
                    }
                }
            }

            if (lineLength > 0 || lineTruncated)
            {
                ReportLine(
                    destination,
                    progress,
                    lineBuffer,
                    lineLength,
                    lineTruncated,
                    ref progressLines,
                    ref progressCharacters,
                    ref progressTruncationReported);
            }
        }
        finally
        {
            Array.Clear(readBuffer);
            Array.Clear(lineBuffer);
        }
    }

    private static void ReportLine(
        BoundedTextBuffer destination,
        IProgress<string>? progress,
        char[] lineBuffer,
        int lineLength,
        bool lineTruncated,
        ref int progressLines,
        ref int progressCharacters,
        ref bool progressTruncationReported)
    {
        string line = new(lineBuffer, 0, lineLength);
        if (lineTruncated)
        {
            line += " [line truncated]";
        }

        destination.AppendLine(line, lineTruncated);
        if (progress is null)
        {
            return;
        }

        if (progressLines < MaxProgressLinesPerStream
            && progressCharacters <= MaxProgressCharactersPerStream - line.Length)
        {
            progress.Report(line);
            progressLines++;
            progressCharacters += line.Length;
        }
        else if (!progressTruncationReported)
        {
            progress.Report("[process progress output truncated]");
            progressTruncationReported = true;
        }
    }

    private static async Task StopProcessAsync(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException("The child process could not be terminated.", ex);
        }
        catch (NotSupportedException ex)
        {
            throw new InvalidOperationException("The platform cannot terminate the child process tree.", ex);
        }

        using var waitTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await process.WaitForExitAsync(waitTimeout.Token).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
        }
        catch (OperationCanceledException ex)
        {
            throw new TimeoutException("The terminated child process did not exit within five seconds.", ex);
        }
    }

    private static async Task AwaitProcessTasksFailFastAsync(Process process, params Task[] tasks)
    {
        var pending = new HashSet<Task>(tasks);
        while (pending.Count > 0)
        {
            Task completed = await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(completed);
            try
            {
                await completed.ConfigureAwait(false);
            }
            catch
            {
                try
                {
                    await StopProcessAsync(process).ConfigureAwait(false);
                }
                finally
                {
                    ObserveFutureFaults(pending);
                }

                throw;
            }
        }
    }

    private static void ObserveFutureFaults(IEnumerable<Task> tasks)
    {
        foreach (Task task in tasks)
        {
            _ = task.ContinueWith(
                completed => _ = completed.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private static string GetStreamingMethod(int compressionLevel)
    {
        ValidateCompressionLevel(compressionLevel);
        return compressionLevel switch
        {
            0 => $"s{StreamMethodBlockSize}",
            1 => $"s{StreamMethodBlockSize}.1.5.0.3.22",
            2 => $"s{StreamMethodBlockSize}.1.4.0.8.25",
            3 => $"s{StreamMethodBlockSize}.2.12.0.8.25c0.0.511.255",
            4 => $"s{StreamMethodBlockSize}.3ci1",
            _ => $"s{StreamMethodBlockSize}.0ci1.1.1.1.2am",
        };
    }

    private static void ValidateCompressionLevel(int compressionLevel)
    {
        if (compressionLevel is < 0 or > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(compressionLevel), "ZPAQ compression must be between 0 and 5.");
        }
    }

    private sealed class BoundedTextBuffer
    {
        private const string TruncationMarker = "[process output truncated]";
        private readonly int _maxCharacters;
        private readonly StringBuilder _text = new();
        private bool _truncated;

        public BoundedTextBuffer(int maxCharacters)
        {
            _maxCharacters = maxCharacters > TruncationMarker.Length
                ? maxCharacters
                : throw new ArgumentOutOfRangeException(nameof(maxCharacters));
        }

        public void AppendLine(string line, bool sourceLineTruncated)
        {
            ArgumentNullException.ThrowIfNull(line);
            _truncated |= sourceLineTruncated;
            if (_text.Length >= _maxCharacters)
            {
                _truncated = true;
                return;
            }

            if (_text.Length > 0)
            {
                AppendWithinLimit(Environment.NewLine);
            }

            int available = _maxCharacters - _text.Length;
            int take = Math.Min(available, line.Length);
            _text.Append(line.AsSpan(0, take));
            if (take != line.Length)
            {
                _truncated = true;
            }
        }

        public override string ToString()
        {
            if (!_truncated)
            {
                return _text.ToString();
            }

            string prefix = _text.Length == 0 ? string.Empty : Environment.NewLine;
            return string.Concat(_text.ToString(), prefix, TruncationMarker);
        }

        private void AppendWithinLimit(string value)
        {
            int take = Math.Min(_maxCharacters - _text.Length, value.Length);
            _text.Append(value.AsSpan(0, take));
            if (take != value.Length)
            {
                _truncated = true;
            }
        }
    }

    private sealed class InputFileLeaseSet : IDisposable
    {
        private readonly List<FileStream> _streams = [];

        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Each stream is either transferred into the owning lease set and nulled or disposed by the per-file finally block; the outer catch disposes all previously transferred streams.")]
        public static InputFileLeaseSet Acquire(IEnumerable<string> inputPaths)
        {
            var leases = new InputFileLeaseSet();
            try
            {
                foreach (string inputPath in inputPaths.Where(File.Exists))
                {
                    FileStream? stream = null;
                    try
                    {
                        stream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                        string resolvedPath = NativePathResolver.ResolveFinalDosPath(stream.SafeFileHandle);
                        if (!PathsEqual(inputPath, resolvedPath))
                        {
                            throw new InvalidOperationException(
                                $"ZPAQ input path resolves through a reparse point or alias: {inputPath} -> {resolvedPath}");
                        }

                        leases._streams.Add(stream);
                        stream = null;
                    }
                    finally
                    {
                        stream?.Dispose();
                    }
                }

                return leases;
            }
            catch
            {
                leases.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            for (int index = _streams.Count - 1; index >= 0; index--)
            {
                _streams[index].Dispose();
            }

            _streams.Clear();
        }
    }

#if KEEPVAULT_MACOS
    private sealed partial class MacInputSnapshot : IDisposable
    {
        private const uint CloneNoOwnerCopy = 0x0002;
        private const uint CloneNoFollowAny = 0x0008;
        private readonly string _snapshotRoot;
        private bool _disposed;

        private MacInputSnapshot(string snapshotRoot, string[] inputPaths)
        {
            _snapshotRoot = snapshotRoot;
            WorkingDirectory = snapshotRoot;
            InputPaths = inputPaths;
        }

        internal string WorkingDirectory { get; }
        internal string[] InputPaths { get; }

        internal static MacInputSnapshot Create(string workingDirectory, IReadOnlyList<string> inputPaths)
        {
            string sourceRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(workingDirectory));
            string[] snapshotSources = NormalizeSnapshotSources(inputPaths);
            string snapshotRoot = MacSafeFileSystem.ResolveExistingRealPath(
                Directory.CreateTempSubdirectory("keep-vault-input-").FullName);
            File.SetUnixFileMode(
                snapshotRoot,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            try
            {
                var snapshots = new string[snapshotSources.Length];
                for (int index = 0; index < snapshotSources.Length; index++)
                {
                    string source = snapshotSources[index];
                    string relative = Path.GetRelativePath(sourceRoot, source);
                    ValidateRelativeSnapshotPath(relative);
                    string destination = Path.GetFullPath(Path.Combine(snapshotRoot, relative));
                    EnsureWithinSnapshot(snapshotRoot, destination);

                    string? parent = Path.GetDirectoryName(destination);
                    if (string.IsNullOrWhiteSpace(parent))
                    {
                        throw new IOException("A secure input snapshot destination has no parent directory.");
                    }

                    Directory.CreateDirectory(parent);
                    if (File.Exists(destination) || Directory.Exists(destination))
                    {
                        throw new IOException(
                            $"Two archive inputs collide inside the private snapshot: {relative}");
                    }

                    if (CloneFile(source, destination, CloneNoOwnerCopy | CloneNoFollowAny) != 0)
                    {
                        int error = Marshal.GetLastPInvokeError();
                        throw new IOException(
                            $"macOS could not create the required atomic copy-on-write input snapshot for {source}. " +
                            "The selected item may be on a different file-system volume from the private app container. " +
                            "Keep Vault refuses a non-atomic fallback.",
                            new Win32Exception(error));
                    }

                    snapshots[index] = destination;
                }

                ValidatePortableTree(snapshotRoot);
                return new MacInputSnapshot(snapshotRoot, snapshots);
            }
            catch
            {
                TryDeletePrivateTree(snapshotRoot);
                throw;
            }
        }

        private static string[] NormalizeSnapshotSources(IReadOnlyList<string> inputPaths)
        {
            string[] distinct = inputPaths
                .Select(Path.GetFullPath)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            return distinct
                .Where(source => !distinct.Any(candidate =>
                    !string.Equals(candidate, source, StringComparison.Ordinal)
                    && Directory.Exists(candidate)
                    && IsPathWithinDirectory(source, candidate)))
                .ToArray();
        }

        private static void ValidateRelativeSnapshotPath(string relative)
        {
            if (string.IsNullOrWhiteSpace(relative)
                || Path.IsPathRooted(relative)
                || string.Equals(relative, ".", StringComparison.Ordinal)
                || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Any(component => string.Equals(component, "..", StringComparison.Ordinal)))
            {
                throw new IOException("An input path escapes the secure snapshot root.");
            }
        }

        private static void EnsureWithinSnapshot(string snapshotRoot, string path)
        {
            string prefix = Path.TrimEndingDirectorySeparator(snapshotRoot) + Path.DirectorySeparatorChar;
            if (!path.StartsWith(prefix, StringComparison.Ordinal))
            {
                throw new IOException("An input snapshot path escapes its private root.");
            }
        }

        internal static void ValidatePortableTree(string root)
        {
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                string directory = pending.Pop();
                var portableNames = new HashSet<string>(StringComparer.Ordinal);
                foreach (string entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    string name = Path.GetFileName(entry);
                    ValidatePortableComponent(name);
                    string collisionKey = name.Normalize(NormalizationForm.FormC).ToUpperInvariant();
                    if (!portableNames.Add(collisionKey))
                    {
                        throw new IOException(
                            $"The input contains names that collide after portable Unicode/case normalization: {directory}");
                    }

                    FileAttributes attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new IOException(
                            $"The input contains a symbolic link or other reparse point and cannot be archived safely: {entry}");
                    }

                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        pending.Push(entry);
                    }
                }
            }
        }

        private static void ValidatePortableComponent(string component)
        {
            if (component.Length == 0
                || component is "." or ".."
                || component.EndsWith('.')
                || component.EndsWith(' ')
                || component.Any(character => character < 32 || "<>:\"|?*".Contains(character)))
            {
                throw new IOException($"The input name is not portable between macOS and Windows: {component}");
            }

            string baseName = component.Split('.', 2)[0].ToUpperInvariant();
            bool reserved = baseName is "CON" or "PRN" or "AUX" or "NUL"
                || (baseName.Length == 4
                    && (baseName.StartsWith("COM", StringComparison.Ordinal)
                        || baseName.StartsWith("LPT", StringComparison.Ordinal))
                    && baseName[3] is >= '1' and <= '9');
            if (reserved)
            {
                throw new IOException($"The input uses a Windows-reserved device name: {component}");
            }
        }

        private static void TryDeletePrivateTree(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }
            }
            catch
            {
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            TryDeletePrivateTree(_snapshotRoot);
        }

        [LibraryImport("libSystem.B.dylib", EntryPoint = "clonefile", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int CloneFile(string source, string destination, uint flags);
    }
#endif

    private sealed record ExtractionTarget(string DestinationPath, string StagingPath);
}
