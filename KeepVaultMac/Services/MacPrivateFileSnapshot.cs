namespace KalynaArchiver.Services;

internal sealed class MacPrivateFileSnapshot : IDisposable
{
    private FileStream? _stream;
    private string? _directory;

    private MacPrivateFileSnapshot(string path, string directory, FileStream stream)
    {
        SnapshotPath = path;
        _directory = directory;
        _stream = stream;
    }

    internal string SnapshotPath { get; }
    internal FileStream Stream => _stream ?? throw new ObjectDisposedException(nameof(MacPrivateFileSnapshot));

    internal static MacPrivateFileSnapshot Capture(string sourcePath)
    {
        string fullPath = Path.GetFullPath(sourcePath);
        using FileStream source = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
        _ = NativePathResolver.RequireCanonicalFilePath(source.SafeFileHandle, fullPath, "Sensitive input");
        return Capture(source, Path.GetFileName(fullPath));
    }

    internal static MacPrivateFileSnapshot Capture(FileStream source, string fileName)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead || !source.CanSeek)
        {
            throw new ArgumentException("A private input snapshot requires a readable, seekable file.", nameof(source));
        }

        string directory = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-file-").FullName);
        File.SetUnixFileMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string safeName = string.IsNullOrWhiteSpace(fileName) ? "input.bin" : Path.GetFileName(fileName);
        string target = Path.Combine(directory, safeName);
        FileStream? verified = null;
        try
        {
            MacSafeFileSystem.CloneOpenedFileIntoDirectory(source.SafeFileHandle, directory, safeName);
            File.SetUnixFileMode(target, UnixFileMode.UserRead);
            verified = MacSafeFileSystem.OpenReadNoSymlinks(target);
            _ = NativePathResolver.RequireCanonicalFilePath(verified.SafeFileHandle, target, "Private input snapshot");
            return new MacPrivateFileSnapshot(target, directory, verified);
        }
        catch
        {
            verified?.Dispose();
            TryDelete(directory);
            throw;
        }
    }

    internal static Task<MacPrivateFileSnapshot> CaptureAsync(
        string sourcePath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string fullPath = Path.GetFullPath(sourcePath);
        using FileStream source = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
        _ = NativePathResolver.RequireCanonicalFilePath(source.SafeFileHandle, fullPath, "Sensitive input");
        return Task.FromResult(Capture(source, Path.GetFileName(fullPath)));
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
        string? directory = Interlocked.Exchange(ref _directory, null);
        if (directory is not null)
        {
            TryDelete(directory);
        }
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch
        {
        }
    }
}
