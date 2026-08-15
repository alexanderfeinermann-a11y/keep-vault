using Avalonia.Platform.Storage;
using KalynaArchiver.Gui;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private readonly Dictionary<string, MacStorageAccessLease> _inputStorageAccess = new(StringComparer.Ordinal);

    private MacStorageAccessLease? _archiveDestinationAccess;
    private MacStorageAccessLease? _extractArchiveAccess;
    private MacStorageAccessLease? _extractArchiveParentAccess;
    private MacStorageAccessLease? _extractOutputParentAccess;
    private MacStorageAccessLease? _eraseArchiveAccess;
    private MacStorageAccessLease? _eraseArchiveParentAccess;

    internal bool HandleFileActivation(IStorageFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        string? path = GetLocalPath(file);
        if (_disposed || path is null || !HasArchiveExtension(path))
        {
            return false;
        }

        if (!RetainExtractArchiveAccess(file))
        {
            return false;
        }

        if (!File.Exists(path))
        {
            _extractArchiveAccess!.Dispose();
            _extractArchiveAccess = null;
            return false;
        }

        SetExtractArchivePath(path);
        MainTabs.SelectedItem = ExtractTab;
        if (!IsVisible)
        {
            Show();
        }

        if (WindowState == Avalonia.Controls.WindowState.Minimized)
        {
            WindowState = Avalonia.Controls.WindowState.Normal;
        }

        Activate();
        Log(string.Format(
            System.Globalization.CultureInfo.CurrentCulture,
            T("finderOpenedArchive"),
            path));
        return true;
    }

    private int AddInputStorageItems(IEnumerable<IStorageItem> items)
    {
        int added = 0;
        foreach (IStorageItem item in items)
        {
            string? path = GetLocalPath(item);
            if (path is null)
            {
                continue;
            }

            if (!TryAcquireStorageAccess(item, out MacStorageAccessLease next))
            {
                continue;
            }

            if (!File.Exists(path) && !Directory.Exists(path))
            {
                next.Dispose();
                continue;
            }

            added += AddInputPaths([path]);
            if (!InputList.Items.OfType<string>().Contains(path, StringComparer.Ordinal))
            {
                next.Dispose();
                continue;
            }

            if (_inputStorageAccess.Remove(path, out MacStorageAccessLease? previous))
            {
                previous.Dispose();
            }

            _inputStorageAccess[path] = next;
        }

        return added;
    }

    private void ClearInputStorageAccess()
    {
        foreach (MacStorageAccessLease item in _inputStorageAccess.Values)
        {
            item.Dispose();
        }

        _inputStorageAccess.Clear();
    }

    private bool RetainArchiveDestinationAccess(IStorageFolder folder)
    {
        return ReplaceStorageAccess(ref _archiveDestinationAccess, folder);
    }

    private bool RetainExtractArchiveAccess(IStorageFile file)
    {
        return ReplaceStorageAccess(ref _extractArchiveAccess, file);
    }

    private bool RetainExtractOutputParentAccess(IStorageFolder folder)
    {
        return ReplaceStorageAccess(ref _extractOutputParentAccess, folder);
    }

    private bool RetainEraseArchiveAccess(IStorageFile file)
    {
        return ReplaceStorageAccess(ref _eraseArchiveAccess, file);
    }

    private bool ReplaceStorageAccess(ref MacStorageAccessLease? current, IStorageItem item)
    {
        if (current is not null && ReferenceEquals(current.Item, item))
        {
            return true;
        }

        if (!TryAcquireStorageAccess(item, out MacStorageAccessLease next))
        {
            return false;
        }

        current?.Dispose();
        current = next;
        return true;
    }

    private bool TryAcquireStorageAccess(IStorageItem item, out MacStorageAccessLease lease)
    {
        if (_disposed)
        {
            lease = null!;
            item.Dispose();
            return false;
        }

        try
        {
            lease = MacStorageAccessLease.Acquire(item);
            return true;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException
            or InvalidOperationException
            or NotSupportedException)
        {
            lease = null!;
            item.Dispose();
            Log($"Security-scoped URL lease failed: {exception.Message}");
            _ = ErrorAsync(T("sandboxLeaseFailed"));
            return false;
        }
    }

    private MacSecurityScopedResourceLease? AcquireTransientExtractAccess(string archivePath)
    {
        MacStorageAccessLease? access = _extractArchiveAccess is not null
            && StorageItemNamesPath(_extractArchiveAccess.Item, archivePath)
                ? _extractArchiveAccess
                : StorageFolderIsParentOf(_extractArchiveParentAccess, archivePath)
                    ? _extractArchiveParentAccess
                    : StorageFolderIsParentOf(_extractOutputParentAccess, archivePath)
                        ? _extractOutputParentAccess
                        : null;
        if (access is null)
        {
            return null;
        }

        try
        {
            return MacSecurityScopedResourceLease.Acquire(access.Item);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException
            or InvalidOperationException
            or NotSupportedException)
        {
            Log($"Transient security-scoped URL lease failed: {exception.Message}");
            return null;
        }
    }

    private MacSecurityScopedResourceLease AcquireTransientEraseAccess(string archivePath)
    {
        if (!StorageFolderIsParentOf(_eraseArchiveParentAccess, archivePath))
        {
            throw new UnauthorizedAccessException(T("sandboxFolderAccessRequired"));
        }

        return MacSecurityScopedResourceLease.Acquire(_eraseArchiveParentAccess!.Item);
    }

    private void ReleaseArchiveDestinationAccessIfMismatched(string archivePath)
    {
        if (_archiveDestinationAccess is not null
            && !StorageFolderIsParentOf(_archiveDestinationAccess, archivePath))
        {
            _archiveDestinationAccess.Dispose();
            _archiveDestinationAccess = null;
        }
    }

    private void ReleaseExtractAccessIfMismatched(string archivePath)
    {
        if (_extractArchiveAccess is not null
            && !StorageItemNamesPath(_extractArchiveAccess.Item, archivePath))
        {
            _extractArchiveAccess.Dispose();
            _extractArchiveAccess = null;
        }

        if (_extractArchiveParentAccess is not null
            && !StorageFolderIsParentOf(_extractArchiveParentAccess, archivePath))
        {
            _extractArchiveParentAccess.Dispose();
            _extractArchiveParentAccess = null;
        }
    }

    private void ReleaseExtractOutputAccessIfMismatched(string outputPath)
    {
        if (_extractOutputParentAccess is not null
            && !StorageFolderIsParentOf(_extractOutputParentAccess, outputPath))
        {
            _extractOutputParentAccess.Dispose();
            _extractOutputParentAccess = null;
        }
    }

    private void ReleaseEraseAccessIfMismatched(string archivePath)
    {
        if (_eraseArchiveAccess is not null
            && !StorageItemNamesPath(_eraseArchiveAccess.Item, archivePath))
        {
            _eraseArchiveAccess.Dispose();
            _eraseArchiveAccess = null;
        }

        if (_eraseArchiveParentAccess is not null
            && !StorageFolderIsParentOf(_eraseArchiveParentAccess, archivePath))
        {
            _eraseArchiveParentAccess.Dispose();
            _eraseArchiveParentAccess = null;
        }
    }

    private async Task<bool> EnsureArchiveDestinationAccessAsync(string archivePath)
    {
        if (StorageFolderIsParentOf(_archiveDestinationAccess, archivePath))
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseArchiveDestinationFolderDialog"),
            _archiveDestinationAccess);
        if (folder is null)
        {
            return false;
        }

        return RetainArchiveDestinationAccess(folder);
    }

    private async Task<bool> EnsureExtractArchiveParentAccessAsync(string archivePath)
    {
        if (StorageFolderIsParentOf(_extractArchiveParentAccess, archivePath)
            || StorageFolderIsParentOf(_extractOutputParentAccess, archivePath))
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseArchiveSidecarFolderDialog"),
            _extractArchiveAccess);
        if (folder is null)
        {
            return false;
        }

        return ReplaceStorageAccess(ref _extractArchiveParentAccess, folder);
    }

    private async Task<bool> EnsureExtractOutputParentAccessAsync(string outputPath)
    {
        if (StorageFolderIsParentOf(_extractOutputParentAccess, outputPath)
            || StorageFolderIsParentOf(_extractArchiveParentAccess, outputPath))
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            outputPath,
            T("chooseOutputParentDialog"),
            _extractOutputParentAccess);
        if (folder is null)
        {
            return false;
        }

        return RetainExtractOutputParentAccess(folder);
    }

    private async Task<bool> EnsureEraseArchiveParentAccessAsync(string archivePath)
    {
        if (StorageFolderIsParentOf(_eraseArchiveParentAccess, archivePath))
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseEraseSidecarFolderDialog"),
            _eraseArchiveAccess);
        if (folder is null)
        {
            return false;
        }

        return ReplaceStorageAccess(ref _eraseArchiveParentAccess, folder);
    }

    private async Task<IStorageFolder?> RequestExactParentFolderAccessAsync(
        string childPath,
        string title,
        MacStorageAccessLease? suggestedAccess)
    {
        string? normalizedChild = NormalizeLocalPath(childPath);
        string? expectedParent = normalizedChild is null ? null : Path.GetDirectoryName(normalizedChild);
        if (string.IsNullOrWhiteSpace(expectedParent))
        {
            await WarnAsync(T("sandboxParentUnavailable"));
            return null;
        }

        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            SuggestedStartLocation = suggestedAccess?.Item as IStorageFolder,
        });
        IStorageFolder? selected = folders.FirstOrDefault();
        foreach (IStorageFolder extra in folders.Skip(1))
        {
            extra.Dispose();
        }

        if (selected is null)
        {
            await WarnAsync(T("sandboxFolderAccessRequired"));
            return null;
        }

        string? selectedPath = GetLocalPath(selected);
        if (!PathsNameSameDirectory(selectedPath, expectedParent))
        {
            selected.Dispose();
            await WarnAsync(string.Format(
                System.Globalization.CultureInfo.CurrentCulture,
                T("sandboxWrongFolder"),
                expectedParent));
            return null;
        }

        return selected;
    }

    private void DisposeStorageAccess()
    {
        ClearInputStorageAccess();
        _archiveDestinationAccess?.Dispose();
        _archiveDestinationAccess = null;
        _extractArchiveAccess?.Dispose();
        _extractArchiveAccess = null;
        _extractArchiveParentAccess?.Dispose();
        _extractArchiveParentAccess = null;
        _extractOutputParentAccess?.Dispose();
        _extractOutputParentAccess = null;
        _eraseArchiveAccess?.Dispose();
        _eraseArchiveAccess = null;
        _eraseArchiveParentAccess?.Dispose();
        _eraseArchiveParentAccess = null;
    }

    private bool IsStorageAccessRetained(IStorageItem item)
    {
        return ReferenceEquals(item, _archiveDestinationAccess?.Item)
            || ReferenceEquals(item, _extractArchiveAccess?.Item)
            || ReferenceEquals(item, _extractArchiveParentAccess?.Item)
            || ReferenceEquals(item, _extractOutputParentAccess?.Item)
            || ReferenceEquals(item, _eraseArchiveAccess?.Item)
            || ReferenceEquals(item, _eraseArchiveParentAccess?.Item)
            || _inputStorageAccess.Values.Any(retained => ReferenceEquals(retained.Item, item));
    }

    private void DisposeUnretainedStorageItems(IEnumerable<IStorageItem> items)
    {
        foreach (IStorageItem item in items)
        {
            if (!IsStorageAccessRetained(item))
            {
                item.Dispose();
            }
        }
    }

    private static bool StorageItemNamesPath(IStorageItem? item, string path)
    {
        return item is not null && PathsNameSameItem(GetLocalPath(item), NormalizeLocalPath(path));
    }

    private static bool StorageFolderIsParentOf(MacStorageAccessLease? access, string childPath)
    {
        string? normalizedChild = NormalizeLocalPath(childPath);
        string? parent = normalizedChild is null ? null : Path.GetDirectoryName(normalizedChild);
        return access?.Item is IStorageFolder folder
            && PathsNameSameDirectory(GetLocalPath(folder), parent);
    }

    private static bool PathsNameSameDirectory(string? left, string? right)
    {
        string? normalizedLeft = NormalizeLocalPath(left)?.TrimEnd(Path.DirectorySeparatorChar);
        string? normalizedRight = NormalizeLocalPath(right)?.TrimEnd(Path.DirectorySeparatorChar);
        return normalizedLeft is not null
            && normalizedRight is not null
            && string.Equals(normalizedLeft, normalizedRight, StringComparison.Ordinal);
    }

    private static bool PathsNameSameItem(string? left, string? right)
    {
        return left is not null
            && right is not null
            && string.Equals(left, right, StringComparison.Ordinal);
    }

    private static string? GetLocalPath(IStorageItem item)
    {
        try
        {
            return NormalizeLocalPath(item.TryGetLocalPath());
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            return null;
        }
    }

    private static string? NormalizeLocalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path).Normalize(System.Text.NormalizationForm.FormC);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            return null;
        }
    }
}
