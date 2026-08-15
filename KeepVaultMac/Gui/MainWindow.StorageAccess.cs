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

    /// <summary>
    /// Takes grants produced by the panel helper into the input list.
    /// </summary>
    /// <remarks>
    /// The drop path keeps its own routine because it starts from Avalonia
    /// storage items; here access already exists as a resolved lease, so the
    /// only remaining questions are whether the path is still there and whether
    /// the list accepted it. Anything rejected releases its grant immediately
    /// rather than leaving a sandbox extension open for a file the app is not
    /// working with.
    /// </remarks>
    private int AddInputAccessLeases(IReadOnlyList<MacStorageAccessLease> leases)
    {
        int added = 0;
        foreach (MacStorageAccessLease lease in leases)
        {
            if (_disposed || (!File.Exists(lease.Path) && !Directory.Exists(lease.Path)))
            {
                lease.Dispose();
                continue;
            }

            added += AddInputPaths([lease.Path]);
            if (!InputList.Items.OfType<string>().Contains(lease.Path, StringComparer.Ordinal))
            {
                lease.Dispose();
                continue;
            }

            if (_inputStorageAccess.Remove(lease.Path, out MacStorageAccessLease? previous))
            {
                previous.Dispose();
            }

            _inputStorageAccess[lease.Path] = lease;
        }

        return added;
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
        if (current?.Item is not null && ReferenceEquals(current.Item, item))
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
            string? path = GetLocalPath(item);
            if (path is null)
            {
                lease = null!;
                item.Dispose();
                return false;
            }

            lease = MacStorageAccessLease.Acquire(item, path);
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
            && StorageItemNamesPath(_extractArchiveAccess, archivePath)
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

        // The retained lease already holds the scope for the whole operation, so
        // this borrows it rather than starting a second one: starting twice and
        // stopping once would leak the sandbox extension.
        return MacSecurityScopedResourceLease.Borrowed();
    }

    private MacSecurityScopedResourceLease AcquireTransientEraseAccess(string archivePath)
    {
        if (!StorageFolderIsParentOf(_eraseArchiveParentAccess, archivePath))
        {
            throw new UnauthorizedAccessException(T("sandboxFolderAccessRequired"));
        }

        return MacSecurityScopedResourceLease.Borrowed();
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
            && !StorageItemNamesPath(_extractArchiveAccess, archivePath))
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
            && !StorageItemNamesPath(_eraseArchiveAccess, archivePath))
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

        MacStorageAccessLease? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseArchiveDestinationFolderDialog"),
            _archiveDestinationAccess);
        if (folder is null)
        {
            return false;
        }

        _archiveDestinationAccess?.Dispose();
        _archiveDestinationAccess = folder;
        return true;
    }

    private async Task<bool> EnsureExtractArchiveParentAccessAsync(string archivePath)
    {
        if (StorageFolderIsParentOf(_extractArchiveParentAccess, archivePath)
            || StorageFolderIsParentOf(_extractOutputParentAccess, archivePath))
        {
            return true;
        }

        MacStorageAccessLease? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseArchiveSidecarFolderDialog"),
            _extractArchiveAccess);
        if (folder is null)
        {
            return false;
        }

        _extractArchiveParentAccess?.Dispose();
        _extractArchiveParentAccess = folder;
        return true;
    }

    private async Task<bool> EnsureExtractOutputParentAccessAsync(string outputPath)
    {
        if (StorageFolderIsParentOf(_extractOutputParentAccess, outputPath)
            || StorageFolderIsParentOf(_extractArchiveParentAccess, outputPath))
        {
            return true;
        }

        MacStorageAccessLease? folder = await RequestExactParentFolderAccessAsync(
            outputPath,
            T("chooseOutputParentDialog"),
            _extractOutputParentAccess);
        if (folder is null)
        {
            return false;
        }

        _extractOutputParentAccess?.Dispose();
        _extractOutputParentAccess = folder;
        return true;
    }

    private async Task<bool> EnsureEraseArchiveParentAccessAsync(string archivePath)
    {
        if (StorageFolderIsParentOf(_eraseArchiveParentAccess, archivePath))
        {
            return true;
        }

        MacStorageAccessLease? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseEraseSidecarFolderDialog"),
            _eraseArchiveAccess);
        if (folder is null)
        {
            return false;
        }

        _eraseArchiveParentAccess?.Dispose();
        _eraseArchiveParentAccess = folder;
        return true;
    }

    private async Task<MacStorageAccessLease?> RequestExactParentFolderAccessAsync(
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

        _ = suggestedAccess;
        MacStorageAccessLease? selected = await RequestPanelAccessAsync(
            MacPanelBroker.PanelKind.OpenFolder,
            title,
            suggestedName: string.Empty);
        if (selected is null)
        {
            await WarnAsync(T("sandboxFolderAccessRequired"));
            return null;
        }

        // The user must grant the exact folder that holds the file, so a
        // neighbouring or parent folder is refused rather than silently used.
        if (!PathsNameSameDirectory(selected.Path, expectedParent))
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

    /// <summary>
    /// Raises one panel through the helper bundle and retains the access it
    /// granted.
    /// </summary>
    private async Task<MacStorageAccessLease?> RequestPanelAccessAsync(
        MacPanelBroker.PanelKind kind,
        string title,
        string suggestedName)
    {
        IReadOnlyList<MacPanelBroker.PanelSelection> selections;
        try
        {
            selections = await MacPanelBroker.ShowAsync(kind, title, suggestedName, _lifetime.Token);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException
            or InvalidOperationException
            or InvalidDataException
            or IOException
            or NotSupportedException)
        {
            Log($"Panel request failed: {exception.Message}");
            await ErrorAsync(T("sandboxLeaseFailed"));
            return null;
        }

        if (selections.Count == 0)
        {
            return null;
        }

        foreach (MacPanelBroker.PanelSelection extra in selections.Skip(1))
        {
            extra.Dispose();
        }

        MacPanelBroker.PanelSelection first = selections[0];
        return MacStorageAccessLease.FromResolvedSelection(first.Path, first.Lease);
    }

    /// <summary>Raises a multi-selection panel and retains every grant.</summary>
    private async Task<IReadOnlyList<MacStorageAccessLease>> RequestPanelAccessManyAsync(
        MacPanelBroker.PanelKind kind,
        string title)
    {
        IReadOnlyList<MacPanelBroker.PanelSelection> selections;
        try
        {
            selections = await MacPanelBroker.ShowAsync(kind, title, string.Empty, _lifetime.Token);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return [];
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException
            or InvalidOperationException
            or InvalidDataException
            or IOException
            or NotSupportedException)
        {
            Log($"Panel request failed: {exception.Message}");
            await ErrorAsync(T("sandboxLeaseFailed"));
            return [];
        }

        return [.. selections.Select(selection =>
            MacStorageAccessLease.FromResolvedSelection(selection.Path, selection.Lease))];
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

    /// <summary>
    /// Whether a retained lease grants access to exactly this path.
    /// </summary>
    /// <remarks>
    /// Compared on the lease's canonical path rather than on a storage item,
    /// because a lease obtained through the panel helper has no storage item
    /// behind it — only a resolved security-scoped URL.
    /// </remarks>
    /// <summary>Whether a dropped storage item names exactly this path.</summary>
    private static bool StorageItemHasPath(IStorageItem? item, string path)
    {
        return item is not null && PathsNameSameItem(GetLocalPath(item), NormalizeLocalPath(path));
    }

    private static bool StorageItemNamesPath(MacStorageAccessLease? access, string path)
    {
        return access is not null && PathsNameSameItem(access.Path, NormalizeLocalPath(path));
    }

    private static bool StorageFolderIsParentOf(MacStorageAccessLease? access, string childPath)
    {
        string? normalizedChild = NormalizeLocalPath(childPath);
        string? parent = normalizedChild is null ? null : Path.GetDirectoryName(normalizedChild);
        return access is not null && PathsNameSameDirectory(access.Path, parent);
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
