using Avalonia.Input;
using Avalonia.Platform.Storage;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    internal static string NormalizeTargetArchivePath(string path, bool encrypted)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        string trimmed = path.Trim();
        string extension = encrypted ? ".kzpaq" : ".zpaq";
        if (Directory.Exists(trimmed))
        {
            return Path.Combine(trimmed, $"archive{extension}");
        }

        return string.Equals(Path.GetExtension(trimmed), extension, StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : Path.ChangeExtension(trimmed, extension);
    }

    internal static string SuggestTargetArchivePath(string source, bool encrypted)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return string.Empty;
        }

        string full = Path.GetFullPath(source.Trim());
        string extension = encrypted ? ".kzpaq" : ".zpaq";
        if (Directory.Exists(full))
        {
            // Beside the folder, named after it — not inside it. An archive
            // created inside its own input is refused a moment later by the
            // safety check, so suggesting one only ever produced a dead end.
            // Naming it after the folder also keeps it distinct from anything
            // else of that name: a folder "Docs" and a file "Docs.zip" can sit
            // side by side, and so can the "Docs(1).kzpaq" made from either.
            string trimmed = Path.TrimEndingDirectorySeparator(full);
            string? parent = Path.GetDirectoryName(trimmed);
            string folderName = Path.GetFileName(trimmed);
            return string.IsNullOrEmpty(parent) || string.IsNullOrWhiteSpace(folderName)
                ? BuildNumberedArchivePath(full, "archive", extension)
                : BuildNumberedArchivePath(parent, folderName, extension);
        }

        string directory = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(full);
        return BuildNumberedArchivePath(directory, string.IsNullOrWhiteSpace(stem) ? "archive" : stem, extension);
    }

    internal static string SuggestOutputFolderPath(string archivePath)
    {
        if (string.IsNullOrWhiteSpace(archivePath))
        {
            return string.Empty;
        }

        string full = Path.GetFullPath(archivePath.Trim());
        string directory = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(full);
        return BuildNumberedDirectoryPath(directory, string.IsNullOrWhiteSpace(stem) ? "extract" : stem);
    }

    internal static string SuggestOutputFolderPath(string archivePath, string parentDirectory)
    {
        string parent = Path.GetFullPath(parentDirectory.Trim());
        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException($"Der gewählte übergeordnete Zielordner existiert nicht: {parent}");
        }

        string stem = string.IsNullOrWhiteSpace(archivePath)
            ? "extract"
            : Path.GetFileNameWithoutExtension(archivePath.Trim());
        return BuildNumberedDirectoryPath(parent, string.IsNullOrWhiteSpace(stem) ? "extract" : stem);
    }

    internal static bool HasEncryptedArchiveExtension(string path) =>
        string.Equals(Path.GetExtension(path), ".kzpaq", StringComparison.OrdinalIgnoreCase);

    internal static bool HasArchiveExtension(string path)
    {
        string extension = Path.GetExtension(path);
        return string.Equals(extension, ".kzpaq", StringComparison.OrdinalIgnoreCase)
            || string.Equals(extension, ".zpaq", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildNumberedArchivePath(string directory, string stem, string extension)
    {
        for (int index = 1; index < int.MaxValue; index++)
        {
            string candidate = Path.Combine(directory, $"{stem}({index}){extension}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Kein freier nummerierter Archivname verfügbar.");
    }

    private static string BuildNumberedDirectoryPath(string directory, string stem)
    {
        for (int index = 1; index < int.MaxValue; index++)
        {
            string candidate = Path.Combine(directory, $"{stem}({index})");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Kein freier nummerierter Zielordner verfügbar.");
    }

    private int AddInputPaths(IEnumerable<string> paths)
    {
        int added = 0;
        string? first = null;
        foreach (string source in paths)
        {
            string path;
            try
            {
                path = Path.GetFullPath(source);
            }
            catch
            {
                continue;
            }

            if (!File.Exists(path) && !Directory.Exists(path))
            {
                continue;
            }

            first ??= path;
            if (!InputList.Items.OfType<string>().Contains(path, StringComparer.Ordinal))
            {
                InputList.Items.Add(path);
                added++;
            }
        }

        if (first is not null && string.IsNullOrWhiteSpace(ArchivePathBox.Text))
        {
            ArchivePathBox.Text = SuggestTargetArchivePath(first, EncryptBox.IsChecked == true);
            ResetKeySheetStatus();
        }

        if (added > 0)
        {
            Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropAddedInputs"), added));
        }

        return added;
    }

    private void EnsureArchiveTargetIsSafe(string archivePath, IReadOnlyList<string> inputs)
    {
        string target = Path.GetFullPath(archivePath);
        if (File.Exists(target) || Directory.Exists(target))
        {
            throw new InvalidOperationException(T("archiveTargetExists"));
        }

        foreach (string input in inputs)
        {
            string fullInput = Path.GetFullPath(input);
            if (File.Exists(fullInput) && string.Equals(target, fullInput, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(T("archiveTargetOverwritesInput"));
            }

            if (Directory.Exists(fullInput) && IsInsideDirectory(target, fullInput))
            {
                throw new InvalidOperationException(T("archiveTargetInsideInput"));
            }
        }
    }

    private static bool IsInsideDirectory(string path, string directory)
    {
        string normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        string normalizedDirectory = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return normalizedPath.StartsWith(normalizedDirectory, StringComparison.Ordinal);
    }

    private static string[] GetDroppedPaths(DragEventArgs e)
    {
        IReadOnlyList<IStorageItem>? items = e.DataTransfer.TryGetFiles();
        return items?
            .Select(item => item.TryGetLocalPath())
            .OfType<string>()
            .Select(Path.GetFullPath)
            .ToArray() ?? [];
    }

    private static void SetDropEffect(DragEventArgs e, MacDropTarget target)
    {
        IReadOnlyList<IStorageItem> items = e.DataTransfer.TryGetFiles() ?? [];
        string[] paths = items.Select(GetLocalPath).OfType<string>().ToArray();
        e.DragEffects = CanDrop(items, paths, target) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private static bool CanDrop(
        IReadOnlyList<IStorageItem> items,
        IReadOnlyList<string> paths,
        MacDropTarget target) => target switch
    {
        MacDropTarget.Inputs => items.Any(item => item is IStorageFile or IStorageFolder),
        MacDropTarget.TargetArchive => items.Count == 1 && paths.Count == 1,
        MacDropTarget.ExtractArchive => paths.Any(HasArchiveExtension),
        MacDropTarget.OutputFolder => items.Any(item => item is IStorageFolder),
        MacDropTarget.EraseTarget => items.Any(item => item is IStorageFile),
        MacDropTarget.Auto => paths.Count > 0,
        _ => false,
    };

    private void ApplyDrop(DragEventArgs e, MacDropTarget target)
    {
        IReadOnlyList<IStorageItem> items = e.DataTransfer.TryGetFiles() ?? [];
        string[] paths = items
            .Select(GetLocalPath)
            .OfType<string>()
            .ToArray();
        try
        {
            MacDropTarget effective = target;
            if (effective == MacDropTarget.Auto)
            {
                effective = paths.Count(HasArchiveExtension) > 0 ? MacDropTarget.ExtractArchive : MacDropTarget.Inputs;
            }

            bool applied = effective switch
            {
                MacDropTarget.Inputs => ApplyInputDrop(items),
                MacDropTarget.TargetArchive => ApplyArchiveTargetDrop(items, paths),
                MacDropTarget.ExtractArchive => ApplyExtractDrop(items, paths),
                MacDropTarget.OutputFolder => ApplyOutputDrop(items, paths),
                MacDropTarget.EraseTarget => ApplyEraseDrop(items, paths),
                _ => false,
            };
            e.DragEffects = applied ? DragDropEffects.Copy : DragDropEffects.None;
            e.Handled = true;
        }
        finally
        {
            DisposeUnretainedStorageItems(items);
        }
    }

    private bool ApplyInputDrop(IReadOnlyList<IStorageItem> items) => AddInputStorageItems(items) > 0;

    private bool ApplyArchiveTargetDrop(IReadOnlyList<IStorageItem> items, IReadOnlyList<string> paths)
    {
        if (paths.Count != 1)
        {
            return false;
        }

        string path = paths[0];
        IStorageItem? selectedItem = items.FirstOrDefault(item => StorageItemNamesPath(item, path));
        if (selectedItem is IStorageFile && !HasArchiveExtension(path))
        {
            AddInputStorageItems([selectedItem]);
        }
        else if (selectedItem is IStorageFolder folder)
        {
            if (!RetainArchiveDestinationAccess(folder))
            {
                return false;
            }
        }

        ArchivePathBox.Text = SuggestTargetArchivePath(path, EncryptBox.IsChecked == true);
        ResetKeySheetStatus();
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropTargetArchive"), ArchivePathBox.Text));
        return true;
    }

    private bool ApplyExtractDrop(IReadOnlyList<IStorageItem> items, IEnumerable<string> paths)
    {
        string? archive = paths.FirstOrDefault(HasArchiveExtension);
        if (archive is null)
        {
            return false;
        }

        if (items.FirstOrDefault(item => StorageItemNamesPath(item, archive)) is IStorageFile file)
        {
            if (!RetainExtractArchiveAccess(file))
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        SetExtractArchivePath(archive);
        MainTabs.SelectedItem = ExtractTab;
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropExtractArchive"), archive));
        return true;
    }

    private bool ApplyOutputDrop(IReadOnlyList<IStorageItem> items, IEnumerable<string> paths)
    {
        IStorageFolder? storageFolder = items.OfType<IStorageFolder>().FirstOrDefault();
        string? folder = storageFolder is null ? null : GetLocalPath(storageFolder);
        if (storageFolder is null || folder is null)
        {
            return false;
        }

        if (!RetainExtractOutputParentAccess(storageFolder))
        {
            return false;
        }

        string output = SuggestOutputFolderPath(ExtractArchiveBox.Text ?? string.Empty, folder);
        OutputFolderBox.Text = output;
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropOutputFolder"), output));
        return true;
    }

    private bool ApplyEraseDrop(IReadOnlyList<IStorageItem> items, IEnumerable<string> paths)
    {
        IStorageFile? storageFile = items.OfType<IStorageFile>().FirstOrDefault();
        string? path = storageFile is null ? null : GetLocalPath(storageFile);
        if (storageFile is null || path is null)
        {
            return false;
        }

        if (!RetainEraseArchiveAccess(storageFile))
        {
            return false;
        }

        SetErasePath(path);
        MainTabs.SelectedItem = EraseTab;
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropEraseTarget"), path));
        return true;
    }

    private void Window_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.Auto);
    private void Window_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.Auto);
    private void CreatePanel_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.Inputs);
    private void CreatePanel_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.Inputs);
    private void InputList_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.Inputs);
    private void InputList_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.Inputs);
    private void ArchivePathBox_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.TargetArchive);
    private void ArchivePathBox_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.TargetArchive);
    private void ExtractPanel_DragOver(object? sender, DragEventArgs e)
    {
        string[] paths = GetDroppedPaths(e);
        MacDropTarget target = paths.Any(HasArchiveExtension) ? MacDropTarget.ExtractArchive : MacDropTarget.OutputFolder;
        SetDropEffect(e, target);
    }

    private void ExtractPanel_Drop(object? sender, DragEventArgs e)
    {
        string[] paths = GetDroppedPaths(e);
        ApplyDrop(e, paths.Any(HasArchiveExtension) ? MacDropTarget.ExtractArchive : MacDropTarget.OutputFolder);
    }
    private void ExtractArchiveBox_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.ExtractArchive);
    private void ExtractArchiveBox_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.ExtractArchive);
    private void OutputFolderBox_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.OutputFolder);
    private void OutputFolderBox_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.OutputFolder);
    private void ErasePanel_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.EraseTarget);
    private void ErasePanel_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.EraseTarget);
    private void ErasePathBox_DragOver(object? sender, DragEventArgs e) => SetDropEffect(e, MacDropTarget.EraseTarget);
    private void ErasePathBox_Drop(object? sender, DragEventArgs e) => ApplyDrop(e, MacDropTarget.EraseTarget);
}

internal enum MacDropTarget
{
    Auto,
    Inputs,
    TargetArchive,
    ExtractArchive,
    OutputFolder,
    EraseTarget,
}
