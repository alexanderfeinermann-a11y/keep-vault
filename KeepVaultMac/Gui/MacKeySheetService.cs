using KalynaArchiver.Services;

namespace KalynaArchiver.Gui;

internal sealed record MacKeySheetData(
    string ArchivePath,
    EncryptionSuite Suite,
    string FirstGeneratedPassword,
    string SecondGeneratedPassword,
    DateTime CreatedAt,
    bool English = false,
    string DeviceName = "")
{
    internal KeySheetData ToServiceData() => new(
        ArchivePath,
        Suite,
        FirstGeneratedPassword,
        SecondGeneratedPassword,
        CreatedAt,
        English,
        DeviceName);
}

/// <summary>
/// Keeps the GUI API small while routing every key-sheet operation through the
/// audited macOS KeySheetService. Security checks are intentionally not
/// duplicated in the view layer.
/// </summary>
internal sealed class MacKeySheetService
{
    private readonly KeySheetService _service = new();

    internal void SaveExplicitTestPdf(MacKeySheetData data, string path)
    {
        ArgumentNullException.ThrowIfNull(data);
        _service.SaveTestPdf(data.ToServiceData(), path);
    }

    internal async Task<IReadOnlyList<string>> GetPhysicalPrintersAsync(
        CancellationToken cancellationToken)
    {
        IReadOnlyList<PhysicalPrinterDescriptor> printers = await _service
            .GetVerifiedPhysicalPrintersAsync(cancellationToken)
            .ConfigureAwait(false);
        return printers.Select(printer => printer.Name).ToArray();
    }

    internal async Task PrintAsync(
        MacKeySheetData data,
        string printer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(data);
        _ = await _service
            .PrintKeySheetsAsync(printer, data.ToServiceData(), cancellationToken)
            .ConfigureAwait(false);
    }

    internal static string GroupGeneratedPassword(string password) =>
        KeySheetService.GroupGeneratedPassword(password);

    internal static string BuildBindingFingerprint(MacKeySheetData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return KeySheetService.BuildBindingFingerprint(data.ToServiceData());
    }
}
