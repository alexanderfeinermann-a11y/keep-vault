using System.Buffers.Binary;
using System.ComponentModel;
using System.Drawing.Printing;
using System.IO;
using System.Printing;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using QRCoder;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// Produces the two printed key sheets, and the explicit test export of them.
/// </summary>
/// <remarks>
/// Deliberately the same document as the macOS build renders: one sheet per
/// factor, a separating page carrying only the public installation
/// instructions, each factor's QR code printed twice, and the archive path,
/// suite and device name that let the sheet be matched to an archive years
/// later. The layout itself lives in <see cref="KeySheetLayout"/> and is drawn
/// once for the PDF and once for the printer, so the exported document and the
/// paper cannot drift apart.
/// </remarks>
public sealed class KeySheetService
{
    internal const string ProductName = "Keep Vault";
    private static readonly object FontResolverGate = new();

    /// <summary>
    /// Writes the two key sheets as two separate files.
    /// </summary>
    /// <remarks>
    /// The whole scheme rests on factor A and factor B never being in one
    /// place. A single export file quietly undid that: it put both halves of
    /// the key in one object, on one disk, in one backup. Each factor now gets
    /// its own file so the separation survives the digital step too, and each
    /// carries the public installation page so either one is useful on its own.
    ///
    /// This method exists solely for explicit test and export use. The normal
    /// print path never calls it and never writes a PDF to disk.
    /// </remarks>
    public void SaveTestPdf(KeySheetData data, string firstPdfPath, string secondPdfPath)
    {
        ValidatedKeySheetData validated = Validate(data);
        ArgumentException.ThrowIfNullOrWhiteSpace(firstPdfPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(secondPdfPath);
        if (string.Equals(
                Path.GetFullPath(firstPdfPath),
                Path.GetFullPath(secondPdfPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The two factors must not be written into the same file.",
                nameof(secondPdfPath));
        }

        EnsurePdfFontResolver();
        WriteSheet(validated, KeySheetFactor.First, firstPdfPath);
        try
        {
            WriteSheet(validated, KeySheetFactor.Second, secondPdfPath);
        }
        catch
        {
            // Never leave factor A behind on its own without the caller knowing
            // the export failed halfway.
            TryDestroyExport(firstPdfPath);
            throw;
        }
    }

    /// <summary>
    /// Returns only queues the local spooler gives direct physical-device
    /// evidence for. Virtual file, PDF, XPS and fax destinations are excluded,
    /// as are queues whose port says nothing about a device.
    /// </summary>
    public IReadOnlyList<PhysicalPrinterDescriptor> GetVerifiedPhysicalPrinters()
    {
        var printers = new List<PhysicalPrinterDescriptor>();
        foreach (string name in WindowsPrinters.EnumerateDestinationNames())
        {
            try
            {
                PhysicalPrinterDescriptor candidate = WindowsPrinters.Inspect(name);
                if (candidate.IsVerifiedPhysical)
                {
                    printers.Add(candidate);
                }
            }
            catch (Exception exception) when (exception is InvalidOperationException
                or InvalidDataException
                or PrintQueueException
                or Win32Exception
                or IOException)
            {
                // A malformed or unavailable queue is never offered as a print
                // target. Selecting it explicitly still reports the details.
            }
        }

        return printers
            .OrderBy(printer => printer.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(printer => printer.Name, StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// The first verified physical printer, or <see langword="null"/>.
    /// </summary>
    public static string? FirstValidPhysicalPrinter() =>
        new KeySheetService().GetVerifiedPhysicalPrinters().FirstOrDefault()?.Name;

    public PhysicalPrinterDescriptor EnsurePhysicalPrinter(string? printerName)
    {
        if (string.IsNullOrWhiteSpace(printerName))
        {
            throw new InvalidOperationException("No printer was selected.");
        }

        PhysicalPrinterDescriptor descriptor = WindowsPrinters.Inspect(printerName);
        if (!descriptor.IsVerifiedPhysical)
        {
            throw new InvalidOperationException(
                $"The print target '{printerName}' is not verified as a physical printer: {descriptor.VerificationMessage} "
                + "Virtual PDF, XPS, OneNote, fax and file destinations are blocked. For testing, only the explicitly separated test-PDF export is available.");
        }

        return descriptor;
    }

    /// <summary>
    /// Sends sheet A, the separating installation page, and sheet B to a
    /// verified physical printer.
    /// </summary>
    /// <remarks>
    /// The pages are drawn straight onto the printer device context, so no PDF
    /// and no rasterised page ever reaches the file system. The spooler, the
    /// driver and the printer necessarily remain outside any memory control
    /// this process can exercise.
    ///
    /// GDI printing is used rather than WPF's <c>System.Printing</c> job
    /// pipeline because some drivers — the generic Microsoft IPP Class Driver
    /// among them — fail every PrintTicket/DEVMODE conversion with 0x80004005,
    /// which makes the WPF path unusable even for choosing a different printer.
    /// </remarks>
    public KeySheetPrintResult PrintKeySheets(string printerName, KeySheetData data)
    {
        ValidatedKeySheetData validated = Validate(data);

        // Re-query immediately before submission. The spooler exposes no
        // transactional handle that would bind queue inspection and job
        // submission atomically, so the check is repeated as late as possible.
        PhysicalPrinterDescriptor printer = EnsurePhysicalPrinter(printerName);

        using var printDocument = new PrintDocument();
        printDocument.PrinterSettings.PrinterName = printer.Name;
        if (!printDocument.PrinterSettings.IsValid)
        {
            throw new InvalidOperationException(
                $"The selected printer '{printer.Name}' reports an invalid configuration (driver or DEVMODE problem). "
                + "Choose a different printer or reinstall the printer driver.");
        }

        printDocument.DocumentName = $"{ProductName} separated key sheets";
        printDocument.OriginAtMargins = false;
        printDocument.DefaultPageSettings.Margins = new Margins(0, 0, 0, 0);

        PhysicalPrinterDescriptor immediatePrinter = EnsurePhysicalPrinter(printerName);
        if (printer.Evidence != immediatePrinter.Evidence
            || !string.Equals(printer.PortName, immediatePrinter.PortName, StringComparison.Ordinal)
            || !string.Equals(printer.DriverName, immediatePrinter.DriverName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The physical print target changed while the job was being prepared.");
        }

        int pageIndex = 0;
        Exception? renderFailure = null;
        printDocument.PrintPage += (_, printPageEventArgs) =>
        {
            try
            {
                System.Drawing.Graphics? graphics = printPageEventArgs.Graphics;
                if (graphics is not null)
                {
                    // PageBounds is in hundredths of an inch; the layout works
                    // in points, and the sheet is centred on whatever paper the
                    // driver actually reports.
                    double pageWidthPoints = printPageEventArgs.PageBounds.Width * 72.0 / 100.0;
                    double pageHeightPoints = printPageEventArgs.PageBounds.Height * 72.0 / 100.0;
                    double offsetX = Math.Max(0, (pageWidthPoints - KeySheetLayout.A4WidthPoints) / 2);
                    double offsetY = Math.Max(0, (pageHeightPoints - KeySheetLayout.A4HeightPoints) / 2);
                    using var canvas = new GdiSheetCanvas(
                        graphics,
                        KeySheetLayout.A4WidthPoints,
                        KeySheetLayout.A4HeightPoints,
                        offsetX,
                        offsetY);
                    switch (pageIndex)
                    {
                        case 0:
                            KeySheetLayout.DrawSheet(canvas, validated, KeySheetFactor.First, separatedByBlankPage: true);
                            break;
                        case 1:
                            KeySheetLayout.DrawInstallationPage(canvas, validated.English);
                            break;
                        default:
                            KeySheetLayout.DrawSheet(canvas, validated, KeySheetFactor.Second, separatedByBlankPage: true);
                            break;
                    }
                }
            }
            catch (Exception exception)
            {
                renderFailure ??= exception;
            }

            pageIndex++;
            printPageEventArgs.HasMorePages = pageIndex < 3;
        };

        try
        {
            printDocument.Print();
        }
        catch (Exception ex) when (ex is InvalidPrinterException or Win32Exception or ExternalException)
        {
            throw new InvalidOperationException(
                $"The printer '{printer.Name}' refused the print job (driver or DEVMODE problem). Choose a different physical printer, "
                + "or install the manufacturer's driver for this device instead of the generic \"Microsoft IPP Class Driver\".",
                ex);
        }

        if (renderFailure is not null)
        {
            throw new InvalidOperationException("The key sheets could not be rendered for printing.", renderFailure);
        }

        return new KeySheetPrintResult(immediatePrinter, printDocument.DocumentName, DateTimeOffset.Now);
    }

    /// <summary>
    /// Binds a printed sheet to exactly one archive path, suite and factor pair.
    /// </summary>
    /// <remarks>
    /// The same dual-digest construction and the same domain separator as the
    /// macOS build, over the canonical Windows target path. Case is folded
    /// because NTFS resolves names case-insensitively, so two spellings of one
    /// path are one archive and must not produce two fingerprints.
    /// </remarks>
    public static string BuildBindingFingerprint(KeySheetData data)
    {
        ValidatedKeySheetData validated = Validate(data);
        using LockedSensitiveBuffer pathBytes = LockedSensitiveBuffer.Encode(
            validated.CanonicalArchivePath.ToUpperInvariant(),
            Encoding.UTF8);
        using LockedSensitiveBuffer suiteBytes = LockedSensitiveBuffer.Encode(validated.Suite.ToString(), Encoding.ASCII);
        using LockedSensitiveBuffer firstBytes = LockedSensitiveBuffer.Encode(validated.FirstGeneratedPassword, Encoding.ASCII);
        using LockedSensitiveBuffer secondBytes = LockedSensitiveBuffer.Encode(validated.SecondGeneratedPassword, Encoding.ASCII);
        using LockedSensitiveBuffer sha3Fingerprint = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
        using LockedSensitiveBuffer skeinFingerprint = LockedSensitiveBuffer.Create(Skein1024Digest.DigestSize);

        // The repository's own SHA3-512 rather than the platform's. Windows
        // only exposes SHA3 through CNG from Windows 11 24H2 onwards, so the
        // platform implementation throws PlatformNotSupportedException on every
        // older machine - and the throw would land on the key-sheet gate, which
        // is the one step between generating factors and encrypting with them.
        // It is also what the macOS build uses, so a fingerprint computed on
        // one platform matches the other by construction.
        using var sha3 = new Sha3_512Incremental();
        using var skein = new Skein1024Digest();

        AppendFingerprintPart(sha3, skein, "Kalyna-ZPAQ/v9/key-sheet-fingerprint"u8);
        AppendFingerprintPart(sha3, skein, pathBytes.Bytes);
        AppendFingerprintPart(sha3, skein, suiteBytes.Bytes);
        AppendFingerprintPart(sha3, skein, firstBytes.Bytes);
        AppendFingerprintPart(sha3, skein, secondBytes.Bytes);
        int sha3Written = sha3.GetHashAndReset(sha3Fingerprint.Bytes);
        if (sha3Written != Sha3_512Compat.HashSizeInBytes)
        {
            throw new CryptographicException("SHA3-512 returned an invalid key-sheet fingerprint length.");
        }

        skein.GetHashAndReset(skeinFingerprint.Bytes);
        return $"{Convert.ToHexString(sha3Fingerprint.Bytes)}:{Convert.ToHexString(skeinFingerprint.Bytes)}";
    }

    public static string BuildKeySheetFingerprint(
        string archivePath,
        EncryptionSuite suite,
        string firstGeneratedPassword,
        string secondGeneratedPassword)
    {
        return BuildBindingFingerprint(new KeySheetData(
            archivePath,
            suite,
            firstGeneratedPassword,
            secondGeneratedPassword,
            DateTime.Now));
    }

    public static byte[] CreateQrPng(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        using var generator = new QRCodeGenerator();
        QRCodeData qrData = generator.CreateQrCode(normalized, QRCodeGenerator.ECCLevel.Q);
        try
        {
            // Not a using: PngByteQRCode.Dispose() disposes the QRCodeData it
            // was handed and nulls its matrix. The matrix holds the factor, so
            // it has to be overwritten while it is still there - and the
            // earlier arrangement instead threw a NullReferenceException on the
            // way out, leaving the key material to the allocator.
            var png = new PngByteQRCode(qrData);
            return png.GetGraphic(6);
        }
        finally
        {
            KeySheetLayout.ClearQrMatrix(qrData);
            qrData.Dispose();
        }
    }

    public static string GroupGeneratedPassword(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        return string.Join(' ', Enumerable.Range(0, normalized.Length / 8)
            .Select(index => normalized.Substring(index * 8, 8)));
    }

    /// <summary>
    /// The machine the archive was created on, as its owner named it.
    /// </summary>
    /// <remarks>
    /// With several computers in a household this is often the only remaining
    /// clue to where the archive itself ended up. The platform is appended so a
    /// sheet found next to a Mac's sheet is still identifiable.
    /// </remarks>
    internal static string ResolveDeviceName()
    {
        string resolved;
        try
        {
            resolved = Environment.MachineName.Trim();
        }
        catch (InvalidOperationException)
        {
            resolved = string.Empty;
        }

        if (resolved.Length == 0)
        {
            resolved = "Unknown";
        }

        return $"{resolved} (Windows)";
    }

    internal static ValidatedKeySheetData Validate(KeySheetData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        _ = EncryptionSuiteCatalog.Get(data.Suite);
        string first = PasswordKeyService.NormalizeGeneratedPassword(data.FirstGeneratedPassword);
        string second = PasswordKeyService.NormalizeGeneratedPassword(data.SecondGeneratedPassword);
        if (string.Equals(first, second, StringComparison.Ordinal))
        {
            throw new ArgumentException("Factors A and B must differ.", nameof(data));
        }

        string canonicalArchivePath = WindowsCanonicalPath.CanonicalizeCreatableFile(data.ArchivePath);
        string deviceName = string.IsNullOrWhiteSpace(data.DeviceName)
            ? ResolveDeviceName()
            : data.DeviceName.Trim();
        return new ValidatedKeySheetData(
            canonicalArchivePath,
            data.Suite,
            EncryptionSuiteCatalog.DisplayName(data.Suite, data.English),
            first,
            second,
            data.CreatedAt,
            data.English,
            deviceName);
    }

    /// <summary>
    /// One factor's sheet plus the public installation page.
    /// </summary>
    private static PdfDocument CreateSingleSheetDocument(ValidatedKeySheetData data, KeySheetFactor factor)
    {
        var document = new PdfDocument();
        document.Info.Title = data.English
            ? $"{ProductName} key sheet {(factor == KeySheetFactor.First ? "A" : "B")}"
            : $"{ProductName} Schlüsselzettel {(factor == KeySheetFactor.First ? "A" : "B")}";
        document.Info.Author = ProductName;
        DrawPage(document, canvas => KeySheetLayout.DrawSheet(canvas, data, factor, separatedByBlankPage: false));
        DrawPage(document, canvas => KeySheetLayout.DrawInstallationPage(canvas, data.English));
        return document;
    }

    private static void DrawPage(PdfDocument document, Action<ISheetCanvas> body)
    {
        PdfPage page = document.AddPage();
        page.Width = XUnit.FromMillimeter(210);
        page.Height = XUnit.FromMillimeter(297);
        using var canvas = new PdfSheetCanvas(page);
        body(canvas);
    }

    private static void WriteSheet(ValidatedKeySheetData validated, KeySheetFactor factor, string pdfPath)
    {
        string targetPath = WindowsCanonicalPath.CanonicalizeCreatableFile(pdfPath);
        FileStream? output = null;
        try
        {
            output = WindowsSecretFile.CreateExclusive(targetPath);
            using PdfDocument document = CreateSingleSheetDocument(validated, factor);
            document.Save(output, closeStream: false);
            output.Flush(flushToDisk: true);
        }
        catch
        {
            if (output is not null)
            {
                TryDestroyOpenPartialTestExport(output, targetPath);
                output = null;
            }

            throw;
        }
        finally
        {
            output?.Dispose();
        }
    }

    private static void TryDestroyExport(string path)
    {
        try
        {
            SecureFile.DestroyPrefixAndSuffixAndDelete(path, 1024 * 1024, 1024 * 1024);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or Win32Exception)
        {
            // Preserve the exception that interrupted the explicit export.
        }
    }

    private static void TryDestroyOpenPartialTestExport(FileStream output, string expectedPath)
    {
        byte[] buffer = new byte[1024 * 1024];
        IDisposable? memoryLock = null;
        try
        {
            memoryLock = SecureMemory.TryLock(buffer);
            int prefixLength = checked((int)Math.Min(buffer.Length, output.Length));
            if (prefixLength > 0)
            {
                RandomNumberGenerator.Fill(buffer.AsSpan(0, prefixLength));
                output.Position = 0;
                output.Write(buffer, 0, prefixLength);
            }

            int suffixLength = checked((int)Math.Min(buffer.Length, output.Length));
            if (suffixLength > 0)
            {
                RandomNumberGenerator.Fill(buffer.AsSpan(0, suffixLength));
                output.Position = output.Length - suffixLength;
                output.Write(buffer, 0, suffixLength);
            }

            output.Flush(flushToDisk: true);
            output.Dispose();
            output = null!;
            File.Delete(expectedPath);
        }
        catch
        {
            // Preserve the exception that interrupted the explicit export.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            memoryLock?.Dispose();
            output?.Dispose();
        }
    }

    private static void AppendFingerprintPart(
        Sha3_512Incremental sha3,
        Skein1024Digest skein,
        ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, value.Length);
        sha3.AppendData(length);
        sha3.AppendData(value);
        skein.AppendData(length);
        skein.AppendData(value);
        CryptographicOperations.ZeroMemory(length);
    }

    private static void EnsurePdfFontResolver()
    {
        lock (FontResolverGate)
        {
            GlobalFontSettings.FontResolver ??= WindowsFontResolver.Instance;
        }
    }
}

public enum KeySheetFactor
{
    First,
    Second,
}

/// <summary>
/// Everything a printed key sheet shows.
/// </summary>
/// <param name="English">
/// Renders the sheets in English rather than German. A sheet is read years
/// later, possibly by someone else, so it follows the language the app was
/// being used in rather than the machine locale at print time.
/// </param>
/// <param name="DeviceName">
/// The machine the archive was created on. With several computers in a
/// household this is often the only remaining clue to where the archive itself
/// ended up.
/// </param>
public sealed record KeySheetData(
    string ArchivePath,
    EncryptionSuite Suite,
    string FirstGeneratedPassword,
    string SecondGeneratedPassword,
    DateTime CreatedAt,
    bool English = false,
    string DeviceName = "");

internal sealed record ValidatedKeySheetData(
    string CanonicalArchivePath,
    EncryptionSuite Suite,
    string SuiteDisplayName,
    string FirstGeneratedPassword,
    string SecondGeneratedPassword,
    DateTime CreatedAt,
    bool English,
    string DeviceName);

/// <summary>
/// What the local spooler can actually prove about a queue's device.
/// </summary>
public enum PhysicalPrinterEvidence
{
    None = 0,

    /// <summary>A directly attached bus port: USB, DOT4, parallel or serial.</summary>
    LocalHardwarePort = 1,

    /// <summary>A network port bound to a concrete host: TCP/IP or WSD.</summary>
    NetworkDevicePort = 2,
}

public sealed record PhysicalPrinterDescriptor(
    string Name,
    string DisplayName,
    string DriverName,
    string PortName,
    bool IsAcceptingJobs,
    PhysicalPrinterEvidence Evidence,
    string VerificationMessage)
{
    public bool IsVerifiedPhysical => IsAcceptingJobs && Evidence != PhysicalPrinterEvidence.None;
}

public sealed record KeySheetPrintResult(
    PhysicalPrinterDescriptor Printer,
    string SpoolerReceipt,
    DateTimeOffset SubmittedAt);

/// <summary>
/// Decides whether a print queue names a real piece of hardware.
/// </summary>
/// <remarks>
/// A name blocklist alone is not enough — "Microsoft Print to PDF" can be
/// renamed, and a renamed virtual printer would then be offered as a place to
/// send a 512-bit key. The port is the part the spooler derives from the
/// device rather than from a label, so the decision rests on it: a USB, DOT4,
/// LPT, COM, TCP/IP or WSD port is evidence of a device, and PORTPROMPT, FILE,
/// NUL and driver-owned ports are evidence of the opposite. The name check
/// stays as a second, independent reason to refuse.
/// </remarks>
internal static class WindowsPrinters
{
    private static readonly string[] VirtualNameMarkers =
        ["pdf", "xps", "onenote", "fax", "send to", "print to file", "microsoft print"];

    private static readonly string[] VirtualPortMarkers =
        ["portprompt", "file:", "nul:", "onenote", "xpsport", "pdfport", "shrfax", "fax:"];

    private static readonly string[] HardwarePortPrefixes =
        ["usb", "dot4", "lpt", "com", "1394", "hpr"];

    private static readonly string[] NetworkPortPrefixes =
        ["ip_", "wsd-", "wsd_", "tcpmon", "standard tcp/ip port", "\\\\"];

    private const int MaximumPrinterNameLength = 220;

    internal static IReadOnlyList<string> EnumerateDestinationNames()
    {
        var names = new List<string>();
        foreach (string? name in PrinterSettings.InstalledPrinters)
        {
            if (!string.IsNullOrWhiteSpace(name) && IsValidDestinationName(name))
            {
                names.Add(name);
            }
        }

        return names;
    }

    internal static PhysicalPrinterDescriptor Inspect(string printerName)
    {
        RequireValidDestinationName(printerName);
        using var server = new LocalPrintServer();
        using PrintQueue queue = server.GetPrintQueue(printerName);
        string port = queue.QueuePort?.Name ?? string.Empty;
        string driver = queue.QueueDriver?.Name ?? string.Empty;
        string display = string.IsNullOrWhiteSpace(queue.FullName) ? queue.Name : queue.FullName;
        bool accepting = !queue.IsNotAvailable && !queue.IsOffline && queue.QueueStatus != PrintQueueStatus.Error;

        (PhysicalPrinterEvidence evidence, string message) = Classify(printerName, display, driver, port);
        return new PhysicalPrinterDescriptor(
            queue.Name,
            display,
            driver,
            port,
            accepting,
            evidence,
            accepting
                ? message
                : $"{message} The queue is offline, unavailable or in an error state.");
    }

    private static (PhysicalPrinterEvidence Evidence, string Message) Classify(
        string printerName,
        string displayName,
        string driverName,
        string portName)
    {
        string haystack = $"{printerName} {displayName} {driverName}";
        foreach (string marker in VirtualNameMarkers)
        {
            if (haystack.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return (PhysicalPrinterEvidence.None,
                    $"The queue names a virtual destination ('{marker}').");
            }
        }

        string port = portName.Trim();
        if (port.Length == 0)
        {
            return (PhysicalPrinterEvidence.None, "The queue reports no port.");
        }

        foreach (string marker in VirtualPortMarkers)
        {
            if (port.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return (PhysicalPrinterEvidence.None,
                    $"The queue is bound to a virtual port ('{port}').");
            }
        }

        foreach (string prefix in HardwarePortPrefixes)
        {
            if (port.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return (PhysicalPrinterEvidence.LocalHardwarePort,
                    $"Directly attached device port '{port}'.");
            }
        }

        foreach (string prefix in NetworkPortPrefixes)
        {
            if (port.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return (PhysicalPrinterEvidence.NetworkDevicePort,
                    $"Network device port '{port}'.");
            }
        }

        return (PhysicalPrinterEvidence.None,
            $"The port '{port}' provides no evidence of a physical device.");
    }

    internal static bool IsValidDestinationName(string name)
    {
        return !string.IsNullOrWhiteSpace(name)
            && name.Length <= MaximumPrinterNameLength
            && !name.Any(character => char.IsControl(character));
    }

    internal static void RequireValidDestinationName(string name)
    {
        if (!IsValidDestinationName(name))
        {
            throw new InvalidOperationException("The printer name is empty, over-long or contains control characters.");
        }
    }
}

/// <summary>
/// Resolves the archive target through the file system rather than trusting the
/// text in the box.
/// </summary>
/// <remarks>
/// The key sheet is bound to a path, so the path has to be the one the file
/// system will actually use. A junction, a symbolic link or a substituted drive
/// would otherwise let two different-looking paths name one archive, or one
/// path name two, and either breaks the binding the sheet exists to carry.
/// </remarks>
internal static partial class WindowsCanonicalPath
{
    private const uint FileReadAttributes = 0x0080;
    private const uint ShareAll = 0x00000007;
    private const uint OpenExisting = 3;

    // Without this flag CreateFileW refuses a directory outright, which is why
    // the framework's own File.OpenHandle cannot be used here: it does not set
    // it, and every attempt to resolve a folder came back as access denied.
    private const uint FileFlagBackupSemantics = 0x02000000;

    internal static string CanonicalizeCreatableFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        string? fileName = Path.GetFileName(fullPath);
        string? parent = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(fileName) || string.IsNullOrWhiteSpace(parent))
        {
            throw new ArgumentException("The target path must name a file inside an existing folder.", nameof(path));
        }

        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException($"The target folder does not exist: {parent}");
        }

        using SafeFileHandle parentHandle = CreateDirectoryHandle(
            parent,
            FileReadAttributes,
            ShareAll,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);
        if (parentHandle.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                $"The target folder could not be opened for canonical resolution: {parent}");
        }

        string resolvedParent = NativePathResolver.ResolveFinalDosPath(parentHandle);
        string canonicalPath = Path.Combine(resolvedParent, fileName);
        if (Directory.Exists(canonicalPath))
        {
            throw new IOException($"The target path names a folder rather than a file: {canonicalPath}");
        }

        if (File.Exists(canonicalPath)
            && (File.GetAttributes(canonicalPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"The target path is a reparse point: {canonicalPath}");
        }

        return canonicalPath;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial SafeFileHandle CreateDirectoryHandle(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);
}

/// <summary>
/// Creates the explicit test export so that only its owner can read it.
/// </summary>
/// <remarks>
/// <see cref="FileMode.CreateNew"/> refuses to overwrite: an export must never
/// silently replace a file, least of all the other factor's sheet. The
/// discretionary ACL is written explicitly rather than inherited, because an
/// export dropped into a shared folder would otherwise be readable by everyone
/// that folder is shared with.
/// </remarks>
internal static class WindowsSecretFile
{
    internal static FileStream CreateExclusive(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var security = new FileSecurity();
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier owner = identity.User
            ?? throw new InvalidOperationException("The current Windows identity has no user SID.");
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        return FileSystemAclExtensions.Create(
            new FileInfo(path),
            FileMode.CreateNew,
            FileSystemRights.FullControl,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.WriteThrough,
            security);
    }
}

/// <summary>
/// The only fonts a key sheet may be set in.
/// </summary>
/// <remarks>
/// An allowlist rather than a fallback: silently substituting a face changes
/// the metrics the layout was measured against, and the factor block is the
/// part that would overflow. Courier New is present because the factor is set
/// monospaced on both platforms and must group identically.
/// </remarks>
internal sealed class WindowsFontResolver : IFontResolver
{
    private const int MaximumFontBytes = 64 * 1024 * 1024;
    public static readonly WindowsFontResolver Instance = new();

    private static readonly IReadOnlyDictionary<string, string> FontFiles = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["arial"] = "arial.ttf",
        ["arial-bold"] = "arialbd.ttf",
        ["courier-new"] = "cour.ttf",
        ["courier-new-bold"] = "courbd.ttf",
    };

    private WindowsFontResolver()
    {
    }

    public FontResolverInfo ResolveTypeface(string familyName, bool bold, bool italic)
    {
        bool courier = familyName.Contains("courier", StringComparison.OrdinalIgnoreCase)
            || familyName.Contains("mono", StringComparison.OrdinalIgnoreCase)
            || familyName.Contains("consol", StringComparison.OrdinalIgnoreCase);
        string face = courier
            ? bold ? "courier-new-bold" : "courier-new"
            : bold ? "arial-bold" : "arial";
        return new FontResolverInfo(face, mustSimulateBold: false, mustSimulateItalic: italic);
    }

    public byte[] GetFont(string faceName)
    {
        if (!FontFiles.TryGetValue(faceName, out string? fileName))
        {
            throw new InvalidOperationException($"The PDF font '{faceName}' is not permitted.");
        }

        string fontPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Fonts",
            fileName);
        if (!File.Exists(fontPath))
        {
            throw new FileNotFoundException($"PDF font not found: {fontPath}", fontPath);
        }

        using var stream = new FileStream(
            fontPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 or > MaximumFontBytes)
        {
            throw new InvalidDataException($"PDF font has an invalid bounded length: {fontPath}");
        }

        byte[] font = new byte[checked((int)stream.Length)];
        stream.ReadExactly(font);
        return font;
    }
}
