using System.Buffers.Binary;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Signing;
using Microsoft.Win32.SafeHandles;
using PdfSharp.Drawing;
using PdfSharp.Drawing.Layout;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using QRCoder;

namespace KalynaArchiver.Services;

/// <summary>
/// Creates the two independent Keep Vault key sheets and submits them to a
/// conservatively verified physical CUPS destination on macOS.
/// </summary>
public sealed class KeySheetService
{
    private const string ProductName = "Keep Vault";
    private static readonly object FontResolverGate = new();

    /// <summary>
    /// Explicitly writes a persistent test PDF. The normal print path never calls
    /// this method and transports its in-memory PDF directly to the CUPS pipe.
    /// Existing files are intentionally not overwritten.
    /// </summary>
    /// <summary>
    /// Writes the two key sheets as two separate files.
    /// </summary>
    /// <remarks>
    /// The whole scheme rests on factor A and factor B never being in one
    /// place. A single export file quietly undid that: it put both halves of
    /// the key in one object, on one disk, in one backup. Each factor now gets
    /// its own file so the separation survives the digital step too, and each
    /// carries the public installation page so either one is useful on its own.
    /// </remarks>
    public void SaveTestPdf(KeySheetData data, string firstPdfPath, string secondPdfPath)
    {
        ValidatedKeySheetData validated = Validate(data);
        ArgumentException.ThrowIfNullOrWhiteSpace(firstPdfPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(secondPdfPath);
        if (string.Equals(
                Path.GetFullPath(firstPdfPath),
                Path.GetFullPath(secondPdfPath),
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Die beiden Faktoren dürfen nicht in dieselbe Datei geschrieben werden.",
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
            TryDelete(firstPdfPath);
            throw;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            string full = MacCanonicalPath.CanonicalizeCreatableFile(path);
            if (File.Exists(full))
            {
                File.Delete(full);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void WriteSheet(ValidatedKeySheetData validated, KeySheetFactor factor, string pdfPath)
    {
        string targetPath = MacCanonicalPath.CanonicalizeCreatableFile(pdfPath);
        FileStream? output = null;
        try
        {
            output = MacSecretFile.CreateExclusive(targetPath);
            using PdfDocument document = CreateSingleSheetDocument(validated, factor);
            document.Save(output, closeStream: false);
            output.Flush(flushToDisk: true);
            MacSafeFileSystem.FullSync(output.SafeFileHandle);
            MacSafeFileSystem.RequirePathStillNamesHandle(output.SafeFileHandle, targetPath);
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

    /// <summary>
    /// Returns only destinations for which the local CUPS configuration provides
    /// direct physical-device evidence. Ambiguous network queues and all virtual
    /// file/fax destinations are excluded.
    /// </summary>
    public async Task<IReadOnlyList<PhysicalPrinterDescriptor>> GetVerifiedPhysicalPrintersAsync(
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<string> names = await MacCupsPrinter.EnumerateDestinationNamesAsync(cancellationToken)
            .ConfigureAwait(false);
        var printers = new List<PhysicalPrinterDescriptor>(names.Count);
        foreach (string name in names)
        {
            try
            {
                PhysicalPrinterDescriptor candidate = await MacCupsPrinter.InspectAsync(name, cancellationToken)
                    .ConfigureAwait(false);
                if (candidate.IsVerifiedPhysical)
                {
                    printers.Add(candidate);
                }
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested
                && exception is InvalidOperationException or InvalidDataException or TimeoutException or IOException)
            {
                // A malformed or unavailable queue is never offered as a print target.
                // Exact selection through EnsurePhysicalPrinterAsync still reports details.
            }
        }

        return printers
            .OrderBy(printer => printer.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(printer => printer.Name, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<PhysicalPrinterDescriptor?> FirstValidPhysicalPrinterAsync(
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<PhysicalPrinterDescriptor> printers =
            await GetVerifiedPhysicalPrintersAsync(cancellationToken).ConfigureAwait(false);
        return printers.FirstOrDefault();
    }

    public static string? FirstValidPhysicalPrinter()
    {
        return new KeySheetService()
            .FirstValidPhysicalPrinterAsync()
            .GetAwaiter()
            .GetResult()
            ?.Name;
    }

    public async Task<PhysicalPrinterDescriptor> EnsurePhysicalPrinterAsync(
        string? printerName,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(printerName))
        {
            throw new InvalidOperationException("Es wurde kein Drucker ausgewählt.");
        }

        PhysicalPrinterDescriptor descriptor =
            await MacCupsPrinter.InspectInstalledAsync(printerName, cancellationToken).ConfigureAwait(false);
        if (!descriptor.IsVerifiedPhysical)
        {
            throw new InvalidOperationException(
                $"Das Druckziel '{printerName}' ist nicht als physischer Drucker verifiziert: {descriptor.VerificationMessage} " +
                "Virtuelle PDF-, Fax- und Dateiziele sind gesperrt. Für Tests steht ausschließlich der ausdrücklich getrennte Test-PDF-Export zur Verfügung.");
        }

        return descriptor;
    }

    public static void EnsurePhysicalPrinter(string? printerName)
    {
        _ = new KeySheetService()
            .EnsurePhysicalPrinterAsync(printerName)
            .GetAwaiter()
            .GetResult();
    }

    /// <summary>
    /// Sends page A, an actually empty PDF page, and page B to a verified physical
    /// printer. The generated PDF remains in locked process memory until it is
    /// streamed into the Apple-signed /usr/bin/lp process. CUPS and the printer
    /// driver necessarily remain outside Keep Vault's memory-control boundary.
    /// </summary>
    public async Task<KeySheetPrintResult> PrintKeySheetsAsync(
        string printerName,
        KeySheetData data,
        CancellationToken cancellationToken = default)
    {
        ValidatedKeySheetData validated = Validate(data);

        // Re-query immediately before submission. CUPS exposes no transactional
        // handle that would bind queue inspection and job submission atomically.
        PhysicalPrinterDescriptor printer =
            await EnsurePhysicalPrinterAsync(printerName, cancellationToken).ConfigureAwait(false);

        EnsurePdfFontResolver();
        using var pdf = new SensitiveBufferStream(initialCapacity: 256 * 1024);
        using (PdfDocument document = CreatePdfDocument(validated))
        {
            document.Save(pdf, closeStream: false);
        }

        PhysicalPrinterDescriptor immediatePrinter =
            await EnsurePhysicalPrinterAsync(printerName, cancellationToken).ConfigureAwait(false);
        if (printer.Evidence != immediatePrinter.Evidence
            || !string.Equals(printer.DeviceUri, immediatePrinter.DeviceUri, StringComparison.Ordinal)
            || !string.Equals(printer.MakeAndModel, immediatePrinter.MakeAndModel, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Das physische CUPS-Druckziel wurde während der Auftragsvorbereitung verändert.");
        }

        pdf.Position = 0;
        string receipt = await MacCupsPrinter.SubmitPdfAsync(
            immediatePrinter.Name,
            pdf.GetWrittenMemory(),
            cancellationToken).ConfigureAwait(false);
        return new KeySheetPrintResult(immediatePrinter, receipt, DateTimeOffset.Now);
    }

    public KeySheetPrintResult PrintKeySheets(string printerName, KeySheetData data)
    {
        return PrintKeySheetsAsync(printerName, data).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Computes the same dual-digest binding concept as the Windows reference,
    /// but binds the case-sensitive, NFC-normalized macOS canonical target path.
    /// The ordered A and B factors are both included.
    /// </summary>
    public static string BuildBindingFingerprint(KeySheetData data)
    {
        ValidatedKeySheetData validated = Validate(data);
        using LockedSensitiveBuffer pathBytes = LockedSensitiveBuffer.Encode(validated.CanonicalArchivePath, Encoding.UTF8);
        using LockedSensitiveBuffer suiteBytes = LockedSensitiveBuffer.Encode(validated.Suite.ToString(), Encoding.ASCII);
        using LockedSensitiveBuffer firstBytes = LockedSensitiveBuffer.Encode(validated.FirstGeneratedPassword, Encoding.ASCII);
        using LockedSensitiveBuffer secondBytes = LockedSensitiveBuffer.Encode(validated.SecondGeneratedPassword, Encoding.ASCII);
        using LockedSensitiveBuffer sha3Fingerprint = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
        using LockedSensitiveBuffer skeinFingerprint = LockedSensitiveBuffer.Create(Skein1024Digest.DigestSize);
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
        using QRCodeData qrData = generator.CreateQrCode(normalized, QRCodeGenerator.ECCLevel.Q);
        try
        {
            using var png = new PngByteQRCode(qrData);
            return png.GetGraphic(6);
        }
        finally
        {
            ClearQrMatrix(qrData);
        }
    }

    public static string GroupGeneratedPassword(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        return string.Join(' ', Enumerable.Range(0, normalized.Length / 8)
            .Select(index => normalized.Substring(index * 8, 8)));
    }

    private static ValidatedKeySheetData Validate(KeySheetData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        EncryptionSuiteParameters suite = EncryptionSuiteCatalog.Get(data.Suite);
        string first = PasswordKeyService.NormalizeGeneratedPassword(data.FirstGeneratedPassword);
        string second = PasswordKeyService.NormalizeGeneratedPassword(data.SecondGeneratedPassword);
        if (string.Equals(first, second, StringComparison.Ordinal))
        {
            throw new ArgumentException("Die Faktoren A und B müssen verschieden sein.", nameof(data));
        }

        string canonicalArchivePath = MacCanonicalPath.CanonicalizeCreatableFile(data.ArchivePath);
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
    /// The page the app can be downloaded and verified from.
    /// </summary>
    /// <remarks>
    /// A key sheet outlives the computer it was printed on. Whoever finds it
    /// later needs to know what it belongs to and where to get the program that
    /// reads it, so the address is on the paper rather than only in the app.
    /// </remarks>
    private const string ProjectUrl = "https://github.com/michael-feinermann/keep-vault";

    /// <summary>
    /// No text on a key sheet is ever smaller than this.
    /// </summary>
    /// <remarks>
    /// These sheets are read under stress, often years later and often by
    /// someone older than the person who printed them. A hex factor misread by
    /// one character is unrecoverable, so legibility is a security property
    /// here, not a matter of taste.
    /// </remarks>
    private const double MinimumFontSize = 16;

    private const string SystemConfigurationLibrary =
        "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration";
    private const string CoreFoundationLibrary =
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const uint Utf8Encoding = 0x08000100;

    [DllImport(SystemConfigurationLibrary, EntryPoint = "SCDynamicStoreCopyComputerName")]
    private static extern IntPtr CopyComputerName(IntPtr store, IntPtr nameEncoding);

    [DllImport(CoreFoundationLibrary, EntryPoint = "CFStringGetCString")]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool CopyCString(IntPtr value, byte[] buffer, nint size, uint encoding);

    [DllImport(CoreFoundationLibrary, EntryPoint = "CFRelease")]
    private static extern void ReleaseCoreFoundation(IntPtr value);

    /// <summary>
    /// The name this machine answers to, as its owner set it, with the platform
    /// beside it.
    /// </summary>
    /// <remarks>
    /// Environment.MachineName returns the network hostname, which macOS derives
    /// by sanitising the real name: a computer the owner called "MacBook Pro"
    /// reports itself as "Mac". A key sheet is read years later, quite possibly
    /// in a household with several machines, and "Mac" narrows that down to
    /// nothing. The name the owner would recognise comes from the system
    /// configuration; the hostname is kept only as a fallback.
    /// </remarks>
    private static string ResolveDeviceName()
    {
        string resolved = string.Empty;
        IntPtr name = IntPtr.Zero;
        try
        {
            name = CopyComputerName(IntPtr.Zero, IntPtr.Zero);
            if (name != IntPtr.Zero)
            {
                byte[] buffer = new byte[512];
                if (CopyCString(name, buffer, buffer.Length, Utf8Encoding))
                {
                    int end = Array.IndexOf(buffer, (byte)0);
                    resolved = Encoding.UTF8
                        .GetString(buffer, 0, end < 0 ? buffer.Length : end)
                        .Trim();
                }
            }
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            resolved = string.Empty;
        }
        finally
        {
            if (name != IntPtr.Zero)
            {
                ReleaseCoreFoundation(name);
            }
        }

        if (resolved.Length == 0)
        {
            resolved = Environment.MachineName;
        }

        return $"{resolved} (macOS)";
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
        DrawPdfSheet(document.AddPage(), data, factor, separatedByBlankPage: false);
        DrawInstallationPage(document.AddPage(), data.English);
        return document;
    }

    private static PdfDocument CreatePdfDocument(ValidatedKeySheetData data)
    {
        var document = new PdfDocument();
        document.Info.Title = data.English
            ? $"{ProductName} separated key sheets"
            : $"{ProductName} getrennte Schlüsselzettel";
        document.Info.Author = ProductName;
        DrawPdfSheet(document.AddPage(), data, KeySheetFactor.First, separatedByBlankPage: true);

        // Page 2 separates factor A from factor B, and that separation is the
        // whole point of it: nothing derived from either factor may appear here.
        // It carries only the public installation instructions and the public
        // project address, so A and B still never share a sheet of paper — not
        // even through a duplex print or a page held up to the light.
        DrawInstallationPage(document.AddPage(), data.English);

        DrawPdfSheet(document.AddPage(), data, KeySheetFactor.Second, separatedByBlankPage: true);
        return document;
    }

    private static void DrawPdfSheet(
        PdfPage page,
        ValidatedKeySheetData data,
        KeySheetFactor factor,
        bool separatedByBlankPage)
    {
        SetA4(page);
        string generatedPassword = factor == KeySheetFactor.First
            ? data.FirstGeneratedPassword
            : data.SecondGeneratedPassword;
        string factorName = factor == KeySheetFactor.First ? "A" : "B";
        bool en = data.English;

        using XGraphics graphics = XGraphics.FromPdfPage(page);
        var titleFont = new XFont("Arial", 24, XFontStyleEx.Bold);
        var headingFont = new XFont("Arial", MinimumFontSize, XFontStyleEx.Bold);
        var normalFont = new XFont("Arial", MinimumFontSize);
        var warningFont = new XFont("Arial", MinimumFontSize, XFontStyleEx.Bold);
        var shoutFont = new XFont("Arial", 19, XFontStyleEx.Bold);

        // The factor is the one thing on this sheet that must never be misread,
        // so it is set at the same size as the heading announcing it.
        var monoFont = new XFont("Courier New", MinimumFontSize);
        var formatter = new XTextFormatter(graphics);

        const double margin = 42;
        const double bodyWidth = 500;
        double y = margin;

        graphics.DrawString(
            en ? $"{ProductName} key sheet {factorName}" : $"{ProductName} Schlüsselzettel {factorName}",
            titleFont,
            XBrushes.Black,
            new XPoint(margin, y));
        y += 30;

        // Flowed rather than clipped into a fixed rectangle: the two variants
        // differ in length and translate differently, and a warning that loses
        // its last line is worse than no warning at all.
        y += 4;
        DrawWrappedValue(
            graphics,
            warningFont,
            separatedByBlankPage
                ? (en
                    ? "Keep this key sheet separate from the other one. The page between A and B separates the two factors on purpose."
                    : "Diesen Schlüsselzettel getrennt vom anderen aufbewahren. Die Seite zwischen A und B trennt beide Faktoren absichtlich.")
                : (en
                    ? "Keep this key sheet separate from the other one. The other factor is in its own file."
                    : "Diesen Schlüsselzettel getrennt vom anderen aufbewahren. Der andere Faktor liegt in einer eigenen Datei."),
            margin,
            bodyWidth,
            ref y,
            XBrushes.DarkRed);
        y += 10;

        graphics.DrawString(
            en ? "DO NOT THROW AWAY!" : "NICHT WEGSCHMEISSEN!",
            shoutFont,
            XBrushes.Red,
            new XPoint(margin, y));
        y += 30;

        DrawLabelAndValue(graphics, headingFont, normalFont,
            en ? "Encryption suite" : "Verschlüsselungssuite",
            data.SuiteDisplayName, margin, bodyWidth, ref y);
        DrawLabelAndValue(graphics, headingFont, normalFont,
            en ? "Archive file" : "Archivdatei",
            Path.GetFileName(data.CanonicalArchivePath), margin, bodyWidth, ref y);
        DrawLabelAndValue(graphics, headingFont, normalFont,
            en ? "Created on device" : "Erstellt auf Gerät",
            data.DeviceName, margin, bodyWidth, ref y);
        DrawLabelAndValue(graphics, headingFont, normalFont,
            en ? "Storage location" : "Speicherort",
            Path.GetDirectoryName(data.CanonicalArchivePath) ?? data.CanonicalArchivePath,
            margin, bodyWidth, ref y);

        // Everything from the QR codes down is measured up from the bottom
        // edge. The fields above vary in height with the archive path, and the
        // codes and the download address are exactly the parts that must not be
        // the ones squeezed off the page when a path runs long.
        const double qrSize = 132;
        const double qrGap = 28;
        double footerBaseline = page.Height.Point - 24;
        double urlBaseline = footerBaseline - 26;
        double urlLabelBaseline = urlBaseline - 21;
        double qrTop = urlLabelBaseline - 22 - qrSize;
        double qrHeadingBaseline = qrTop - 10;

        graphics.DrawString(
            en
                ? "User password (write by hand, never store digitally)"
                : "Benutzerpasswort (von Hand eintragen, nicht digital speichern)",
            headingFont,
            XBrushes.Black,
            new XPoint(margin, y));

        // The password is written by hand and comes first: it is the part the
        // owner supplies, and reading the sheet top to bottom should follow the
        // order the factors are actually entered in.
        //
        // The factor block below is reserved first and the writing lines take
        // what is left. A suite name or a storage path that runs to an extra
        // line then shortens the lines instead of pushing the factor across the
        // QR codes — and the factor is the one thing on this sheet that must
        // never be the part that gets squeezed.
        const double factorBlockHeight = 22 + (4 * 20) + 20;
        double writingTop = y + 4;
        double writingBottom = qrHeadingBaseline - factorBlockHeight;
        const int writingLines = 3;
        double writingSpacing = Math.Min(22, (writingBottom - writingTop) / (writingLines + 1));
        for (int index = 0; index < writingLines && writingSpacing >= 12; index++)
        {
            double lineY = writingTop + (writingSpacing * (index + 1));
            graphics.DrawLine(XPens.Black, margin, lineY, page.Width.Point - margin, lineY);
        }

        y = writingBottom;

        graphics.DrawString(
            en
                ? $"Generated hexadecimal 512-bit factor {factorName}"
                : $"Generierter hexadezimaler 512-Bit-Faktor {factorName}",
            headingFont,
            XBrushes.Black,
            new XPoint(margin, y));
        y += 22;
        formatter.DrawString(
            GroupGeneratedPassword(generatedPassword),
            monoFont,
            XBrushes.Black,
            new XRect(margin, y, bodyWidth, 92));
        y += 80;

        graphics.DrawString(
            en
                ? $"Both QR codes contain factor {factorName} only (error correction Q)"
                : $"Beide QR-Codes enthalten ausschließlich Faktor {factorName} (Fehlerkorrektur Q)",
            headingFont,
            XBrushes.Black,
            new XPoint(margin, qrHeadingBaseline));

        // Printed twice side by side: a single smudged, creased or faded code
        // would otherwise force the whole factor to be typed by hand.
        string qrPayload = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        DrawQrCode(graphics, qrPayload, margin, qrTop, qrSize);
        DrawQrCode(graphics, qrPayload, margin + qrSize + qrGap, qrTop, qrSize);

        graphics.DrawString(
            en ? "Download and verify the app at:" : "App herunterladen und prüfen unter:",
            normalFont,
            XBrushes.Black,
            new XPoint(margin, urlLabelBaseline));
        graphics.DrawString(ProjectUrl, normalFont, XBrushes.DarkBlue, new XPoint(margin, urlBaseline));

        string footer = en
            ? $"Created: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Keep offline and physically protected."
            : $"Erstellt: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Offline und physisch geschützt aufbewahren.";
        graphics.DrawString(footer, normalFont, XBrushes.DarkSlateGray, new XPoint(margin, footerBaseline));
    }

    /// <summary>
    /// Draws the page that separates factor A from factor B.
    /// </summary>
    /// <remarks>
    /// Nothing here depends on the archive or on either factor: this method
    /// deliberately takes no key-sheet data at all, so the separating page
    /// cannot leak anything even if it is later edited carelessly.
    /// </remarks>
    private static void DrawInstallationPage(PdfPage page, bool en)
    {
        SetA4(page);
        using XGraphics graphics = XGraphics.FromPdfPage(page);
        var titleFont = new XFont("Arial", 24, XFontStyleEx.Bold);
        var headingFont = new XFont("Arial", MinimumFontSize, XFontStyleEx.Bold);
        var normalFont = new XFont("Arial", MinimumFontSize);

        const double margin = 42;
        const double bodyWidth = 500;
        double y = margin;

        graphics.DrawString(
            en ? "Installing Keep Vault" : "Keep Vault installieren",
            titleFont,
            XBrushes.Black,
            new XPoint(margin, y));
        y += 34;

        DrawWrappedValue(
            graphics,
            normalFont,
            en
                ? "This page separates factor A from factor B and contains no key material."
                : "Diese Seite trennt Faktor A von Faktor B und enthält kein Schlüsselmaterial.",
            margin,
            bodyWidth,
            ref y);
        y += 14;

        graphics.DrawString(
            en ? "Download" : "Bezugsquelle",
            headingFont,
            XBrushes.Black,
            new XPoint(margin, y));
        y += 22;
        graphics.DrawString(ProjectUrl, normalFont, XBrushes.DarkBlue, new XPoint(margin, y));
        y += 14;

        DrawQrCode(graphics, ProjectUrl, margin, y, 126);
        y += 126 + 30;

        graphics.DrawString("Windows", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 24;
        DrawSteps(graphics, normalFont, margin, bodyWidth, ref y, en
            ? [
                "1. Download the Windows release from the page above.",
                "2. Unblock the ZIP file in its properties, then extract it.",
                "3. Run Install-KeepVaultShortcuts.ps1 in PowerShell, or start KalynaArchiver.exe directly.",
                "4. The installer verifies the dual signature before it creates any shortcut.",
            ]
            : [
                "1. Windows-Release von der oben genannten Seite herunterladen.",
                "2. Die ZIP-Datei in den Eigenschaften zulassen, danach entpacken.",
                "3. Install-KeepVaultShortcuts.ps1 in PowerShell ausführen oder KalynaArchiver.exe direkt starten.",
                "4. Der Installer prüft die duale Signatur, bevor er eine Verknüpfung anlegt.",
            ]);
        y += 16;

        graphics.DrawString("macOS", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 24;
        DrawSteps(graphics, normalFont, margin, bodyWidth, ref y, en
            ? [
                "1. Download the macOS release from the page above.",
                "2. Extract the ZIP file. The .khsig files belong next to Keep Vault.app and must stay there.",
                "3. Run tools/Install-KeepVault-macOS.sh; it installs the app and creates a Desktop alias.",
                "4. QR-Scanner.app in the same package reads the codes above. Keep Vault never uses the camera.",
                "5. The app checks Apple's signature and its own dual signature at every start.",
            ]
            : [
                "1. macOS-Release von der oben genannten Seite herunterladen.",
                "2. Die ZIP-Datei entpacken. Die .khsig-Dateien gehören neben Keep Vault.app und müssen dort bleiben.",
                "3. tools/Install-KeepVault-macOS.sh ausführen; es installiert die App und legt ein Alias an.",
                "4. QR-Scanner.app aus demselben Paket liest die Codes oben. Keep Vault nutzt die Kamera nie.",
                "5. Die App prüft bei jedem Start Apples Signatur und ihre eigene duale Signatur.",
            ]);

        string footer = en
            ? "Keep this page with the key sheets."
            : "Diese Seite bei den Schlüsselzetteln aufbewahren.";
        graphics.DrawString(footer, normalFont, XBrushes.DarkSlateGray, new XPoint(margin, page.Height.Point - 24));
    }

    /// <summary>
    /// Draws numbered steps, wrapping each one to the page width.
    /// </summary>
    /// <remarks>
    /// Drawn line by line rather than into a fixed rectangle: a clipped
    /// rectangle silently drops the end of the last instruction, which on a
    /// sheet nobody re-reads before filing is a mistake that only surfaces when
    /// the instructions are actually needed.
    /// </remarks>
    private static void DrawSteps(
        XGraphics graphics,
        XFont font,
        double x,
        double width,
        ref double y,
        string[] steps)
    {
        foreach (string step in steps)
        {
            DrawWrappedValue(graphics, font, step, x, width, ref y);
            y += 4;
        }
    }

    private static void DrawLabelAndValue(
        XGraphics graphics,
        XFont headingFont,
        XFont normalFont,
        string label,
        string value,
        double x,
        double width,
        ref double y)
    {
        graphics.DrawString(label, headingFont, XBrushes.Black, new XPoint(x, y));
        y += 22;
        DrawWrappedValue(graphics, normalFont, value, x, width, ref y);
        y += 12;
    }

    /// <summary>
    /// Draws a value across as many lines as it needs, breaking inside long
    /// unbroken strings.
    /// </summary>
    /// <remarks>
    /// A storage location is a single token with no spaces, and at this font
    /// size it is easily wider than the page. Word wrapping alone would run it
    /// off the right edge, which is how a sheet ends up telling its owner only
    /// half of where the archive is, so the break falls after a path separator
    /// where possible and mid-token where not.
    /// </remarks>
    private static void DrawWrappedValue(
        XGraphics graphics,
        XFont font,
        string value,
        double x,
        double width,
        ref double y,
        XBrush? brush = null)
    {
        const double lineHeight = 20;
        XBrush ink = brush ?? XBrushes.Black;
        foreach (string line in WrapToWidth(graphics, font, value, width))
        {
            graphics.DrawString(line, font, ink, new XPoint(x, y));
            y += lineHeight;
        }
    }

    private static List<string> WrapToWidth(XGraphics graphics, XFont font, string value, double width)
    {
        var lines = new List<string>();
        if (string.IsNullOrEmpty(value))
        {
            lines.Add(string.Empty);
            return lines;
        }

        var current = new StringBuilder();
        int lastBreak = -1;
        foreach (char character in value)
        {
            current.Append(character);
            if (character is '/' or ' ' or '\\' or '-' or '_')
            {
                lastBreak = current.Length;
            }

            if (graphics.MeasureString(current.ToString(), font).Width <= width)
            {
                continue;
            }

            // Prefer the last separator, but never emit an empty line: if the
            // overflow happens before any separator, break mid-token instead.
            int cut = lastBreak > 0 && lastBreak < current.Length ? lastBreak : current.Length - 1;
            if (cut <= 0)
            {
                cut = 1;
            }

            lines.Add(current.ToString(0, cut).TrimEnd());
            string remainder = current.ToString(cut, current.Length - cut).TrimStart();
            current.Clear();
            current.Append(remainder);
            lastBreak = -1;
        }

        if (current.Length > 0)
        {
            lines.Add(current.ToString());
        }

        return lines;
    }

    /// <summary>
    /// Draws one QR code for an arbitrary payload.
    /// </summary>
    /// <remarks>
    /// Factor payloads are normalised by their caller, so what is encoded here
    /// is exactly what the scanner will be checked against. The matrix is
    /// cleared afterwards because for a factor it is key material.
    /// </remarks>
    private static void DrawQrCode(XGraphics graphics, string payload, double x, double y, double size)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData qrData = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        try
        {
            int moduleCount = qrData.ModuleMatrix.Count;
            double moduleSize = size / moduleCount;
            graphics.DrawRectangle(XBrushes.White, x, y, size, size);

            for (int row = 0; row < moduleCount; row++)
            {
                BitArray rowData = qrData.ModuleMatrix[row];
                for (int column = 0; column < moduleCount; column++)
                {
                    if (rowData[column])
                    {
                        graphics.DrawRectangle(
                            XBrushes.Black,
                            x + (column * moduleSize),
                            y + (row * moduleSize),
                            moduleSize + 0.05,
                            moduleSize + 0.05);
                    }
                }
            }
        }
        finally
        {
            ClearQrMatrix(qrData);
        }
    }

    private static void ClearQrMatrix(QRCodeData qrData)
    {
        foreach (BitArray row in qrData.ModuleMatrix)
        {
            row.SetAll(false);
        }
    }

    private static void SetA4(PdfPage page)
    {
        page.Width = XUnit.FromMillimeter(210);
        page.Height = XUnit.FromMillimeter(297);
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
            if (GlobalFontSettings.FontResolver is null)
            {
                GlobalFontSettings.FontResolver = MacSystemFontResolver.Instance;
            }
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
            MacSafeFileSystem.FullSync(output.SafeFileHandle);
            MacSecretFile.UnlinkVerified(output.SafeFileHandle, expectedPath);
        }
        catch
        {
            // Preserve the exception that interrupted the explicit export.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            memoryLock?.Dispose();
            output.Dispose();
        }
    }

    private sealed record ValidatedKeySheetData(
        string CanonicalArchivePath,
        EncryptionSuite Suite,
        string SuiteDisplayName,
        string FirstGeneratedPassword,
        string SecondGeneratedPassword,
        DateTime CreatedAt,
        bool English,
        string DeviceName);
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

public enum PhysicalPrinterEvidence
{
    None = 0,
    UsbDeviceWithSerial = 1,
    LocalDnssdIppDeviceWithUuid = 2,
}

public sealed record PhysicalPrinterDescriptor(
    string Name,
    string DisplayName,
    string MakeAndModel,
    string DeviceUri,
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

internal static class MacCupsPrinter
{
    private const int MaximumPrinterOutputCharacters = 64 * 1024;
    private const string LpPath = "/usr/bin/lp";
    private const string LpStatPath = "/usr/bin/lpstat";
    private const string LpOptionsPath = "/usr/bin/lpoptions";
    private static readonly string[] VirtualMarkers =
    [
        "pdf", "xps", "onenote", "fax", "file", "virtual", "preview", "acrobat",
        "adobe", "ghostscript", "ps2pdf", "cups-pdf", "print to", "save as",
    ];

    internal static async Task<IReadOnlyList<string>> EnumerateDestinationNamesAsync(CancellationToken cancellationToken)
    {
        MacPrintToolResult result = await RunToolAsync(
            LpStatPath,
            "com.apple.lpstat",
            new[] { "-e" },
            standardInput: default,
            TimeSpan.FromSeconds(10),
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(result, "Die installierten CUPS-Druckziele konnten nicht abgefragt werden.");
        return result.StandardOutput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(IsValidDestinationName)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    internal static async Task<PhysicalPrinterDescriptor> InspectInstalledAsync(
        string printerName,
        CancellationToken cancellationToken)
    {
        RequireValidDestinationName(printerName);
        IReadOnlyList<string> installed = await EnumerateDestinationNamesAsync(cancellationToken).ConfigureAwait(false);
        if (!installed.Contains(printerName, StringComparer.Ordinal))
        {
            throw new InvalidOperationException($"Das CUPS-Druckziel '{printerName}' ist nicht installiert.");
        }

        return await InspectAsync(printerName, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<PhysicalPrinterDescriptor> InspectAsync(
        string printerName,
        CancellationToken cancellationToken)
    {
        RequireValidDestinationName(printerName);
        MacPrintToolResult uriResult = await RunToolAsync(
            LpStatPath,
            "com.apple.lpstat",
            new[] { "-v", printerName },
            standardInput: default,
            TimeSpan.FromSeconds(10),
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(uriResult, $"Das Druckziel '{printerName}' konnte nicht geprüft werden.");

        MacPrintToolResult optionsResult = await RunToolAsync(
            LpOptionsPath,
            "com.apple.lpoptions",
            new[] { "-p", printerName },
            standardInput: default,
            TimeSpan.FromSeconds(10),
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(optionsResult, $"Die Eigenschaften des Druckziels '{printerName}' konnten nicht geprüft werden.");

        string deviceUri = ParseDeviceUri(uriResult.StandardOutput, printerName);
        IReadOnlyDictionary<string, string> options = ParseCupsOptions(optionsResult.StandardOutput);
        string displayName = GetOption(options, "printer-info", printerName);
        string makeAndModel = GetOption(options, "printer-make-and-model", string.Empty);
        bool accepting = string.Equals(GetOption(options, "printer-is-accepting-jobs", "false"), "true", StringComparison.OrdinalIgnoreCase);
        (PhysicalPrinterEvidence evidence, string message) = ClassifyPhysicalDevice(
            printerName,
            displayName,
            makeAndModel,
            deviceUri,
            accepting);
        return new PhysicalPrinterDescriptor(
            printerName,
            displayName,
            makeAndModel,
            deviceUri,
            accepting,
            evidence,
            message);
    }

    internal static async Task<string> SubmitPdfAsync(
        string printerName,
        ReadOnlyMemory<byte> pdf,
        CancellationToken cancellationToken)
    {
        RequireValidDestinationName(printerName);
        if (pdf.Length < 8 || !pdf.Span.StartsWith("%PDF-"u8))
        {
            throw new InvalidDataException("Der Schlüsselzettel-Druckdatenstrom ist keine gültige PDF-Einleitung.");
        }

        MacPrintToolResult result = await RunToolAsync(
            LpPath,
            "com.apple.lp",
            new[]
            {
                "-d", printerName,
                "-t", "Keep Vault getrennte Schluesselzettel",
                "-n", "1",
                "-o", "media=A4",
                "-o", "sides=one-sided",
                "-o", "job-sheets=none,none",
                "-o", "document-format=application/pdf",
                "-",
            },
            pdf,
            TimeSpan.FromMinutes(2),
            cancellationToken).ConfigureAwait(false);
        EnsureSuccess(result, $"Der Druckauftrag für '{printerName}' wurde von CUPS abgelehnt.");
        string receipt = result.StandardOutput.Trim();
        return string.IsNullOrWhiteSpace(receipt) ? "CUPS hat den Druckauftrag angenommen." : receipt;
    }

    private static (PhysicalPrinterEvidence Evidence, string Message) ClassifyPhysicalDevice(
        string name,
        string displayName,
        string makeAndModel,
        string deviceUri,
        bool accepting)
    {
        string combined = $"{name} {displayName} {makeAndModel} {deviceUri}";
        if (VirtualMarkers.Any(marker => combined.Contains(marker, StringComparison.OrdinalIgnoreCase)))
        {
            return (PhysicalPrinterEvidence.None, "Name, Modell oder Geräteadresse kennzeichnet ein virtuelles Datei-, PDF- oder Faxziel.");
        }

        if (!accepting)
        {
            return (PhysicalPrinterEvidence.None, "CUPS meldet, dass das Druckziel keine Aufträge annimmt.");
        }

        if (string.IsNullOrWhiteSpace(makeAndModel)
            || makeAndModel.Contains("generic", StringComparison.OrdinalIgnoreCase)
            || makeAndModel.Contains("raw", StringComparison.OrdinalIgnoreCase))
        {
            return (PhysicalPrinterEvidence.None, "CUPS liefert kein konkretes physisches Hersteller- und Modellmerkmal.");
        }

        if (deviceUri.Length is <= 3 or > 4096
            || deviceUri.Any(char.IsControl)
            || deviceUri.Any(char.IsWhiteSpace))
        {
            return (PhysicalPrinterEvidence.None, "CUPS liefert keine gültige absolute Geräteadresse.");
        }

        int schemeSeparator = deviceUri.IndexOf(':');
        if (schemeSeparator <= 0
            || !deviceUri[..schemeSeparator].All(character => char.IsAsciiLetterOrDigit(character) || character is '+' or '-' or '.'))
        {
            return (PhysicalPrinterEvidence.None, "CUPS liefert keine gültige absolute Geräteadresse.");
        }

        string scheme = deviceUri[..schemeSeparator].ToLowerInvariant();
        string queryText = deviceUri[(deviceUri.IndexOf('?') is int queryIndex && queryIndex >= 0 ? queryIndex : deviceUri.Length)..];
        if (string.Equals(scheme, "usb", StringComparison.Ordinal))
        {
            if (!deviceUri.StartsWith("usb://", StringComparison.OrdinalIgnoreCase))
            {
                return (PhysicalPrinterEvidence.None, "Die USB-Geräteadresse besitzt keine hierarchische Gerätekennung.");
            }

            IReadOnlyDictionary<string, string> query = ParseQuery(queryText);
            if (query.TryGetValue("serial", out string? serial) && IsBoundedHardwareIdentifier(serial))
            {
                return (PhysicalPrinterEvidence.UsbDeviceWithSerial, "Direktes USB-Druckgerät mit konkretem Modell und Serienkennung verifiziert.");
            }

            return (PhysicalPrinterEvidence.None, "Das USB-Ziel besitzt keine belastbare Serienkennung.");
        }

        if (string.Equals(scheme, "dnssd", StringComparison.Ordinal))
        {
            if (!deviceUri.StartsWith("dnssd://", StringComparison.OrdinalIgnoreCase))
            {
                return (PhysicalPrinterEvidence.None, "Die DNS-SD-Geräteadresse besitzt keine lokale Dienstkennung.");
            }

            int authorityStart = "dnssd://".Length;
            int authorityEnd = deviceUri.IndexOf('/', authorityStart);
            if (authorityEnd < 0) authorityEnd = deviceUri.Length;
            string authority = Uri.UnescapeDataString(deviceUri[authorityStart..authorityEnd]).TrimEnd('.');
            bool localIppService = authority.EndsWith("._ipp._tcp.local", StringComparison.OrdinalIgnoreCase)
                || authority.EndsWith("._ipps._tcp.local", StringComparison.OrdinalIgnoreCase);
            IReadOnlyDictionary<string, string> query = ParseQuery(queryText);
            bool hasUuid = query.TryGetValue("uuid", out string? uuid)
                && Guid.TryParse(uuid, out _);
            if (localIppService && hasUuid)
            {
                return (PhysicalPrinterEvidence.LocalDnssdIppDeviceWithUuid, "Lokal entdecktes IPP-Druckgerät mit konkretem Modell und Geräte-UUID verifiziert.");
            }

            return (PhysicalPrinterEvidence.None, "Das DNS-SD-Ziel ist kein lokal entdecktes IPP-Gerät mit Geräte-UUID.");
        }

        return (PhysicalPrinterEvidence.None,
            $"Der Transport '{scheme}' lässt sich nicht hinreichend von einer virtuellen oder weitergeleiteten Warteschlange unterscheiden.");
    }

    private static IReadOnlyDictionary<string, string> ParseQuery(string query)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = part.IndexOf('=');
            string key = Uri.UnescapeDataString(separator < 0 ? part : part[..separator]);
            string value = Uri.UnescapeDataString(separator < 0 ? string.Empty : part[(separator + 1)..]);
            if (!string.IsNullOrWhiteSpace(key))
            {
                values[key] = value;
            }
        }

        return values;
    }

    private static bool IsBoundedHardwareIdentifier(string value)
    {
        return value.Length is >= 4 and <= 128
            && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    private static string ParseDeviceUri(string output, string printerName)
    {
        foreach (string line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int nameIndex = line.IndexOf(printerName, StringComparison.Ordinal);
            if (nameIndex < 0)
            {
                continue;
            }

            int separator = line.IndexOf(':', nameIndex + printerName.Length);
            if (separator >= 0)
            {
                string value = line[(separator + 1)..].Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        throw new InvalidDataException($"CUPS lieferte keine Geräteadresse für '{printerName}'.");
    }

    private static IReadOnlyDictionary<string, string> ParseCupsOptions(string input)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int index = 0;
        while (index < input.Length)
        {
            while (index < input.Length && char.IsWhiteSpace(input[index])) index++;
            int keyStart = index;
            while (index < input.Length && !char.IsWhiteSpace(input[index]) && input[index] != '=') index++;
            if (index == keyStart || index >= input.Length || input[index] != '=')
            {
                while (index < input.Length && !char.IsWhiteSpace(input[index])) index++;
                continue;
            }

            string key = input[keyStart..index++];
            var value = new StringBuilder();
            char quote = '\0';
            if (index < input.Length && input[index] is '\'' or '"')
            {
                quote = input[index++];
            }

            while (index < input.Length)
            {
                char character = input[index++];
                if (character == '\\' && index < input.Length)
                {
                    value.Append(input[index++]);
                    continue;
                }

                if (quote != '\0')
                {
                    if (character == quote) break;
                    value.Append(character);
                    continue;
                }

                if (char.IsWhiteSpace(character)) break;
                value.Append(character);
            }

            if (!string.IsNullOrWhiteSpace(key))
            {
                values[key] = value.ToString();
            }
        }

        return values;
    }

    private static string GetOption(IReadOnlyDictionary<string, string> options, string key, string fallback)
    {
        return options.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : fallback;
    }

    private static bool IsValidDestinationName(string name)
    {
        return name.Length is >= 1 and <= 127
            && name[0] != '-'
            && name.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.');
    }

    private static void RequireValidDestinationName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!IsValidDestinationName(name))
        {
            throw new ArgumentException("Der CUPS-Druckername enthält unzulässige Zeichen.", nameof(name));
        }
    }

    private static async Task<MacPrintToolResult> RunToolAsync(
        string toolPath,
        string expectedIdentifier,
        IReadOnlyList<string> arguments,
        ReadOnlyMemory<byte> standardInput,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using FileStream toolLease = AppleSystemToolSignature.AcquireValidLease(toolPath, expectedIdentifier);
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        CancellationToken effectiveCancellation = timeoutSource.Token;
        var startInfo = new ProcessStartInfo
        {
            FileName = toolPath,
            UseShellExecute = false,
            RedirectStandardInput = !standardInput.IsEmpty,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.Environment.Clear();
        startInfo.Environment["PATH"] = "/usr/bin:/bin";
        startInfo.Environment["LANG"] = "C";
        startInfo.Environment["LC_ALL"] = "C";
        startInfo.Environment["HOME"] = "/var/empty";
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException($"Das verifizierte Systemprogramm '{toolPath}' konnte nicht gestartet werden.");
        }

        try
        {
            MacSafeFileSystem.RequirePathStillNamesHandle(toolLease.SafeFileHandle, toolPath);
            Task<string> stdoutTask = ReadBoundedAsync(process.StandardOutput, MaximumPrinterOutputCharacters, effectiveCancellation);
            Task<string> stderrTask = ReadBoundedAsync(process.StandardError, MaximumPrinterOutputCharacters, effectiveCancellation);
            if (!standardInput.IsEmpty)
            {
                await process.StandardInput.BaseStream.WriteAsync(standardInput, effectiveCancellation).ConfigureAwait(false);
                await process.StandardInput.BaseStream.FlushAsync(effectiveCancellation).ConfigureAwait(false);
                process.StandardInput.Close();
            }

            await process.WaitForExitAsync(effectiveCancellation).ConfigureAwait(false);
            string stdout = await stdoutTask.ConfigureAwait(false);
            string stderr = await stderrTask.ConfigureAwait(false);
            return new MacPrintToolResult(process.ExitCode, stdout, stderr);
        }
        catch
        {
            TryTerminate(process);
            throw;
        }
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        char[] buffer = new char[4096];
        var output = new StringBuilder();
        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > maximumCharacters)
            {
                throw new InvalidDataException("Ein CUPS-Systemprogramm lieferte eine unerwartet große Ausgabe.");
            }

            output.Append(buffer, 0, read);
        }

        return output.ToString();
    }

    private static void TryTerminate(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch
        {
            // Preserve the original process or cancellation exception.
        }
    }

    private static void EnsureSuccess(MacPrintToolResult result, string context)
    {
        if (result.ExitCode != 0)
        {
            string detail = string.IsNullOrWhiteSpace(result.StandardError)
                ? result.StandardOutput.Trim()
                : result.StandardError.Trim();
            throw new InvalidOperationException($"{context} Exit-Code {result.ExitCode}: {detail}");
        }
    }

    private sealed record MacPrintToolResult(int ExitCode, string StandardOutput, string StandardError);
}

internal static partial class AppleSystemToolSignature
{
    private const uint CheckAllArchitectures = 1U << 0;
    private const uint StrictValidate = 1U << 4;
    private const uint Utf8Encoding = 0x08000100;

    internal static FileStream AcquireValidLease(string path, string expectedIdentifier)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("Der Schlüsselzetteldruck ist ausschließlich für macOS implementiert.");
        }

        string canonical = Path.GetFullPath(path);
        FileStream? lease = MacSafeFileSystem.OpenReadNoSymlinks(canonical);

        nint url = 0;
        nint code = 0;
        nint requirementText = 0;
        nint requirement = 0;
        byte[] pathBytes = Encoding.UTF8.GetBytes(canonical);
        byte[] requirementBytes = Encoding.UTF8.GetBytes($"anchor apple and identifier \"{expectedIdentifier}\"");
        try
        {
            url = CFURLCreateFromFileSystemRepresentation(0, pathBytes, checked((nint)pathBytes.Length), false);
            if (url == 0)
            {
                throw new CryptographicException("CoreFoundation konnte die URL des Systemdruckprogramms nicht erzeugen.");
            }

            int status = SecStaticCodeCreateWithPath(url, 0, out code);
            if (status != 0 || code == 0)
            {
                throw new CryptographicException($"SecStaticCodeCreateWithPath schlug mit OSStatus {status} fehl.");
            }

            requirementText = CFStringCreateWithBytes(0, requirementBytes, checked((nint)requirementBytes.Length), Utf8Encoding, false);
            if (requirementText == 0)
            {
                throw new CryptographicException("CoreFoundation konnte die Apple-Signaturanforderung nicht erzeugen.");
            }

            status = SecRequirementCreateWithString(requirementText, 0, out requirement);
            if (status != 0 || requirement == 0)
            {
                throw new CryptographicException($"SecRequirementCreateWithString schlug mit OSStatus {status} fehl.");
            }

            status = SecStaticCodeCheckValidity(code, CheckAllArchitectures | StrictValidate, requirement);
            if (status != 0)
            {
                throw new CryptographicException(
                    $"Die Apple-Signatur oder die feste Kennung '{expectedIdentifier}' von '{canonical}' ist ungültig (OSStatus {status}).");
            }

            MacSafeFileSystem.RequirePathStillNamesHandle(lease.SafeFileHandle, canonical);
            FileStream result = lease;
            lease = null;
            return result;
        }
        finally
        {
            lease?.Dispose();
            CryptographicOperations.ZeroMemory(pathBytes);
            CryptographicOperations.ZeroMemory(requirementBytes);
            if (requirement != 0) CFRelease(requirement);
            if (requirementText != 0) CFRelease(requirementText);
            if (code != 0) CFRelease(code);
            if (url != 0) CFRelease(url);
        }
    }

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFURLCreateFromFileSystemRepresentation")]
    private static partial nint CFURLCreateFromFileSystemRepresentation(
        nint allocator,
        byte[] bytes,
        nint length,
        [MarshalAs(UnmanagedType.I1)] bool isDirectory);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFStringCreateWithBytes")]
    private static partial nint CFStringCreateWithBytes(
        nint allocator,
        byte[] bytes,
        nint length,
        uint encoding,
        [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease")]
    private static partial void CFRelease(nint value);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecStaticCodeCreateWithPath")]
    private static partial int SecStaticCodeCreateWithPath(nint path, uint flags, out nint staticCode);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecRequirementCreateWithString")]
    private static partial int SecRequirementCreateWithString(nint text, uint flags, out nint requirement);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecStaticCodeCheckValidity")]
    private static partial int SecStaticCodeCheckValidity(nint staticCode, uint flags, nint requirement);
}

internal static partial class MacCanonicalPath
{
    internal static string CanonicalizeCreatableFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("Die kanonische Schlüsselzettelbindung ist ausschließlich für macOS implementiert.");
        }

        string fullPath = Path.GetFullPath(path).Normalize(NormalizationForm.FormC);
        string? fileName = Path.GetFileName(fullPath);
        string? parent = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(fileName) || string.IsNullOrWhiteSpace(parent))
        {
            throw new ArgumentException("Der Zielpfad muss eine Datei in einem vorhandenen Ordner bezeichnen.", nameof(path));
        }

        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException($"Der Zielordner existiert nicht: {parent}");
        }

        nint resolvedPointer = RealPath(parent, 0);
        if (resolvedPointer == 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS konnte den Zielordner nicht kanonisch auflösen: {parent}");
        }

        try
        {
            string resolvedParent = Marshal.PtrToStringUTF8(resolvedPointer)
                ?? throw new IOException("realpath lieferte einen ungültigen UTF-8-Pfad.");
            string canonicalPath = Path.Combine(
                resolvedParent.Normalize(NormalizationForm.FormC),
                fileName.Normalize(NormalizationForm.FormC));
            if (Directory.Exists(canonicalPath))
            {
                throw new IOException($"Der Zielpfad bezeichnet einen Ordner statt einer Archivdatei: {canonicalPath}");
            }

            if (File.Exists(canonicalPath))
            {
                using FileStream existing = MacSafeFileSystem.OpenReadNoSymlinks(canonicalPath);
                MacSafeFileSystem.RequirePathStillNamesHandle(existing.SafeFileHandle, canonicalPath);
            }

            return canonicalPath;
        }
        finally
        {
            Free(resolvedPointer);
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "realpath", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint RealPath(string path, nint resolvedPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "free")]
    private static partial void Free(nint pointer);
}

internal static partial class MacSecretFile
{
    private const int OpenReadOnly = 0x0000;
    private const int OpenReadWrite = 0x0002;
    private const int OpenCreate = 0x0200;
    private const int OpenExclusive = 0x0800;
    private const int OpenNoFollow = 0x0100;
    private const int OpenDirectory = 0x00100000;
    private const int OpenCloseOnExec = 0x01000000;
    private const int OpenNoFollowAny = 0x20000000;
    private const ushort OwnerReadWrite = 0x0180; // 0600

    internal static FileStream CreateExclusive(string path)
    {
        string parentPath = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("Der Test-PDF-Pfad besitzt keinen Zielordner.", nameof(path));
        string fileName = Path.GetFileName(path);
        int parentDescriptor = OpenDirectoryHandle(
            parentPath,
            OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny);
        if (parentDescriptor < 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Der Test-PDF-Zielordner konnte nicht symlink-sicher geöffnet werden: {parentPath}");
        }

        using var parentHandle = new SafeFileHandle(parentDescriptor, ownsHandle: true);
        bool parentAdded = false;
        int descriptor = -1;
        try
        {
            parentHandle.DangerousAddRef(ref parentAdded);
            descriptor = OpenAt(
                checked((int)parentHandle.DangerousGetHandle()),
                fileName,
                OpenReadWrite | OpenCreate | OpenExclusive | OpenNoFollow | OpenCloseOnExec,
                OwnerReadWrite);
            if (descriptor < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Die Test-PDF konnte nicht exklusiv und symlink-sicher angelegt werden: {path}");
            }

            var handle = new SafeFileHandle(descriptor, ownsHandle: true);
            descriptor = -1;
            try
            {
                bool handleAdded = false;
                try
                {
                    handle.DangerousAddRef(ref handleAdded);
                    int fileDescriptor = checked((int)handle.DangerousGetHandle());
                    if (Fchmod(fileDescriptor, OwnerReadWrite) != 0)
                    {
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "Die Test-PDF konnte nicht auf exklusive 0600-Rechte gesetzt werden.");
                    }
                }
                finally
                {
                    if (handleAdded) handle.DangerousRelease();
                }

                MacSafeFileSystem.ValidateRegularFile(handle, requireSingleLink: true, path);
                MacFileIdentity identity = MacSafeFileSystem.GetIdentity(handle);
                if ((identity.Mode & 0x01FF) != OwnerReadWrite)
                {
                    throw new IOException("Die Test-PDF besitzt nach fchmod nicht ausschließlich 0600-Rechte.");
                }

                MacSafeFileSystem.RequirePathStillNamesHandle(handle, path);
                return new FileStream(handle, FileAccess.ReadWrite, 64 * 1024, isAsync: false);
            }
            catch
            {
                handle.Dispose();
                _ = UnlinkAt(checked((int)parentHandle.DangerousGetHandle()), fileName, 0);
                throw;
            }
        }
        finally
        {
            if (descriptor >= 0)
            {
                _ = Close(descriptor);
            }

            if (parentAdded)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static void UnlinkVerified(SafeFileHandle handle, string expectedPath)
    {
        MacSafeFileSystem.RequirePathStillNamesHandle(handle, expectedPath);
        if (Unlink(expectedPath) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Die beschädigte Test-PDF konnte nicht entfernt werden.");
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenDirectoryHandle(string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(int directoryDescriptor, string path, int flags, uint mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "unlinkat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int UnlinkAt(int directoryDescriptor, string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "unlink", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Unlink(string path);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fchmod", SetLastError = true)]
    private static partial int Fchmod(int descriptor, ushort mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int descriptor);
}

internal sealed class SensitiveBufferStream : Stream
{
    private byte[]? _buffer;
    private IDisposable? _memoryLock;
    private int _length;
    private int _position;

    internal SensitiveBufferStream(int initialCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialCapacity);
        _buffer = new byte[initialCapacity];
        try
        {
            _memoryLock = SecureMemory.TryLock(_buffer);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_buffer);
            _buffer = null;
            throw;
        }
    }

    public override bool CanRead => _buffer is not null;
    public override bool CanSeek => _buffer is not null;
    public override bool CanWrite => _buffer is not null;
    public override long Length => _buffer is not null ? _length : throw new ObjectDisposedException(nameof(SensitiveBufferStream));

    public override long Position
    {
        get => _buffer is not null ? _position : throw new ObjectDisposedException(nameof(SensitiveBufferStream));
        set
        {
            ObjectDisposedException.ThrowIf(_buffer is null, this);
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            if (value > int.MaxValue) throw new IOException("Der vertrauliche PDF-Datenstrom ist zu groß.");
            _position = checked((int)value);
        }
    }

    internal ReadOnlyMemory<byte> GetWrittenMemory()
    {
        byte[] buffer = _buffer ?? throw new ObjectDisposedException(nameof(SensitiveBufferStream));
        return buffer.AsMemory(0, _length);
    }

    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_buffer is null, this);
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_buffer is null, this);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> destination)
    {
        byte[] source = _buffer ?? throw new ObjectDisposedException(nameof(SensitiveBufferStream));
        int available = Math.Max(0, _length - _position);
        int count = Math.Min(destination.Length, available);
        source.AsSpan(_position, count).CopyTo(destination);
        _position += count;
        return count;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long next = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        Position = next;
        return next;
    }

    public override void SetLength(long value)
    {
        ObjectDisposedException.ThrowIf(_buffer is null, this);
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value > int.MaxValue) throw new IOException("Der vertrauliche PDF-Datenstrom ist zu groß.");
        int nextLength = checked((int)value);
        EnsureCapacity(nextLength);
        if (nextLength < _length)
        {
            _buffer.AsSpan(nextLength, _length - nextLength).Clear();
        }

        _length = nextLength;
        _position = Math.Min(_position, _length);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> source)
    {
        ObjectDisposedException.ThrowIf(_buffer is null, this);
        int end = checked(_position + source.Length);
        EnsureCapacity(end);
        source.CopyTo(_buffer.AsSpan(_position));
        _position = end;
        _length = Math.Max(_length, _position);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && _buffer is not null)
        {
            CryptographicOperations.ZeroMemory(_buffer);
            _memoryLock?.Dispose();
            _memoryLock = null;
            _buffer = null;
            _length = 0;
            _position = 0;
        }

        base.Dispose(disposing);
    }

    private void EnsureCapacity(int required)
    {
        byte[] current = _buffer ?? throw new ObjectDisposedException(nameof(SensitiveBufferStream));
        if (required <= current.Length) return;
        int capacity = current.Length;
        while (capacity < required)
        {
            capacity = checked(capacity <= int.MaxValue / 2 ? capacity * 2 : int.MaxValue);
            if (capacity == int.MaxValue && capacity < required)
            {
                throw new IOException("Der vertrauliche PDF-Datenstrom ist zu groß.");
            }
        }

        byte[] replacement = new byte[capacity];
        IDisposable? replacementLock = null;
        try
        {
            replacementLock = SecureMemory.TryLock(replacement);
            current.AsSpan(0, _length).CopyTo(replacement);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(replacement);
            replacementLock?.Dispose();
            throw;
        }

        CryptographicOperations.ZeroMemory(current);
        _memoryLock?.Dispose();
        _buffer = replacement;
        _memoryLock = replacementLock;
    }
}

internal sealed class MacSystemFontResolver : IFontResolver
{
    private const int MaximumFontBytes = 16 * 1024 * 1024;
    private const string FontRoot = "/System/Library/Fonts/Supplemental";
    internal static readonly MacSystemFontResolver Instance = new();
    private static readonly IReadOnlyDictionary<string, string> FontFiles = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["arial"] = "Arial.ttf",
        ["arial-bold"] = "Arial Bold.ttf",
        ["courier-new"] = "Courier New.ttf",
        ["courier-new-bold"] = "Courier New Bold.ttf",
    };

    private MacSystemFontResolver()
    {
    }

    public FontResolverInfo ResolveTypeface(string familyName, bool bold, bool italic)
    {
        bool courier = familyName.Contains("courier", StringComparison.OrdinalIgnoreCase)
            || familyName.Contains("mono", StringComparison.OrdinalIgnoreCase);
        string face = courier
            ? bold ? "courier-new-bold" : "courier-new"
            : bold ? "arial-bold" : "arial";
        return new FontResolverInfo(face, mustSimulateBold: false, mustSimulateItalic: italic);
    }

    public byte[] GetFont(string faceName)
    {
        if (!FontFiles.TryGetValue(faceName, out string? fileName))
        {
            throw new InvalidOperationException($"Die PDF-Schriftart '{faceName}' ist nicht freigegeben.");
        }

        string path = Path.Combine(FontRoot, fileName);
        using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
        if (stream.Length is <= 0 or > MaximumFontBytes)
        {
            throw new InvalidDataException($"Die PDF-Schriftart besitzt eine ungültige Größe: {path}");
        }

        byte[] font = new byte[checked((int)stream.Length)];
        stream.ReadExactly(font);
        return font;
    }
}
