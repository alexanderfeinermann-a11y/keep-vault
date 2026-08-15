using System.Collections;
using System.Drawing.Printing;
using System.IO;
using System.Printing;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using PdfSharp.Drawing;
using PdfSharp.Drawing.Layout;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using QRCoder;
using WpfBrushes = System.Windows.Media.Brushes;
using WpfFontFamily = System.Windows.Media.FontFamily;
using WpfHorizontalAlignment = System.Windows.HorizontalAlignment;
using WpfImage = System.Windows.Controls.Image;
using WpfOrientation = System.Windows.Controls.Orientation;
using WpfPoint = System.Windows.Point;
using WpfSize = System.Windows.Size;

namespace KalynaArchiver.Services;

public sealed class KeySheetService
{
    private static readonly object FontResolverGate = new();
    private static readonly string[] VirtualPrinterMarkers = ["pdf", "xps", "onenote", "fax", "send to"];

    // This method exists solely for explicit test/export use. It intentionally writes both
    // generated factors to a persistent file and is never used by the normal print flow.
    public void SaveTestPdf(KeySheetData data, string pdfPath)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentException.ThrowIfNullOrWhiteSpace(pdfPath);
        EnsurePdfFontResolver();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(pdfPath)) ?? Environment.CurrentDirectory);

        using var document = new PdfDocument();
        document.Info.Title = "Kalyna and Threefish ZPAQ Vault two-factor key sheets";
        document.Info.Author = "Kalyna and Threefish ZPAQ Vault";
        DrawPdfSheet(document.AddPage(), data, KeySheetFactor.First);

        // A truly blank page prevents the two secret sheets from ending up front/back on a
        // duplex printer. It contains no text, metadata, QR code, or key material.
        PdfPage blank = document.AddPage();
        blank.Width = XUnit.FromMillimeter(210);
        blank.Height = XUnit.FromMillimeter(297);

        DrawPdfSheet(document.AddPage(), data, KeySheetFactor.Second);
        document.Save(pdfPath);
    }

    public FixedDocument CreatePrintDocument(KeySheetData data, WpfSize printableArea)
    {
        ArgumentNullException.ThrowIfNull(data);
        WpfSize pageSize = NormalizePageSize(printableArea);
        var document = new FixedDocument();
        document.DocumentPaginator.PageSize = pageSize;
        document.Pages.Add(CreatePage(CreatePrintVisual(data, KeySheetFactor.First), pageSize));
        document.Pages.Add(CreateBlankPage(pageSize));
        document.Pages.Add(CreatePage(CreatePrintVisual(data, KeySheetFactor.Second), pageSize));
        return document;
    }

    public FrameworkElement CreatePrintVisual(KeySheetData data, KeySheetFactor factor = KeySheetFactor.First)
    {
        ArgumentNullException.ThrowIfNull(data);
        string generatedPassword = GetGeneratedPassword(data, factor);
        byte[] qrPng = CreateQrPng(generatedPassword);
        IDisposable? qrLock = null;
        try
        {
            qrLock = SecureMemory.TryLock(qrPng);
            string factorName = factor == KeySheetFactor.First ? "A" : "B";
            var root = new Border
            {
                Background = WpfBrushes.White,
                Padding = new Thickness(48),
                Child = new StackPanel
                {
                    Orientation = WpfOrientation.Vertical,
                    Children =
                    {
                        new TextBlock { Text = $"{ProductInfo.Name} key sheet {factorName}", FontSize = 24, FontWeight = FontWeights.Bold, Foreground = WpfBrushes.Black, Margin = new Thickness(0, 0, 0, 16) },
                        new TextBlock { Text = "Store this sheet separately from the other key sheet. A deliberately blank page is printed between A and B for duplex separation.", FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = WpfBrushes.DarkRed, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 20) },
                        Label("Cipher suite"),
                        Value(EncryptionSuiteCatalog.Get(data.Suite).DisplayName),
                        Label("Archive file"),
                        Value(Path.GetFileName(data.ArchivePath)),
                        Label("Storage location"),
                        Value(Path.GetDirectoryName(data.ArchivePath) ?? data.ArchivePath),
                        Label($"Generated 512-bit hexadecimal password {factorName}"),
                        new TextBlock { Text = GroupGeneratedPassword(generatedPassword), FontFamily = new WpfFontFamily("Consolas"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Foreground = WpfBrushes.Black, Margin = new Thickness(0, 4, 0, 18) },
                        Label("User password field (write by hand; do not store it digitally)"),
                        FieldLine(),
                        FieldLine(),
                        FieldLine(),
                        FieldLine(),
                        Label($"QR code contains only generated password {factorName}"),
                        new WpfImage { Source = CreateBitmap(qrPng), Width = 220, Height = 220, HorizontalAlignment = WpfHorizontalAlignment.Left, Margin = new Thickness(0, 8, 0, 16) },
                        new TextBlock { Text = $"Created: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Keep this sheet offline and physically protected.", FontSize = 11, Foreground = WpfBrushes.DimGray, TextWrapping = TextWrapping.Wrap },
                    },
                },
            };

            return root;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(qrPng);
            qrLock?.Dispose();
        }
    }

    public static void EnsurePhysicalPrinter(PrintQueue? printQueue)
    {
        if (printQueue is null)
        {
            throw new InvalidOperationException("No printer queue is selected.");
        }

        EnsureNotVirtualPrinter($"{printQueue.Name} {printQueue.FullName} {printQueue.QueueDriver?.Name}");
    }

    public static void EnsurePhysicalPrinter(string? printerName)
    {
        if (string.IsNullOrWhiteSpace(printerName))
        {
            throw new InvalidOperationException("No printer is selected.");
        }

        EnsureNotVirtualPrinter(printerName);
    }

    private static void EnsureNotVirtualPrinter(string identifier)
    {
        if (VirtualPrinterMarkers.Any(marker => identifier.Contains(marker, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Virtual PDF/XPS/OneNote/Fax printers are blocked for key sheets. Use a physical printer or the explicit test-PDF export.");
        }
    }

    // Returns the first installed, valid, non-virtual printer, or null if none qualifies.
    // Used to seed the print dialog with a working printer so a broken default printer
    // driver (whose DEVMODE cannot be converted to a PrintTicket) does not make the dialog
    // unusable.
    public static string? FirstValidPhysicalPrinter()
    {
        foreach (string? name in PrinterSettings.InstalledPrinters)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            if (VirtualPrinterMarkers.Any(marker => name.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            try
            {
                if (new PrinterSettings { PrinterName = name }.IsValid)
                {
                    return name;
                }
            }
            catch
            {
                // Ignore printers whose settings cannot be queried.
            }
        }

        return null;
    }

    // Prints the two key sheets (plus a blank separator page) through the classic GDI print
    // path (System.Drawing.Printing) instead of WPF's System.Printing pipeline. Some printer
    // drivers (e.g. the Microsoft IPP Class Driver) fail every PrintTicket<->DEVMODE
    // conversion with HRESULT 0x80004005, which breaks WPF's PrintDialog/PrintDocument even
    // for selecting a different, working printer. GDI printing does not use that provider.
    // No app-created PDF is written; secrets go only to the spooler, as with any print job.
    public void PrintKeySheets(PrinterSettings printerSettings, KeySheetData data)
    {
        ArgumentNullException.ThrowIfNull(printerSettings);
        if (!printerSettings.IsValid)
        {
            throw new InvalidOperationException(
                $"Der ausgewählte Drucker '{printerSettings.PrinterName}' meldet eine ungültige Konfiguration (Treiber-/DEVMODE-Problem). Bitte einen anderen Drucker wählen oder den Druckertreiber neu installieren.");
        }

        var pageSize = new WpfSize(793.7, 1122.5); // A4 at WPF's 96 DPI unit.
        const double renderDpi = 200.0;
        var pages = new List<System.Drawing.Bitmap?>();
        try
        {
            pages.Add(RenderVisualToGdiBitmap(CreatePrintVisual(data, KeySheetFactor.First), pageSize, renderDpi));
            pages.Add(null); // deliberately blank duplex-separation page
            pages.Add(RenderVisualToGdiBitmap(CreatePrintVisual(data, KeySheetFactor.Second), pageSize, renderDpi));

            using var printDocument = new PrintDocument
            {
                PrinterSettings = printerSettings,
                DocumentName = "Kalyna and Threefish ZPAQ separate key sheets",
            };
            printDocument.DefaultPageSettings.Margins = new Margins(0, 0, 0, 0);

            int pageIndex = 0;
            printDocument.PrintPage += (_, printPageEventArgs) =>
            {
                System.Drawing.Bitmap? bitmap = pages[pageIndex];
                if (bitmap is not null)
                {
                    System.Drawing.Rectangle destination = FitPreservingAspect(bitmap.Size, printPageEventArgs.PageBounds);
                    printPageEventArgs.Graphics!.DrawImage(bitmap, destination);
                }

                pageIndex++;
                printPageEventArgs.HasMorePages = pageIndex < pages.Count;
            };

            try
            {
                printDocument.Print();
            }
            catch (Exception ex) when (ex is System.Drawing.Printing.InvalidPrinterException
                or System.ComponentModel.Win32Exception
                or System.Runtime.InteropServices.ExternalException)
            {
                // Some printer drivers (notably the generic "Microsoft IPP Class Driver") cannot
                // produce a valid DEVMODE and reject every print job across all desktop print APIs.
                throw new InvalidOperationException(
                    $"Der Drucker '{printerSettings.PrinterName}' konnte den Druckauftrag nicht annehmen (Treiber-/DEVMODE-Problem). Bitte einen anderen physischen Drucker wählen oder für dieses Gerät den passenden Herstellertreiber statt des generischen \"Microsoft IPP Class Driver\" installieren.", ex);
            }
        }
        finally
        {
            foreach (System.Drawing.Bitmap? bitmap in pages)
            {
                bitmap?.Dispose();
            }
        }
    }

    private static System.Drawing.Bitmap RenderVisualToGdiBitmap(FrameworkElement visual, WpfSize pageSize, double dpi)
    {
        visual.Width = pageSize.Width;
        visual.Height = pageSize.Height;
        visual.Measure(pageSize);
        visual.Arrange(new Rect(new WpfPoint(0, 0), pageSize));
        visual.UpdateLayout();

        int pixelWidth = (int)Math.Ceiling(pageSize.Width * dpi / 96.0);
        int pixelHeight = (int)Math.Ceiling(pageSize.Height * dpi / 96.0);
        var renderTarget = new RenderTargetBitmap(pixelWidth, pixelHeight, dpi, dpi, PixelFormats.Pbgra32);
        renderTarget.Render(visual);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(renderTarget));
        using var stream = new MemoryStream();
        encoder.Save(stream);
        stream.Position = 0;

        try
        {
            // Clone into a stream-independent bitmap: GDI+ requires the source stream to
            // stay open for the lifetime of a Bitmap constructed directly from it.
            using var streamBitmap = new System.Drawing.Bitmap(stream);
            return new System.Drawing.Bitmap(streamBitmap);
        }
        finally
        {
            if (stream.TryGetBuffer(out ArraySegment<byte> encodedPage))
            {
                CryptographicOperations.ZeroMemory(encodedPage.AsSpan(0, checked((int)stream.Length)));
            }
        }
    }

    private static System.Drawing.Rectangle FitPreservingAspect(System.Drawing.Size image, System.Drawing.Rectangle bounds)
    {
        if (image.Width <= 0 || image.Height <= 0 || bounds.Width <= 0 || bounds.Height <= 0)
        {
            return bounds;
        }

        double scale = Math.Min((double)bounds.Width / image.Width, (double)bounds.Height / image.Height);
        int width = Math.Max(1, (int)(image.Width * scale));
        int height = Math.Max(1, (int)(image.Height * scale));
        int x = bounds.X + ((bounds.Width - width) / 2);
        int y = bounds.Y + ((bounds.Height - height) / 2);
        return new System.Drawing.Rectangle(x, y, width, height);
    }

    public static byte[] CreateQrPng(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(normalized, QRCodeGenerator.ECCLevel.Q);
        using var png = new PngByteQRCode(data);
        return png.GetGraphic(6);
    }

    public static string GroupGeneratedPassword(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        return string.Join(" ", Enumerable.Range(0, normalized.Length / 8).Select(i => normalized.Substring(i * 8, 8)));
    }

    private static void DrawPdfSheet(PdfPage page, KeySheetData data, KeySheetFactor factor)
    {
        page.Width = XUnit.FromMillimeter(210);
        page.Height = XUnit.FromMillimeter(297);
        string generatedPassword = GetGeneratedPassword(data, factor);
        string factorName = factor == KeySheetFactor.First ? "A" : "B";

        using XGraphics gfx = XGraphics.FromPdfPage(page);
        var titleFont = new XFont("Segoe UI", 20, XFontStyleEx.Bold);
        var headingFont = new XFont("Segoe UI", 11, XFontStyleEx.Bold);
        var normalFont = new XFont("Segoe UI", 10);
        var warningFont = new XFont("Segoe UI", 9, XFontStyleEx.Bold);
        var monoFont = new XFont("Consolas", 8.5);
        var formatter = new XTextFormatter(gfx);

        double margin = 42;
        double y = margin;
        gfx.DrawString($"{ProductInfo.Name} key sheet {factorName}", titleFont, XBrushes.Black, new XPoint(margin, y));
        y += 24;
        formatter.DrawString("Store this sheet separately from the other key sheet. A deliberately blank page is inserted between A and B for duplex separation.", warningFont, XBrushes.DarkRed, new XRect(margin, y, 500, 28));
        y += 42;
        gfx.DrawString("Cipher suite", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 15;
        gfx.DrawString(EncryptionSuiteCatalog.Get(data.Suite).DisplayName, normalFont, XBrushes.Black, new XPoint(margin, y));
        y += 30;
        gfx.DrawString("Archive file", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 15;
        formatter.DrawString(Path.GetFileName(data.ArchivePath), normalFont, XBrushes.Black, new XRect(margin, y, 500, 28));
        y += 36;
        gfx.DrawString("Storage location", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 15;
        formatter.DrawString(Path.GetDirectoryName(data.ArchivePath) ?? data.ArchivePath, normalFont, XBrushes.Black, new XRect(margin, y, 500, 38));
        y += 48;
        gfx.DrawString($"Generated 512-bit hexadecimal password {factorName}", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 15;
        formatter.DrawString(GroupGeneratedPassword(generatedPassword), monoFont, XBrushes.Black, new XRect(margin, y, 500, 54));
        y += 74;
        gfx.DrawString("User password field (write by hand; do not store it digitally)", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 24;
        for (int i = 0; i < 4; i++)
        {
            gfx.DrawLine(XPens.Black, margin, y, page.Width.Point - margin, y);
            y += 28;
        }

        y += 12;
        gfx.DrawString($"QR code contains only generated password {factorName}", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 12;
        DrawQrCode(gfx, generatedPassword, margin, y, 190);

        string footer = $"Created: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Keep this sheet offline and physically protected.";
        gfx.DrawString(footer, normalFont, XBrushes.DarkSlateGray, new XPoint(margin, page.Height.Point - 36));
    }

    private static string GetGeneratedPassword(KeySheetData data, KeySheetFactor factor)
    {
        return PasswordKeyService.NormalizeGeneratedPassword(
            factor == KeySheetFactor.First ? data.FirstGeneratedPassword : data.SecondGeneratedPassword);
    }

    private static WpfSize NormalizePageSize(WpfSize printableArea)
    {
        return printableArea.Width > 100 && printableArea.Height > 100
            ? printableArea
            : new WpfSize(793.7, 1122.5); // A4 at WPF's 96 DPI unit.
    }

    private static PageContent CreatePage(FrameworkElement visual, WpfSize pageSize)
    {
        visual.Width = pageSize.Width;
        visual.Height = pageSize.Height;
        visual.Measure(pageSize);
        visual.Arrange(new Rect(new WpfPoint(0, 0), pageSize));
        visual.UpdateLayout();

        var fixedPage = new FixedPage { Width = pageSize.Width, Height = pageSize.Height, Background = WpfBrushes.White };
        fixedPage.Children.Add(visual);
        return new PageContent { Child = fixedPage };
    }

    private static PageContent CreateBlankPage(WpfSize pageSize)
    {
        var fixedPage = new FixedPage { Width = pageSize.Width, Height = pageSize.Height, Background = WpfBrushes.White };
        return new PageContent { Child = fixedPage };
    }

    private static TextBlock Label(string text)
    {
        return new TextBlock
        {
            Text = text,
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            Foreground = WpfBrushes.Black,
            Margin = new Thickness(0, 0, 0, 4),
        };
    }

    private static TextBlock Value(string text)
    {
        return new TextBlock
        {
            Text = text,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = WpfBrushes.Black,
            Margin = new Thickness(0, 0, 0, 16),
        };
    }

    private static Border FieldLine()
    {
        return new Border
        {
            BorderBrush = WpfBrushes.Black,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Height = 28,
            Margin = new Thickness(0, 0, 0, 8),
        };
    }

    private static BitmapImage CreateBitmap(byte[] pngBytes)
    {
        using var stream = new MemoryStream(pngBytes);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    private static void DrawQrCode(XGraphics gfx, string generatedPassword, double x, double y, double size)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(normalized, QRCodeGenerator.ECCLevel.Q);
        int moduleCount = data.ModuleMatrix.Count;
        double moduleSize = size / moduleCount;
        gfx.DrawRectangle(XBrushes.White, x, y, size, size);

        for (int row = 0; row < moduleCount; row++)
        {
            BitArray rowData = data.ModuleMatrix[row];
            for (int column = 0; column < moduleCount; column++)
            {
                if (rowData[column])
                {
                    gfx.DrawRectangle(
                        XBrushes.Black,
                        x + (column * moduleSize),
                        y + (row * moduleSize),
                        moduleSize + 0.05,
                        moduleSize + 0.05);
                }
            }
        }
    }

    private static void EnsurePdfFontResolver()
    {
        lock (FontResolverGate)
        {
            if (GlobalFontSettings.FontResolver is null)
            {
                GlobalFontSettings.FontResolver = WindowsFontResolver.Instance;
            }
        }
    }
}

public enum KeySheetFactor
{
    First,
    Second,
}

public sealed record KeySheetData(
    string ArchivePath,
    EncryptionSuite Suite,
    string FirstGeneratedPassword,
    string SecondGeneratedPassword,
    DateTime CreatedAt);

internal sealed class WindowsFontResolver : IFontResolver
{
    private const int MaximumFontBytes = 64 * 1024 * 1024;
    public static readonly WindowsFontResolver Instance = new();
    private static readonly IReadOnlyDictionary<string, string> FontFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["segoeui"] = "segoeui.ttf",
        ["segoeuib"] = "segoeuib.ttf",
        ["segoeuii"] = "segoeuii.ttf",
        ["segoeuiz"] = "segoeuiz.ttf",
        ["consola"] = "consola.ttf",
        ["consolab"] = "consolab.ttf",
        ["arial"] = "arial.ttf",
        ["arialbd"] = "arialbd.ttf",
    };

    private WindowsFontResolver()
    {
    }

    public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic)
    {
        string family = familyName.Trim();
        if (family.Contains("consol", StringComparison.OrdinalIgnoreCase))
        {
            return new FontResolverInfo(bold ? "consolab" : "consola", false, italic);
        }

        if (family.Contains("segoe", StringComparison.OrdinalIgnoreCase))
        {
            string face = (bold, italic) switch
            {
                (true, true) => "segoeuiz",
                (true, false) => "segoeuib",
                (false, true) => "segoeuii",
                _ => "segoeui",
            };
            return new FontResolverInfo(face);
        }

        return new FontResolverInfo(bold ? "arialbd" : "arial", false, italic);
    }

    public byte[] GetFont(string faceName)
    {
        if (!FontFiles.TryGetValue(faceName, out string? fileName))
        {
            fileName = "arial.ttf";
        }

        string fontPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts", fileName);
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
