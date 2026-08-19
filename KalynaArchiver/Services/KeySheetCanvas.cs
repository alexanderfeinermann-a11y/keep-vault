using System.Collections;
using System.IO;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using QRCoder;
using GdiBrush = System.Drawing.Brush;
using GdiBrushes = System.Drawing.Brushes;
using GdiFont = System.Drawing.Font;
using GdiFontFamily = System.Drawing.FontFamily;
using GdiFontStyle = System.Drawing.FontStyle;
using GdiGraphics = System.Drawing.Graphics;
using GdiGraphicsUnit = System.Drawing.GraphicsUnit;
using GdiPen = System.Drawing.Pen;
using GdiPointF = System.Drawing.PointF;
using GdiSizeF = System.Drawing.SizeF;
using GdiStringFormat = System.Drawing.StringFormat;

namespace KalynaArchiver.Services;

/// <summary>
/// The ink colours a key sheet uses.
/// </summary>
/// <remarks>
/// Named rather than passed as platform brushes because the same sheet is
/// drawn twice on Windows: once into a PDF and once onto a printer device
/// context. Two brush types would mean two copies of the layout, and two copies
/// of a layout are how the printed sheet and the exported one stop agreeing.
/// </remarks>
internal enum SheetInk
{
    Black,
    DarkRed,
    Red,
    DarkBlue,
    DarkSlateGray,
    White,
}

/// <summary>
/// A font on a key sheet, in points.
/// </summary>
internal readonly record struct SheetFont(string Family, double Size, bool Bold)
{
    internal const string Sans = "Arial";
    internal const string Mono = "Courier New";
}

/// <summary>
/// The drawing surface a key sheet is rendered onto.
/// </summary>
/// <remarks>
/// Everything is in typographic points with the origin at the top-left of the
/// page, and <see cref="DrawText"/> places the text <em>baseline</em> at the
/// given y. That is PDFsharp's own convention for
/// <c>DrawString(text, font, brush, XPoint)</c>, verified against the emitted
/// content stream rather than assumed, and the GDI implementation converts to
/// it so both surfaces put a glyph in the same place.
/// </remarks>
internal interface ISheetCanvas
{
    double WidthPoints { get; }

    double HeightPoints { get; }

    void DrawText(string text, SheetFont font, SheetInk ink, double x, double baselineY);

    void DrawLine(SheetInk ink, double x1, double y1, double x2, double y2);

    void FillRectangle(SheetInk ink, double x, double y, double width, double height);

    double MeasureWidth(string text, SheetFont font);
}

internal sealed class PdfSheetCanvas : ISheetCanvas, IDisposable
{
    private readonly XGraphics _graphics;

    internal PdfSheetCanvas(PdfPage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        WidthPoints = page.Width.Point;
        HeightPoints = page.Height.Point;
        _graphics = XGraphics.FromPdfPage(page);
    }

    public double WidthPoints { get; }

    public double HeightPoints { get; }

    public void DrawText(string text, SheetFont font, SheetInk ink, double x, double baselineY)
    {
        _graphics.DrawString(text, Resolve(font), Brush(ink), new XPoint(x, baselineY));
    }

    public void DrawLine(SheetInk ink, double x1, double y1, double x2, double y2)
    {
        _graphics.DrawLine(new XPen(Color(ink), 1), x1, y1, x2, y2);
    }

    public void FillRectangle(SheetInk ink, double x, double y, double width, double height)
    {
        _graphics.DrawRectangle(Brush(ink), x, y, width, height);
    }

    public double MeasureWidth(string text, SheetFont font)
    {
        return _graphics.MeasureString(text, Resolve(font)).Width;
    }

    public void Dispose() => _graphics.Dispose();

    private static XFont Resolve(SheetFont font) =>
        new(font.Family, font.Size, font.Bold ? XFontStyleEx.Bold : XFontStyleEx.Regular);

    private static XBrush Brush(SheetInk ink) => ink switch
    {
        SheetInk.Black => XBrushes.Black,
        SheetInk.DarkRed => XBrushes.DarkRed,
        SheetInk.Red => XBrushes.Red,
        SheetInk.DarkBlue => XBrushes.DarkBlue,
        SheetInk.DarkSlateGray => XBrushes.DarkSlateGray,
        SheetInk.White => XBrushes.White,
        _ => XBrushes.Black,
    };

    private static XColor Color(SheetInk ink) => ink switch
    {
        SheetInk.Black => XColors.Black,
        SheetInk.DarkRed => XColors.DarkRed,
        SheetInk.Red => XColors.Red,
        SheetInk.DarkBlue => XColors.DarkBlue,
        SheetInk.DarkSlateGray => XColors.DarkSlateGray,
        SheetInk.White => XColors.White,
        _ => XColors.Black,
    };
}

/// <summary>
/// Draws a key sheet straight onto a printer device context.
/// </summary>
/// <remarks>
/// The alternative — rasterising the page and sending a bitmap — was what the
/// earlier Windows build did, and it is why the printed sheet and the exported
/// PDF had drifted into two different layouts. Drawing the same layout twice
/// through one interface keeps them the same document.
///
/// Nothing here is written to disk: the job goes from process memory into the
/// spooler, which is as far as any application can control it.
/// </remarks>
internal sealed class GdiSheetCanvas : ISheetCanvas, IDisposable
{
    // Typographic measurement, not the display-oriented default: the default
    // adds padding around the string, which would make MeasureWidth disagree
    // with the PDF surface and wrap the archive path at a different character.
    private static readonly GdiStringFormat Typographic =
        new(GdiStringFormat.GenericTypographic) { FormatFlags = System.Drawing.StringFormatFlags.MeasureTrailingSpaces };

    private readonly GdiGraphics _graphics;
    private readonly Dictionary<SheetFont, GdiFont> _fonts = [];
    private readonly double _offsetX;
    private readonly double _offsetY;

    internal GdiSheetCanvas(GdiGraphics graphics, double widthPoints, double heightPoints, double offsetX, double offsetY)
    {
        _graphics = graphics ?? throw new ArgumentNullException(nameof(graphics));
        _graphics.PageUnit = GdiGraphicsUnit.Point;
        _offsetX = offsetX;
        _offsetY = offsetY;
        WidthPoints = widthPoints;
        HeightPoints = heightPoints;
    }

    public double WidthPoints { get; }

    public double HeightPoints { get; }

    public void DrawText(string text, SheetFont font, SheetInk ink, double x, double baselineY)
    {
        GdiFont resolved = Resolve(font);
        double ascent = AscentPoints(resolved);
        _graphics.DrawString(
            text,
            resolved,
            Brush(ink),
            new GdiPointF((float)(x + _offsetX), (float)(baselineY - ascent + _offsetY)),
            Typographic);
    }

    public void DrawLine(SheetInk ink, double x1, double y1, double x2, double y2)
    {
        using var pen = new GdiPen(Color(ink), 1f);
        _graphics.DrawLine(
            pen,
            (float)(x1 + _offsetX),
            (float)(y1 + _offsetY),
            (float)(x2 + _offsetX),
            (float)(y2 + _offsetY));
    }

    public void FillRectangle(SheetInk ink, double x, double y, double width, double height)
    {
        _graphics.FillRectangle(
            Brush(ink),
            (float)(x + _offsetX),
            (float)(y + _offsetY),
            (float)width,
            (float)height);
    }

    public double MeasureWidth(string text, SheetFont font)
    {
        if (string.IsNullOrEmpty(text))
        {
            return 0;
        }

        GdiSizeF size = _graphics.MeasureString(text, Resolve(font), int.MaxValue, Typographic);
        return size.Width;
    }

    public void Dispose()
    {
        foreach (GdiFont font in _fonts.Values)
        {
            font.Dispose();
        }

        _fonts.Clear();
    }

    /// <summary>
    /// How far the baseline sits below the top of a line box, in points.
    /// </summary>
    /// <remarks>
    /// GDI positions a string by its top-left corner and PDFsharp by its
    /// baseline. Converting through the font's own design metrics rather than a
    /// fixed fraction keeps the two surfaces aligned whatever face is
    /// installed.
    /// </remarks>
    private static double AscentPoints(GdiFont font)
    {
        GdiFontFamily family = font.FontFamily;
        GdiFontStyle style = font.Style;
        int emHeight = family.GetEmHeight(style);
        return emHeight == 0 ? font.SizeInPoints : font.SizeInPoints * family.GetCellAscent(style) / emHeight;
    }

    private GdiFont Resolve(SheetFont font)
    {
        if (_fonts.TryGetValue(font, out GdiFont? existing))
        {
            return existing;
        }

        var created = new GdiFont(
            font.Family,
            (float)font.Size,
            font.Bold ? GdiFontStyle.Bold : GdiFontStyle.Regular,
            GdiGraphicsUnit.Point);
        _fonts[font] = created;
        return created;
    }

    private static GdiBrush Brush(SheetInk ink) => ink switch
    {
        SheetInk.Black => GdiBrushes.Black,
        SheetInk.DarkRed => GdiBrushes.DarkRed,
        SheetInk.Red => GdiBrushes.Red,
        SheetInk.DarkBlue => GdiBrushes.DarkBlue,
        SheetInk.DarkSlateGray => GdiBrushes.DarkSlateGray,
        SheetInk.White => GdiBrushes.White,
        _ => GdiBrushes.Black,
    };

    private static System.Drawing.Color Color(SheetInk ink) => ink switch
    {
        SheetInk.Black => System.Drawing.Color.Black,
        SheetInk.DarkRed => System.Drawing.Color.DarkRed,
        SheetInk.Red => System.Drawing.Color.Red,
        SheetInk.DarkBlue => System.Drawing.Color.DarkBlue,
        SheetInk.DarkSlateGray => System.Drawing.Color.DarkSlateGray,
        SheetInk.White => System.Drawing.Color.White,
        _ => System.Drawing.Color.Black,
    };
}

/// <summary>
/// The key sheet itself: what goes on the paper, and where.
/// </summary>
/// <remarks>
/// Written against <see cref="ISheetCanvas"/> so the exported PDF and the
/// printed page are produced by one piece of code, and kept deliberately in
/// step with the macOS layout in
/// <c>KeepVaultMac/Services/KeySheetService.cs</c>: the same headings, the same
/// order, the same two QR codes and the same separating installation page. A
/// sheet printed on one platform has to be readable by someone holding the
/// other platform's manual.
/// </remarks>
internal static class KeySheetLayout
{
    /// <summary>
    /// No text on a key sheet is ever smaller than this.
    /// </summary>
    /// <remarks>
    /// These sheets are read under stress, often years later and often by
    /// someone older than the person who printed them. A hex factor misread by
    /// one character is unrecoverable, so legibility is a security property
    /// here, not a matter of taste.
    /// </remarks>
    internal const double MinimumFontSize = 16;

    internal const double A4WidthPoints = 595.2755905511812;
    internal const double A4HeightPoints = 841.8897637795277;

    /// <summary>
    /// The page the app can be downloaded and verified from.
    /// </summary>
    /// <remarks>
    /// A key sheet outlives the computer it was printed on. Whoever finds it
    /// later needs to know what it belongs to and where to get the program that
    /// reads it, so the address is on the paper rather than only in the app.
    /// </remarks>
    internal const string ProjectUrl = "https://github.com/michael-feinermann/keep-vault";

    private const double Margin = 42;
    private const double BodyWidth = 500;

    private static readonly SheetFont TitleFont = new(SheetFont.Sans, 24, Bold: true);
    private static readonly SheetFont HeadingFont = new(SheetFont.Sans, MinimumFontSize, Bold: true);
    private static readonly SheetFont NormalFont = new(SheetFont.Sans, MinimumFontSize, Bold: false);
    private static readonly SheetFont WarningFont = new(SheetFont.Sans, MinimumFontSize, Bold: true);
    private static readonly SheetFont ShoutFont = new(SheetFont.Sans, 19, Bold: true);

    // The factor is the one thing on this sheet that must never be misread, so
    // it is set at the same size as the heading announcing it.
    private static readonly SheetFont MonoFont = new(SheetFont.Mono, MinimumFontSize, Bold: false);

    internal static void DrawSheet(
        ISheetCanvas canvas,
        ValidatedKeySheetData data,
        KeySheetFactor factor,
        bool separatedByBlankPage)
    {
        ArgumentNullException.ThrowIfNull(canvas);
        ArgumentNullException.ThrowIfNull(data);
        string generatedPassword = factor == KeySheetFactor.First
            ? data.FirstGeneratedPassword
            : data.SecondGeneratedPassword;
        string factorName = factor == KeySheetFactor.First ? "A" : "B";
        bool en = data.English;
        double y = Margin;

        canvas.DrawText(
            en ? $"{KeySheetService.ProductName} key sheet {factorName}" : $"{KeySheetService.ProductName} Schlüsselzettel {factorName}",
            TitleFont,
            SheetInk.Black,
            Margin,
            y);
        y += 30;

        // Flowed rather than clipped into a fixed rectangle: the two variants
        // differ in length and translate differently, and a warning that loses
        // its last line is worse than no warning at all.
        y += 4;
        DrawWrappedValue(
            canvas,
            WarningFont,
            separatedByBlankPage
                ? (en
                    ? "Keep this key sheet separate from the other one. The page between A and B separates the two factors on purpose."
                    : "Diesen Schlüsselzettel getrennt vom anderen aufbewahren. Die Seite zwischen A und B trennt beide Faktoren absichtlich.")
                : (en
                    ? "Keep this key sheet separate from the other one. The other factor is in its own file."
                    : "Diesen Schlüsselzettel getrennt vom anderen aufbewahren. Der andere Faktor liegt in einer eigenen Datei."),
            Margin,
            BodyWidth,
            ref y,
            SheetInk.DarkRed);
        y += 10;

        canvas.DrawText(
            en ? "DO NOT THROW AWAY!" : "NICHT WEGSCHMEISSEN!",
            ShoutFont,
            SheetInk.Red,
            Margin,
            y);
        y += 30;

        DrawLabelAndValue(canvas, en ? "Encryption suite" : "Verschlüsselungssuite", data.SuiteDisplayName, ref y);
        DrawLabelAndValue(
            canvas,
            en ? "Archive file" : "Archivdatei",
            Path.GetFileName(data.CanonicalArchivePath),
            ref y);
        DrawLabelAndValue(canvas, en ? "Created on device" : "Erstellt auf Gerät", data.DeviceName, ref y);
        DrawLabelAndValue(
            canvas,
            en ? "Storage location" : "Speicherort",
            Path.GetDirectoryName(data.CanonicalArchivePath) ?? data.CanonicalArchivePath,
            ref y);

        // Everything from the QR codes down is measured up from the bottom
        // edge. The fields above vary in height with the archive path, and the
        // codes and the download address are exactly the parts that must not be
        // the ones squeezed off the page when a path runs long.
        const double qrSize = 132;
        const double qrGap = 28;
        double footerBaseline = canvas.HeightPoints - 24;
        double urlBaseline = footerBaseline - 26;
        double urlLabelBaseline = urlBaseline - 21;
        double qrTop = urlLabelBaseline - 22 - qrSize;
        double qrHeadingBaseline = qrTop - 10;

        canvas.DrawText(
            en
                ? "User password (write by hand, never store digitally)"
                : "Benutzerpasswort (von Hand eintragen, nicht digital speichern)",
            HeadingFont,
            SheetInk.Black,
            Margin,
            y);

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
            canvas.DrawLine(SheetInk.Black, Margin, lineY, canvas.WidthPoints - Margin, lineY);
        }

        y = writingBottom;

        canvas.DrawText(
            en
                ? $"Generated hexadecimal 512-bit factor {factorName}"
                : $"Generierter hexadezimaler 512-Bit-Faktor {factorName}",
            HeadingFont,
            SheetInk.Black,
            Margin,
            y);
        y += 22;
        DrawWrappedValue(
            canvas,
            MonoFont,
            KeySheetService.GroupGeneratedPassword(generatedPassword),
            Margin,
            BodyWidth,
            ref y);

        canvas.DrawText(
            en
                ? $"Both QR codes contain factor {factorName} only (error correction Q)"
                : $"Beide QR-Codes enthalten ausschließlich Faktor {factorName} (Fehlerkorrektur Q)",
            HeadingFont,
            SheetInk.Black,
            Margin,
            qrHeadingBaseline);

        // Printed twice side by side: a single smudged, creased or faded code
        // would otherwise force the whole factor to be typed by hand.
        string qrPayload = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        DrawQrCode(canvas, qrPayload, Margin, qrTop, qrSize);
        DrawQrCode(canvas, qrPayload, Margin + qrSize + qrGap, qrTop, qrSize);

        canvas.DrawText(
            en ? "Download and verify the app at:" : "App herunterladen und prüfen unter:",
            NormalFont,
            SheetInk.Black,
            Margin,
            urlLabelBaseline);
        canvas.DrawText(ProjectUrl, NormalFont, SheetInk.DarkBlue, Margin, urlBaseline);

        string footer = en
            ? $"Created: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Keep offline and physically protected."
            : $"Erstellt: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Offline und physisch geschützt aufbewahren.";
        canvas.DrawText(footer, NormalFont, SheetInk.DarkSlateGray, Margin, footerBaseline);
    }

    /// <summary>
    /// Draws the page that separates factor A from factor B.
    /// </summary>
    /// <remarks>
    /// Nothing here depends on the archive or on either factor: this method
    /// deliberately takes no key-sheet data at all, so the separating page
    /// cannot leak anything even if it is later edited carelessly.
    /// </remarks>
    internal static void DrawInstallationPage(ISheetCanvas canvas, bool en)
    {
        ArgumentNullException.ThrowIfNull(canvas);
        double y = Margin;

        canvas.DrawText(
            en ? "Installing Keep Vault" : "Keep Vault installieren",
            TitleFont,
            SheetInk.Black,
            Margin,
            y);
        y += 34;

        DrawWrappedValue(
            canvas,
            NormalFont,
            en
                ? "This page separates factor A from factor B and contains no key material."
                : "Diese Seite trennt Faktor A von Faktor B und enthält kein Schlüsselmaterial.",
            Margin,
            BodyWidth,
            ref y);
        y += 14;

        canvas.DrawText(en ? "Download" : "Bezugsquelle", HeadingFont, SheetInk.Black, Margin, y);
        y += 22;
        canvas.DrawText(ProjectUrl, NormalFont, SheetInk.DarkBlue, Margin, y);
        y += 14;

        DrawQrCode(canvas, ProjectUrl, Margin, y, 126);
        y += 126 + 30;

        canvas.DrawText("Windows", HeadingFont, SheetInk.Black, Margin, y);
        y += 24;
        DrawSteps(canvas, ref y, en
            ? [
                "1. Download the Windows release from the page above.",
                "2. Unblock the ZIP file in its properties, then extract it.",
                "3. Run Install-KeepVaultShortcuts.ps1 in PowerShell, or start \"Keep Vault.exe\" directly.",
                "4. The installer verifies the dual signature before it creates any shortcut.",
            ]
            : [
                "1. Windows-Release von der oben genannten Seite herunterladen.",
                "2. Die ZIP-Datei in den Eigenschaften zulassen, danach entpacken.",
                "3. Install-KeepVaultShortcuts.ps1 in PowerShell ausführen oder \"Keep Vault.exe\" direkt starten.",
                "4. Der Installer prüft die duale Signatur, bevor er eine Verknüpfung anlegt.",
            ]);
        y += 16;

        canvas.DrawText("macOS", HeadingFont, SheetInk.Black, Margin, y);
        y += 24;
        DrawSteps(canvas, ref y, en
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
        canvas.DrawText(footer, NormalFont, SheetInk.DarkSlateGray, Margin, canvas.HeightPoints - 24);
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
    private static void DrawSteps(ISheetCanvas canvas, ref double y, string[] steps)
    {
        foreach (string step in steps)
        {
            DrawWrappedValue(canvas, NormalFont, step, Margin, BodyWidth, ref y);
            y += 4;
        }
    }

    private static void DrawLabelAndValue(ISheetCanvas canvas, string label, string value, ref double y)
    {
        canvas.DrawText(label, HeadingFont, SheetInk.Black, Margin, y);
        y += 22;
        DrawWrappedValue(canvas, NormalFont, value, Margin, BodyWidth, ref y);
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
        ISheetCanvas canvas,
        SheetFont font,
        string value,
        double x,
        double width,
        ref double y,
        SheetInk ink = SheetInk.Black)
    {
        const double lineHeight = 20;
        foreach (string line in WrapToWidth(canvas, font, value, width))
        {
            canvas.DrawText(line, font, ink, x, y);
            y += lineHeight;
        }
    }

    internal static List<string> WrapToWidth(ISheetCanvas canvas, SheetFont font, string value, double width)
    {
        var lines = new List<string>();
        if (string.IsNullOrEmpty(value))
        {
            lines.Add(string.Empty);
            return lines;
        }

        var current = new System.Text.StringBuilder();
        int lastBreak = -1;
        foreach (char character in value)
        {
            current.Append(character);
            if (character is '/' or ' ' or '\\' or '-' or '_')
            {
                lastBreak = current.Length;
            }

            if (canvas.MeasureWidth(current.ToString(), font) <= width)
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
    private static void DrawQrCode(ISheetCanvas canvas, string payload, double x, double y, double size)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData qrData = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        try
        {
            int moduleCount = qrData.ModuleMatrix.Count;
            double moduleSize = size / moduleCount;
            canvas.FillRectangle(SheetInk.White, x, y, size, size);

            for (int row = 0; row < moduleCount; row++)
            {
                BitArray rowData = qrData.ModuleMatrix[row];
                for (int column = 0; column < moduleCount; column++)
                {
                    if (rowData[column])
                    {
                        canvas.FillRectangle(
                            SheetInk.Black,
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

    internal static void ClearQrMatrix(QRCodeData qrData)
    {
        foreach (BitArray row in qrData.ModuleMatrix)
        {
            row.SetAll(false);
        }
    }
}
