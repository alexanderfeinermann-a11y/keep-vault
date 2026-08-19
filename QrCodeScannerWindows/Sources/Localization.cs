using System.Globalization;

namespace QrScanner;

// German and English, switchable while the app is running.
//
// Every piece of text the user can see is in this one file, as two values of
// the same type. The compiler therefore refuses a translation that is missing
// rather than letting it fall back to the other language at runtime, which is
// how half-translated interfaces normally happen.
//
// Text that carries a number is a delegate rather than a format string, because
// word order is not the same in both languages and a positional placeholder
// would quietly put the number in the wrong place.

public enum Language
{
    German,
    English,
}

public sealed record Strings(
    string LanguageLabel,
    string CopyButton,
    string RescanButton,
    string RequestingCamera,
    string Ready,
    Func<int, int, string> Confirming,
    Func<int, string> Conflict,
    Func<int, string> AcceptedMatching,
    Func<int, string> AcceptedRepeated,
    Func<int, string> Copied,
    string ClipboardCleared,
    string CameraDeniedHint,
    string NoCamera,
    string CameraUnavailable,
    string DecoderUnavailable,
    Func<string, string> AccessDenied,
    string StatusDenied,
    string StatusUnavailable,
    string StatusUnknown,
    Func<int, string> NoticeControlCharacters,
    Func<int, string> NoticeBidirectional,
    Func<int, string> NoticeInvisible,
    string NoticeWhitespace,
    string WindowTitle,
    string ScannedValueLabel)
{
    public static Strings For(Language language) => language == Language.German ? German : English;

    /// <summary>
    /// The name of the language in that language, which is what a language
    /// switch should say: someone looking for English should not have to know
    /// the German word for it.
    /// </summary>
    public static string OwnName(Language language) => language == Language.German ? "Deutsch" : "English";

    public static readonly Strings German = new(
        LanguageLabel: "Sprache",
        CopyButton: "Kopieren",
        RescanButton: "Erneut scannen",
        RequestingCamera: "Kamera wird angefragt …",
        Ready: "Bereit. QR-Code vor die Kamera halten.",
        Confirming: (progress, required) => $"Ein Code lesbar – wird bestätigt ({progress}/{required}) …",
        Conflict: count => $"{count} unterschiedliche QR-Codes im Bild. Bitte nur einen Code zeigen.",
        AcceptedMatching: count => $"Erkannt und bestätigt: {count} Codes im Bild mit identischem Inhalt.",
        AcceptedRepeated: count => $"Erkannt: nur ein Code lesbar, {count}-mal mit gleichem Ergebnis gelesen.",
        Copied: seconds => $"Kopiert. Der Inhalt wird nach {seconds} Sekunden aus der Zwischenablage entfernt.",
        ClipboardCleared: "Die Zwischenablage wurde geleert. Zum erneuten Einfügen noch einmal auf „Kopieren“ klicken.",
        CameraDeniedHint: "Kamerazugriff in den Windows-Einstellungen unter „Datenschutz und Sicherheit“ › „Kamera“ für Desktop-Apps erlauben.",
        NoCamera: "Es wurde keine Kamera gefunden.",
        CameraUnavailable: "Die Kamera konnte nicht geöffnet werden. Möglicherweise benutzt sie gerade ein anderes Programm.",
        DecoderUnavailable: "Der QR-Decoder konnte nicht eingerichtet werden.",
        AccessDenied: detail => $"Der Kamerazugriff wurde verweigert ({detail}).",
        StatusDenied: "durch die Datenschutzeinstellungen gesperrt",
        StatusUnavailable: "Gerät nicht verfügbar",
        StatusUnknown: "unbekannt",
        NoticeControlCharacters: count => $"Enthält {count} Steuerzeichen, die hier nicht sichtbar sind.",
        NoticeBidirectional: count =>
            $"Enthält {count} Zeichen, die die Leserichtung umkehren; der Text kann anders erscheinen als er gespeichert ist.",
        NoticeInvisible: count => $"Enthält {count} unsichtbare Zeichen ohne Breite.",
        NoticeWhitespace: "Beginnt oder endet mit Leerraum. Der Inhalt wird unverändert kopiert.",
        WindowTitle: "QR-Scanner",
        ScannedValueLabel: "Gelesener Inhalt");

    public static readonly Strings English = new(
        LanguageLabel: "Language",
        CopyButton: "Copy",
        RescanButton: "Scan again",
        RequestingCamera: "Requesting the camera …",
        Ready: "Ready. Hold a QR code in front of the camera.",
        Confirming: (progress, required) => $"One code readable – confirming ({progress}/{required}) …",
        Conflict: count => $"{count} different QR codes in view. Please show only one code.",
        AcceptedMatching: count => $"Read and confirmed: {count} codes in view with identical content.",
        AcceptedRepeated: count => $"Read: only one code was readable, decoded {count} times with the same result.",
        Copied: seconds => $"Copied. The content is removed from the clipboard after {seconds} seconds.",
        ClipboardCleared: "The clipboard was cleared. Press \"Copy\" again to paste once more.",
        CameraDeniedHint: "Allow camera access for desktop apps under Windows Settings › Privacy & security › Camera.",
        NoCamera: "No camera was found.",
        CameraUnavailable: "The camera could not be opened. Another program may be using it.",
        DecoderUnavailable: "The QR decoder could not be set up.",
        AccessDenied: detail => $"Camera access was refused ({detail}).",
        StatusDenied: "blocked by the privacy settings",
        StatusUnavailable: "device unavailable",
        StatusUnknown: "unknown",
        NoticeControlCharacters: count => $"Contains {count} control characters that are not visible here.",
        NoticeBidirectional: count =>
            $"Contains {count} characters that reverse the reading direction; the text may appear differently from how it is stored.",
        NoticeInvisible: count => $"Contains {count} invisible zero-width characters.",
        NoticeWhitespace: "Starts or ends with whitespace. The content is copied unchanged.",
        WindowTitle: "QR-Scanner",
        ScannedValueLabel: "Scanned content");

    /// <summary>
    /// The sentence for one arbitration outcome.
    /// </summary>
    /// <remarks>
    /// Built here rather than at the call site so switching language re-renders
    /// the current state instead of leaving the last sentence in the old one.
    /// </remarks>
    public string Describe(ScanOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        return outcome.Kind switch
        {
            ScanOutcomeKind.Searching => Ready,
            ScanOutcomeKind.Confirming => Confirming(outcome.Progress, outcome.Required),
            ScanOutcomeKind.Conflict => Conflict(outcome.ConflictingPayloads?.Count ?? 0),
            ScanOutcomeKind.Accepted => outcome.Corroboration.Kind == CorroborationKind.MatchingCodes
                ? AcceptedMatching(outcome.Corroboration.Count)
                : AcceptedRepeated(outcome.Corroboration.Count),
            _ => Ready,
        };
    }

    /// <summary>
    /// The language the machine is set to, falling back to English.
    /// </summary>
    public static Language FromCurrentCulture()
    {
        return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName
            .Equals("de", StringComparison.OrdinalIgnoreCase)
            ? Language.German
            : Language.English;
    }
}
