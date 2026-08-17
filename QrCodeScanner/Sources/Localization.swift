import Foundation

// German and English, switchable while the app is running.
//
// Every piece of text the user can see is in this one file, as two values of
// the same type. The compiler therefore refuses a translation that is missing
// rather than letting it fall back to the other language at runtime, which is
// how half-translated interfaces normally happen.
//
// Text that carries a number is a closure rather than a format string, because
// word order is not the same in both languages and a positional placeholder
// would quietly put the number in the wrong place.

enum Language: String, CaseIterable {
    case german = "de"
    case english = "en"

    var strings: Strings {
        switch self {
        case .german: return .german
        case .english: return .english
        }
    }

    /// The name of the language in that language, which is what a language
    /// switch should say: someone looking for English should not have to know
    /// the German word for it.
    var ownName: String {
        switch self {
        case .german: return "Deutsch"
        case .english: return "English"
        }
    }
}

struct Strings {
    let languageLabel: String

    let menuAbout: String
    let menuHide: String
    let menuQuit: String
    let menuEdit: String
    let menuCopy: String
    let menuSelectAll: String

    let copyButton: String
    let rescanButton: String

    let requestingCamera: String
    let ready: String
    let confirming: (_ progress: Int, _ required: Int) -> String
    let conflict: (_ count: Int) -> String
    let acceptedMatching: (_ count: Int) -> String
    let acceptedRepeated: (_ count: Int) -> String
    let copied: (_ seconds: Int) -> String
    let clipboardCleared: String
    let cameraDeniedHint: String

    let noCamera: String
    let cameraUnavailable: String
    let decoderUnavailable: String
    let accessDenied: (_ before: String, _ after: String) -> String

    let statusNotDetermined: String
    let statusRestricted: String
    let statusDenied: String
    let statusAuthorized: String
    let statusUnknown: String

    let noticeControlCharacters: (_ count: Int) -> String
    let noticeBidirectional: (_ count: Int) -> String
    let noticeInvisible: (_ count: Int) -> String
    let noticeWhitespace: String

    static let german = Strings(
        languageLabel: "Sprache",
        menuAbout: "Über QR-Scanner",
        menuHide: "QR-Scanner ausblenden",
        menuQuit: "QR-Scanner beenden",
        menuEdit: "Bearbeiten",
        menuCopy: "Kopieren",
        menuSelectAll: "Alles auswählen",
        copyButton: "Kopieren",
        rescanButton: "Erneut scannen",
        requestingCamera: "Kamera wird angefragt …",
        ready: "Bereit. QR-Code vor die Kamera halten.",
        confirming: { progress, required in
            "Ein Code lesbar – wird bestätigt (\(progress)/\(required)) …"
        },
        conflict: { count in
            "\(count) unterschiedliche QR-Codes im Bild. Bitte nur einen Code zeigen."
        },
        acceptedMatching: { count in
            "Erkannt und bestätigt: \(count) Codes im Bild mit identischem Inhalt."
        },
        acceptedRepeated: { count in
            "Erkannt: nur ein Code lesbar, \(count)-mal mit gleichem Ergebnis gelesen."
        },
        copied: { seconds in
            "Kopiert. Der Inhalt wird nach \(seconds) Sekunden aus der Zwischenablage entfernt."
        },
        clipboardCleared: "Die Zwischenablage wurde geleert. Zum erneuten Einfügen noch einmal auf „Kopieren“ klicken.",
        cameraDeniedHint: "Kamerazugriff in den Systemeinstellungen unter „Datenschutz & Sicherheit“ › „Kamera“ für QR-Scanner erlauben.",
        noCamera: "Es wurde keine Kamera gefunden.",
        cameraUnavailable: "Die Kamera konnte nicht geöffnet werden. Möglicherweise benutzt sie gerade ein anderes Programm.",
        decoderUnavailable: "Der QR-Decoder konnte nicht eingerichtet werden.",
        accessDenied: { before, after in
            "Der Kamerazugriff wurde verweigert (Status vorher: \(before), nachher: \(after))."
        },
        statusNotDetermined: "nicht entschieden",
        statusRestricted: "durch Richtlinie gesperrt",
        statusDenied: "verweigert",
        statusAuthorized: "erlaubt",
        statusUnknown: "unbekannt",
        noticeControlCharacters: { count in
            "Enthält \(count) Steuerzeichen, die hier nicht sichtbar sind."
        },
        noticeBidirectional: { count in
            "Enthält \(count) Zeichen, die die Leserichtung umkehren; der Text kann anders erscheinen als er gespeichert ist."
        },
        noticeInvisible: { count in
            "Enthält \(count) unsichtbare Zeichen."
        },
        noticeWhitespace: "Beginnt oder endet mit Leerzeichen.")

    static let english = Strings(
        languageLabel: "Language",
        menuAbout: "About QR-Scanner",
        menuHide: "Hide QR-Scanner",
        menuQuit: "Quit QR-Scanner",
        menuEdit: "Edit",
        menuCopy: "Copy",
        menuSelectAll: "Select All",
        copyButton: "Copy",
        rescanButton: "Scan again",
        requestingCamera: "Requesting the camera …",
        ready: "Ready. Hold a QR code in front of the camera.",
        confirming: { progress, required in
            "One code readable – confirming (\(progress)/\(required)) …"
        },
        conflict: { count in
            "\(count) different QR codes in view. Please show only one code."
        },
        acceptedMatching: { count in
            "Read and confirmed: \(count) codes in view with identical content."
        },
        acceptedRepeated: { count in
            "Read: only one code was readable, read \(count) times with the same result."
        },
        copied: { seconds in
            "Copied. The content will be removed from the clipboard after \(seconds) seconds."
        },
        clipboardCleared: "The clipboard has been cleared. Click “Copy” again to paste it once more.",
        cameraDeniedHint: "Allow camera access for QR-Scanner in System Settings under “Privacy & Security” › “Camera”.",
        noCamera: "No camera was found.",
        cameraUnavailable: "The camera could not be opened. Another program may be using it.",
        decoderUnavailable: "The QR decoder could not be set up.",
        accessDenied: { before, after in
            "Camera access was denied (status before: \(before), after: \(after))."
        },
        statusNotDetermined: "not determined",
        statusRestricted: "restricted by policy",
        statusDenied: "denied",
        statusAuthorized: "granted",
        statusUnknown: "unknown",
        noticeControlCharacters: { count in
            "Contains \(count) control characters that are not visible here."
        },
        noticeBidirectional: { count in
            "Contains \(count) characters that reverse the reading direction; the text may appear different from how it is stored."
        },
        noticeInvisible: { count in
            "Contains \(count) invisible characters."
        },
        noticeWhitespace: "Starts or ends with whitespace.")
}

extension Notification.Name {
    static let languageChanged = Notification.Name("de.michael-feinermann.qr-scanner.languageChanged")
}

/// Holds the chosen language and remembers it between launches.
///
/// This one preference is the only thing the app ever writes. It is a two-letter
/// language code and nothing else: no scanned content, no history, no window
/// state. See README.md — the rest of the app is arranged specifically so that
/// there is nothing else to write.
@MainActor
final class Localization {
    static let shared = Localization()

    private static let defaultsKey = "language"

    private(set) var language: Language

    var strings: Strings { language.strings }

    private init() {
        if let stored = UserDefaults.standard.string(forKey: Self.defaultsKey),
           let remembered = Language(rawValue: stored) {
            language = remembered
        } else {
            // No choice made yet, so follow the system. A Mac set to German
            // should not open in English before the user has said anything.
            let preferred = Locale.preferredLanguages.first ?? "en"
            language = preferred.hasPrefix("de") ? .german : .english
        }
    }

    func select(_ language: Language) {
        guard language != self.language else { return }
        self.language = language
        UserDefaults.standard.set(language.rawValue, forKey: Self.defaultsKey)
        NotificationCenter.default.post(name: .languageChanged, object: nil)
    }
}
