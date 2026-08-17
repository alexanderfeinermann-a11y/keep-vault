import Foundation

// Describes what a decoded payload actually contains before the user acts on it.
//
// A QR code is a container for arbitrary bytes, and its content is going to be
// pasted somewhere — a terminal, a form, a password field. Characters that are
// invisible on screen but meaningful to whatever receives them are worth
// pointing out, because the whole appeal of scanning is that the user does not
// read what they are transferring.

enum PayloadNotice: Equatable {
    /// Characters that do nothing visible here but are not nothing elsewhere:
    /// escape sequences, newlines in the middle of a value, NUL bytes.
    case controlCharacters(count: Int)

    /// Direction overrides, which let text render in an order other than the
    /// one it is stored in — the reason a pasted value can read differently
    /// from what it does.
    case bidirectionalOverrides(count: Int)

    /// Zero-width or invisible formatting characters.
    case invisibleCharacters(count: Int)

    /// Padding that is easy to lose or gain when a value is handled by hand.
    case surroundingWhitespace

    func message(_ strings: Strings) -> String {
        switch self {
        case .controlCharacters(let count):
            return strings.noticeControlCharacters(count)
        case .bidirectionalOverrides(let count):
            return strings.noticeBidirectional(count)
        case .invisibleCharacters(let count):
            return strings.noticeInvisible(count)
        case .surroundingWhitespace:
            return strings.noticeWhitespace
        }
    }
}

enum PayloadInspector {
    /// Anything longer than this is not something a person is going to read off
    /// a screen, and a QR code cannot hold much more than this anyway. The cap
    /// keeps a malformed or hostile code from filling the window.
    static let maximumLength = 8192

    /// Characters that rewrite how the text around them is displayed.
    private static let bidiOverrides: Set<Unicode.Scalar> = [
        "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
        "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}",
    ]

    private static let invisibles: Set<Unicode.Scalar> = [
        "\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{FEFF}", "\u{00AD}",
    ]

    static func notices(for payload: String) -> [PayloadNotice] {
        var notices: [PayloadNotice] = []

        let controls = payload.unicodeScalars.filter { scalar in
            scalar.properties.generalCategory == .control && scalar != "\n" && scalar != "\r"
        }
        if !controls.isEmpty {
            notices.append(.controlCharacters(count: controls.count))
        }

        let overrides = payload.unicodeScalars.filter(bidiOverrides.contains)
        if !overrides.isEmpty {
            notices.append(.bidirectionalOverrides(count: overrides.count))
        }

        let hidden = payload.unicodeScalars.filter(invisibles.contains)
        if !hidden.isEmpty {
            notices.append(.invisibleCharacters(count: hidden.count))
        }

        if payload != payload.trimmingCharacters(in: .whitespacesAndNewlines), !payload.isEmpty {
            notices.append(.surroundingWhitespace)
        }

        return notices
    }

    /// Rejects payloads that are empty or beyond what this app will display.
    ///
    /// Nothing is trimmed or altered: what the code contains is what is copied,
    /// because a scanner that quietly cleans up its output is a scanner whose
    /// output cannot be trusted to match the code. Whitespace is reported as a
    /// notice instead.
    static func accept(_ payload: String) -> String? {
        guard !payload.isEmpty, payload.count <= maximumLength else {
            return nil
        }
        return payload
    }

    /// Renders control characters visible so the text view shows what is there.
    ///
    /// Only the display is escaped. The copy button always hands over the
    /// original payload.
    static func displayText(for payload: String) -> String {
        var rendered = ""
        rendered.reserveCapacity(payload.count)
        for scalar in payload.unicodeScalars {
            if scalar == "\n" || scalar == "\t" {
                rendered.unicodeScalars.append(scalar)
            } else if scalar.properties.generalCategory == .control
                || bidiOverrides.contains(scalar)
                || invisibles.contains(scalar) {
                rendered += String(format: "‹U+%04X›", scalar.value)
            } else {
                rendered.unicodeScalars.append(scalar)
            }
        }
        return rendered
    }
}
