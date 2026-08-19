using System.Globalization;
using System.Text;

namespace QrScanner;

// Describes what a decoded payload actually contains before the user acts on it.
//
// A QR code is a container for arbitrary bytes, and its content is going to be
// pasted somewhere - a terminal, a form, a password field. Characters that are
// invisible on screen but meaningful to whatever receives them are worth
// pointing out, because the whole appeal of scanning is that the user does not
// read what they are transferring.

public enum PayloadNoticeKind
{
    /// <summary>
    /// Characters that do nothing visible here but are not nothing elsewhere:
    /// escape sequences, newlines in the middle of a value, NUL bytes.
    /// </summary>
    ControlCharacters,

    /// <summary>
    /// Direction overrides, which let text render in an order other than the
    /// one it is stored in - the reason a pasted value can read differently
    /// from what it does.
    /// </summary>
    BidirectionalOverrides,

    /// <summary>Zero-width or invisible formatting characters.</summary>
    InvisibleCharacters,

    /// <summary>Padding that is easy to lose or gain when a value is handled by hand.</summary>
    SurroundingWhitespace,
}

public readonly record struct PayloadNotice(PayloadNoticeKind Kind, int Count)
{
    public string Message(Strings strings)
    {
        ArgumentNullException.ThrowIfNull(strings);
        return Kind switch
        {
            PayloadNoticeKind.ControlCharacters => strings.NoticeControlCharacters(Count),
            PayloadNoticeKind.BidirectionalOverrides => strings.NoticeBidirectional(Count),
            PayloadNoticeKind.InvisibleCharacters => strings.NoticeInvisible(Count),
            _ => strings.NoticeWhitespace,
        };
    }
}

public static class PayloadInspector
{
    /// <summary>
    /// Anything longer than this is not something a person is going to read off
    /// a screen, and a QR code cannot hold much more than this anyway. The cap
    /// keeps a malformed or hostile code from filling the window.
    /// </summary>
    public const int MaximumLength = 8192;

    /// <summary>Characters that rewrite how the text around them is displayed.</summary>
    private static readonly HashSet<int> BidiOverrides =
    [
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2066, 0x2067, 0x2068, 0x2069,
    ];

    private static readonly HashSet<int> Invisibles =
    [
        0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
    ];

    public static IReadOnlyList<PayloadNotice> Notices(string payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var notices = new List<PayloadNotice>();
        int controls = 0;
        int overrides = 0;
        int hidden = 0;

        foreach (int scalar in EnumerateScalars(payload))
        {
            if (BidiOverrides.Contains(scalar))
            {
                overrides++;
            }

            if (Invisibles.Contains(scalar))
            {
                hidden++;
            }

            if (scalar != '\n'
                && scalar != '\r'
                && CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(scalar), 0) == UnicodeCategory.Control)
            {
                controls++;
            }
        }

        if (controls > 0)
        {
            notices.Add(new PayloadNotice(PayloadNoticeKind.ControlCharacters, controls));
        }

        if (overrides > 0)
        {
            notices.Add(new PayloadNotice(PayloadNoticeKind.BidirectionalOverrides, overrides));
        }

        if (hidden > 0)
        {
            notices.Add(new PayloadNotice(PayloadNoticeKind.InvisibleCharacters, hidden));
        }

        if (payload.Length > 0 && !string.Equals(payload, payload.Trim(), StringComparison.Ordinal))
        {
            notices.Add(new PayloadNotice(PayloadNoticeKind.SurroundingWhitespace, 0));
        }

        return notices;
    }

    /// <summary>
    /// Rejects payloads that are empty or beyond what this app will display.
    /// </summary>
    /// <remarks>
    /// Nothing is trimmed or altered: what the code contains is what is copied,
    /// because a scanner that quietly cleans up its output is a scanner whose
    /// output cannot be trusted to match the code. Whitespace is reported as a
    /// notice instead.
    /// </remarks>
    public static string? Accept(string? payload)
    {
        return string.IsNullOrEmpty(payload) || payload.Length > MaximumLength ? null : payload;
    }

    /// <summary>
    /// Renders control characters visible so the text box shows what is there.
    /// </summary>
    /// <remarks>
    /// Only the display is escaped. The copy button always hands over the
    /// original payload.
    /// </remarks>
    public static string DisplayText(string payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var rendered = new StringBuilder(payload.Length);
        foreach (int scalar in EnumerateScalars(payload))
        {
            if (scalar == '\n' || scalar == '\t')
            {
                rendered.Append((char)scalar);
                continue;
            }

            bool control = CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(scalar), 0) == UnicodeCategory.Control;
            if (control || BidiOverrides.Contains(scalar) || Invisibles.Contains(scalar))
            {
                rendered.Append(CultureInfo.InvariantCulture, $"‹U+{scalar:X4}›");
            }
            else
            {
                rendered.Append(char.ConvertFromUtf32(scalar));
            }
        }

        return rendered.ToString();
    }

    /// <summary>
    /// Walks the string by Unicode scalar rather than by UTF-16 unit.
    /// </summary>
    /// <remarks>
    /// A surrogate pair is one character to the person reading it, and counting
    /// it as two would make the length cap and the notices disagree with what
    /// is on screen.
    /// </remarks>
    private static IEnumerable<int> EnumerateScalars(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            if (char.IsHighSurrogate(value[index]) && index + 1 < value.Length && char.IsLowSurrogate(value[index + 1]))
            {
                yield return char.ConvertToUtf32(value[index], value[index + 1]);
                index++;
            }
            else
            {
                yield return value[index];
            }
        }
    }
}
