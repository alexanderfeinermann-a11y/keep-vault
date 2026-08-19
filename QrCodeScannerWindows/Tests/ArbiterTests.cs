using System.Reflection;
using QrScanner;
using QrScanner.Tests;

// Checks the rule this app exists for: which of two printed QR codes is taken.
//
// No test framework, because this needs none: it runs as part of the build and
// fails it on the first wrong answer. The checks are the macOS suite's, in the
// same order, so the two scanners cannot drift apart on the one decision that
// matters.

internal static class ArbiterTests
{
    private static int _failures;
    private static int _checks;

    private const string Factor =
        "A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4"
        + "A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4";

    private static int Main()
    {
        BothCodesReadableIsAcceptedImmediately();
        OneDamagedCodeFallsBackToTheReadableOne();
        ALoneCodeIsNotAcceptedOnItsFirstSighting();
        DisagreeingCodesAreRefused();
        ADuplicateReportIsNotASecondCode();
        FlickerDoesNotResetTheTally();
        AChangedPayloadRestartsTheTally();
        PayloadInspection();
        BothLanguagesAreComplete();
        DecodesRealCodes();

        if (_failures == 0)
        {
            Console.WriteLine($"ArbiterTests: {_checks} checks passed");
            return 0;
        }

        Console.Error.WriteLine($"ArbiterTests: {_failures} of {_checks} checks failed");
        return 1;
    }

    private static void Expect(bool condition, string description)
    {
        _checks++;
        if (!condition)
        {
            _failures++;
            Console.Error.WriteLine($"FAIL {description}");
        }
    }

    private static void ExpectEqual<T>(T actual, T expected, string description)
    {
        _checks++;
        if (!EqualityComparer<T>.Default.Equals(actual, expected))
        {
            _failures++;
            Console.Error.WriteLine($"FAIL {description}: expected {expected}, got {actual}");
        }
    }

    /// <summary>Two codes side by side, as they are printed on a sheet.</summary>
    private static Detection[] Pair(string left, string right) =>
    [
        new Detection(left, 0.3, 0.5),
        new Detection(right, 0.7, 0.5),
    ];

    private static Detection[] Single(string payload) => [new Detection(payload, 0.5, 0.5)];

    private static void ExpectAccepted(ScanOutcome outcome, string payload, CorroborationKind kind, int count, string description)
    {
        Expect(
            outcome.Kind == ScanOutcomeKind.Accepted
            && string.Equals(outcome.Payload, payload, StringComparison.Ordinal)
            && outcome.Corroboration.Kind == kind
            && outcome.Corroboration.Count == count,
            $"{description} (got {outcome.Kind}/{outcome.Corroboration.Kind}/{outcome.Corroboration.Count})");
    }

    private static void ExpectConfirming(ScanOutcome outcome, int progress, int required, string description)
    {
        Expect(
            outcome.Kind == ScanOutcomeKind.Confirming
            && outcome.Progress == progress
            && outcome.Required == required,
            $"{description} (got {outcome.Kind} {outcome.Progress}/{outcome.Required})");
    }

    /// <summary>
    /// Both printed codes decode. They agree, so the payload is taken at once -
    /// no repeat count needed, because a second printed copy is better evidence
    /// than the same code read twice.
    /// </summary>
    private static void BothCodesReadableIsAcceptedImmediately()
    {
        var arbiter = new CodeArbiter();
        ScanOutcome outcome = arbiter.Admit(Pair(Factor, Factor));
        ExpectAccepted(outcome, Factor, CorroborationKind.MatchingCodes, 2, "two matching codes are accepted on the first frame");
    }

    /// <summary>
    /// The user's case: one code is creased or stained, so it never decodes and
    /// never reaches the arbiter. The readable one carries the content.
    /// </summary>
    private static void OneDamagedCodeFallsBackToTheReadableOne()
    {
        var arbiter = new CodeArbiter(requiredRepeats: 3);
        ExpectConfirming(arbiter.Admit(Single(Factor)), 1, 3, "first read of a lone code confirms once");
        ExpectConfirming(arbiter.Admit(Single(Factor)), 2, 3, "second read of a lone code confirms twice");
        ExpectAccepted(
            arbiter.Admit(Single(Factor)),
            Factor,
            CorroborationKind.RepeatedReads,
            3,
            "a lone code is accepted once it has repeated itself");
    }

    private static void ALoneCodeIsNotAcceptedOnItsFirstSighting()
    {
        var arbiter = new CodeArbiter(requiredRepeats: 8);
        for (int step = 1; step < 8; step++)
        {
            ExpectConfirming(arbiter.Admit(Single(Factor)), step, 8, $"a lone code is still unconfirmed after {step} frames");
        }
    }

    /// <summary>
    /// Two codes that decode to different content cannot both be the sheet's
    /// factor. Nothing is accepted and the disagreement is reported.
    /// </summary>
    private static void DisagreeingCodesAreRefused()
    {
        var arbiter = new CodeArbiter();
        ScanOutcome outcome = arbiter.Admit(Pair("ALPHA", "BETA"));
        Expect(
            outcome.Kind == ScanOutcomeKind.Conflict
            && outcome.ConflictingPayloads is ["ALPHA", "BETA"],
            "disagreeing codes are refused");

        // The conflict must also clear whatever was being counted, so a payload
        // half-way to acceptance cannot be completed after a second code has
        // contradicted it.
        var counting = new CodeArbiter(requiredRepeats: 2);
        _ = counting.Admit(Single("ALPHA"));
        _ = counting.Admit(Pair("ALPHA", "BETA"));
        ExpectConfirming(counting.Admit(Single("ALPHA")), 1, 2, "a conflict restarts the tally");
    }

    /// <summary>
    /// The same physical code reported twice in one frame must not be mistaken
    /// for two printed copies; otherwise the strongest acceptance the app
    /// offers would rest on a duplicate report.
    /// </summary>
    private static void ADuplicateReportIsNotASecondCode()
    {
        var arbiter = new CodeArbiter(requiredRepeats: 4);
        Detection[] overlapping =
        [
            new Detection(Factor, 0.500, 0.500),
            new Detection(Factor, 0.505, 0.502),
        ];
        ExpectConfirming(arbiter.Admit(overlapping), 1, 4, "two reports of one code are not treated as two codes");
    }

    /// <summary>
    /// Detection drops out between frames. A single missing frame must not
    /// throw away a tally, or a lone code would never reach the repeat count.
    /// </summary>
    private static void FlickerDoesNotResetTheTally()
    {
        var arbiter = new CodeArbiter(requiredRepeats: 3, toleratedMisses: 2);
        _ = arbiter.Admit(Single(Factor));
        _ = arbiter.Admit([]);
        _ = arbiter.Admit(Single(Factor));
        ExpectAccepted(
            arbiter.Admit(Single(Factor)),
            Factor,
            CorroborationKind.RepeatedReads,
            3,
            "a dropped frame does not discard the tally");

        var patient = new CodeArbiter(requiredRepeats: 3, toleratedMisses: 2);
        _ = patient.Admit(Single(Factor));
        _ = patient.Admit([]);
        _ = patient.Admit([]);
        _ = patient.Admit([]);
        ExpectConfirming(patient.Admit(Single(Factor)), 1, 3, "a code out of view long enough starts over");
    }

    private static void AChangedPayloadRestartsTheTally()
    {
        var arbiter = new CodeArbiter(requiredRepeats: 3);
        _ = arbiter.Admit(Single("ALPHA"));
        _ = arbiter.Admit(Single("ALPHA"));
        ExpectConfirming(arbiter.Admit(Single("BETA")), 1, 3, "a different payload starts its own tally");
    }

    private static void PayloadInspection()
    {
        Expect(PayloadInspector.Accept("") is null, "an empty payload is rejected");
        Expect(
            PayloadInspector.Accept(new string('x', PayloadInspector.MaximumLength + 1)) is null,
            "an oversized payload is rejected");
        ExpectEqual(PayloadInspector.Accept(Factor), Factor, "a normal payload passes through unchanged");

        // Nothing is trimmed: the copy button must hand over exactly what the
        // code contained, so padding is reported rather than removed.
        ExpectEqual(PayloadInspector.Accept("  spaced  "), "  spaced  ", "whitespace is preserved, not trimmed");
        Expect(
            PayloadInspector.Notices("  spaced  ").Any(notice => notice.Kind == PayloadNoticeKind.SurroundingWhitespace),
            "surrounding whitespace is reported");
        Expect(
            PayloadInspector.Notices("a‮b").Any(notice =>
                notice.Kind == PayloadNoticeKind.BidirectionalOverrides && notice.Count == 1),
            "a direction override is reported");
        Expect(
            PayloadInspector.Notices("ab").Any(notice =>
                notice.Kind == PayloadNoticeKind.ControlCharacters && notice.Count == 1),
            "a control character is reported");
        Expect(PayloadInspector.Notices(Factor).Count == 0, "a plain hexadecimal factor raises nothing");
        ExpectEqual(
            PayloadInspector.DisplayText("ab"),
            "a‹U+0007›b",
            "control characters are made visible in the display copy");
        Expect(
            PayloadInspector.Notices("a​b").Any(notice =>
                notice.Kind == PayloadNoticeKind.InvisibleCharacters && notice.Count == 1),
            "a zero-width character is reported");
    }

    /// <summary>
    /// Walks both language tables and checks that nothing was left blank or
    /// left in the other language.
    /// </summary>
    /// <remarks>
    /// The plain strings are reached through reflection rather than listed
    /// here, so a string added to Strings tomorrow is covered without this test
    /// being touched - which is the only way a completeness check stays true.
    /// </remarks>
    private static void BothLanguagesAreComplete()
    {
        PropertyInfo[] properties = typeof(Strings)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.PropertyType == typeof(string))
            .ToArray();

        Expect(properties.Length > 0, "the string table exposes plain strings");

        foreach (PropertyInfo property in properties)
        {
            var german = (string?)property.GetValue(Strings.German);
            var english = (string?)property.GetValue(Strings.English);
            Expect(!string.IsNullOrWhiteSpace(german), $"German {property.Name} is not blank");
            Expect(!string.IsNullOrWhiteSpace(english), $"English {property.Name} is not blank");

            // Nothing but the app's own name should be identical in both
            // tables; a match anywhere else is a translation never written.
            if (property.Name is not ("WindowTitle" or "CopyButton"))
            {
                Expect(
                    !string.Equals(german, english, StringComparison.Ordinal),
                    $"{property.Name} is the same in both languages - untranslated");
            }
        }

        // The delegates cannot be reached the same way, so they are called.
        (string Label, Func<Strings, string> Render)[] cases =
        [
            ("Confirming", strings => strings.Confirming(3, 8)),
            ("Conflict", strings => strings.Conflict(2)),
            ("AcceptedMatching", strings => strings.AcceptedMatching(2)),
            ("AcceptedRepeated", strings => strings.AcceptedRepeated(8)),
            ("Copied", strings => strings.Copied(90)),
            ("AccessDenied", strings => strings.AccessDenied("a")),
            ("NoticeControlCharacters", strings => strings.NoticeControlCharacters(1)),
            ("NoticeBidirectional", strings => strings.NoticeBidirectional(1)),
            ("NoticeInvisible", strings => strings.NoticeInvisible(1)),
        ];

        foreach ((string label, Func<Strings, string> render) in cases)
        {
            foreach (Language language in Enum.GetValues<Language>())
            {
                Expect(render(Strings.For(language)).Length > 0, $"{label} renders in {language}");
            }
        }

        // The number has to survive into the sentence in both languages, which
        // is the failure a hand-written translation actually makes.
        Expect(Strings.German.Copied(90).Contains("90", StringComparison.Ordinal), "the German clipboard notice states the delay");
        Expect(Strings.English.Copied(90).Contains("90", StringComparison.Ordinal), "the English clipboard notice states the delay");
        Expect(Strings.German.Confirming(3, 8).Contains('3', StringComparison.Ordinal), "the German progress notice states the count");
        Expect(Strings.English.Confirming(3, 8).Contains('8', StringComparison.Ordinal), "the English progress notice states the target");

        ExpectEqual(Enum.GetValues<Language>().Length, 2, "two languages are offered");
        foreach (Language language in Enum.GetValues<Language>())
        {
            Expect(Strings.OwnName(language).Length > 0, $"{language} names itself for the switch");
        }

        // Every outcome has a sentence; a missing one would show the ready text
        // where a conflict should be reported.
        foreach (Language language in Enum.GetValues<Language>())
        {
            Strings strings = Strings.For(language);
            Expect(
                strings.Describe(ScanOutcome.Conflict(["A", "B"])).Contains('2', StringComparison.Ordinal),
                $"{language} reports how many codes disagreed");
            Expect(
                strings.Describe(ScanOutcome.Accepted("X", CorroborationKind.MatchingCodes, 2))
                    != strings.Describe(ScanOutcome.Accepted("X", CorroborationKind.RepeatedReads, 8)),
                $"{language} distinguishes two matching codes from one repeated code");
        }
    }

    /// <summary>
    /// Runs the decoder over a rendered sheet, the way the camera would.
    /// </summary>
    /// <remarks>
    /// Everything above tests the rule in the abstract. This puts two real QR
    /// codes into a real image, decodes them through the same call the frame
    /// handler makes, and checks that the arbiter is handed two separate
    /// detections rather than one - which is the difference between the app's
    /// strongest acceptance and its weakest.
    /// </remarks>
    private static void DecodesRealCodes()
    {
        const int size = 320;
        const int gap = 40;
        int width = (2 * size) + (3 * gap);
        int height = size + (2 * gap);
        byte[] frame = QrImage.RenderPair(Factor, Factor, size, gap, width, height);

        var session = new ScanSession(new SynchronizationContext());
        IReadOnlyList<Detection> detections = session.Decode(frame, width, height);

        Expect(detections.Count == 2, $"both printed codes are decoded from one frame (got {detections.Count})");
        Expect(
            detections.All(detection => string.Equals(detection.Payload, Factor, StringComparison.Ordinal)),
            "both decoded codes carry the printed factor");
        if (detections.Count == 2)
        {
            Expect(
                Math.Abs(detections[0].CenterX - detections[1].CenterX) > 0.02,
                "the two codes are reported at separate positions");
            ExpectAccepted(
                new CodeArbiter().Admit(detections),
                Factor,
                CorroborationKind.MatchingCodes,
                2,
                "a real sheet is accepted as confirmed by two codes");
        }

        // One code destroyed: the decoder returns nothing for it rather than
        // returning damaged content, so the readable one is left on its own.
        byte[] damaged = QrImage.RenderPair(Factor, Factor, size, gap, width, height, destroyLeft: true);
        IReadOnlyList<Detection> single = session.Decode(damaged, width, height);
        Expect(single.Count == 1, $"a destroyed code drops out instead of decoding wrongly (got {single.Count})");
        if (single.Count == 1)
        {
            Expect(
                string.Equals(single[0].Payload, Factor, StringComparison.Ordinal),
                "the surviving code still carries the whole factor");
        }
    }
}
