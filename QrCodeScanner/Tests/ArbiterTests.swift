import CoreGraphics
import Foundation

// Checks the rule this app exists for: which of two printed QR codes is taken.
//
// No test framework, because the build has no package manager and this needs
// none: it runs as part of the build and fails it on the first wrong answer.

private var failures = 0
private var checks = 0

private func expect(
    _ condition: Bool,
    _ description: String,
    file: StaticString = #file,
    line: UInt = #line
) {
    checks += 1
    if !condition {
        failures += 1
        FileHandle.standardError.write(Data("FAIL \(description) (line \(line))\n".utf8))
    }
}

private func expectEqual<T: Equatable>(
    _ actual: T,
    _ expected: T,
    _ description: String,
    line: UInt = #line
) {
    checks += 1
    if actual != expected {
        failures += 1
        FileHandle.standardError.write(
            Data("FAIL \(description): expected \(expected), got \(actual) (line \(line))\n".utf8))
    }
}

/// Two codes side by side, as they are printed on a sheet.
private func pair(_ left: String, _ right: String) -> [Detection] {
    [
        Detection(payload: left, center: CGPoint(x: 0.3, y: 0.5)),
        Detection(payload: right, center: CGPoint(x: 0.7, y: 0.5)),
    ]
}

private func single(_ payload: String) -> [Detection] {
    [Detection(payload: payload, center: CGPoint(x: 0.5, y: 0.5))]
}

private let factor = String(repeating: "A1B2C3D4", count: 16)

@main
private enum ArbiterTests {
    static func main() {
        bothCodesReadableIsAcceptedImmediately()
        oneDamagedCodeFallsBackToTheReadableOne()
        aLoneCodeIsNotAcceptedOnItsFirstSighting()
        disagreeingCodesAreRefused()
        aDuplicateReportIsNotASecondCode()
        flickerDoesNotResetTheTally()
        aChangedPayloadRestartsTheTally()
        payloadInspection()
        bothLanguagesAreComplete()

        if failures == 0 {
            print("ArbiterTests: \(checks) checks passed")
            exit(0)
        }
        FileHandle.standardError.write(Data("ArbiterTests: \(failures) of \(checks) checks failed\n".utf8))
        exit(1)
    }

    /// Both printed codes decode. They agree, so the payload is taken at once —
    /// no repeat count needed, because a second printed copy is better evidence
    /// than the same code read twice.
    static func bothCodesReadableIsAcceptedImmediately() {
        var arbiter = CodeArbiter()
        let outcome = arbiter.admit(pair(factor, factor))
        expectEqual(
            outcome,
            .accepted(payload: factor, corroboration: .matchingCodes(count: 2)),
            "two matching codes are accepted on the first frame")
    }

    /// The user's case: one code is creased or stained, so it never decodes and
    /// never reaches the arbiter. The readable one carries the content.
    static func oneDamagedCodeFallsBackToTheReadableOne() {
        var arbiter = CodeArbiter(requiredRepeats: 3)
        var outcome = arbiter.admit(single(factor))
        expectEqual(outcome, .confirming(progress: 1, required: 3), "first read of a lone code confirms once")
        outcome = arbiter.admit(single(factor))
        expectEqual(outcome, .confirming(progress: 2, required: 3), "second read of a lone code confirms twice")
        outcome = arbiter.admit(single(factor))
        expectEqual(
            outcome,
            .accepted(payload: factor, corroboration: .repeatedReads(count: 3)),
            "a lone code is accepted once it has repeated itself")
    }

    static func aLoneCodeIsNotAcceptedOnItsFirstSighting() {
        var arbiter = CodeArbiter(requiredRepeats: 8)
        for step in 1 ..< 8 {
            let outcome = arbiter.admit(single(factor))
            expectEqual(
                outcome,
                .confirming(progress: step, required: 8),
                "a lone code is still unconfirmed after \(step) frames")
        }
    }

    /// Two codes that decode to different content cannot both be the sheet's
    /// factor. Nothing is accepted and the disagreement is reported.
    static func disagreeingCodesAreRefused() {
        var arbiter = CodeArbiter()
        let outcome = arbiter.admit(pair("ALPHA", "BETA"))
        expectEqual(outcome, .conflict(payloads: ["ALPHA", "BETA"]), "disagreeing codes are refused")

        // The conflict must also clear whatever was being counted, so a payload
        // half-way to acceptance cannot be completed after a second code has
        // contradicted it.
        var counting = CodeArbiter(requiredRepeats: 2)
        _ = counting.admit(single("ALPHA"))
        _ = counting.admit(pair("ALPHA", "BETA"))
        let after = counting.admit(single("ALPHA"))
        expectEqual(after, .confirming(progress: 1, required: 2), "a conflict restarts the tally")
    }

    /// The same physical code reported twice in one frame must not be mistaken
    /// for two printed copies; otherwise the strongest acceptance the app
    /// offers would rest on a duplicate report.
    static func aDuplicateReportIsNotASecondCode() {
        var arbiter = CodeArbiter(requiredRepeats: 4)
        let overlapping = [
            Detection(payload: factor, center: CGPoint(x: 0.500, y: 0.500)),
            Detection(payload: factor, center: CGPoint(x: 0.505, y: 0.502)),
        ]
        let outcome = arbiter.admit(overlapping)
        expectEqual(
            outcome,
            .confirming(progress: 1, required: 4),
            "two reports of one code are not treated as two codes")
    }

    /// Detection drops out between frames. A single missing frame must not
    /// throw away a tally, or a lone code would never reach the repeat count.
    static func flickerDoesNotResetTheTally() {
        var arbiter = CodeArbiter(requiredRepeats: 3, toleratedMisses: 2)
        _ = arbiter.admit(single(factor))
        _ = arbiter.admit([])
        _ = arbiter.admit(single(factor))
        let outcome = arbiter.admit(single(factor))
        expectEqual(
            outcome,
            .accepted(payload: factor, corroboration: .repeatedReads(count: 3)),
            "a dropped frame does not discard the tally")

        var patient = CodeArbiter(requiredRepeats: 3, toleratedMisses: 2)
        _ = patient.admit(single(factor))
        _ = patient.admit([])
        _ = patient.admit([])
        _ = patient.admit([])
        let restarted = patient.admit(single(factor))
        expectEqual(
            restarted,
            .confirming(progress: 1, required: 3),
            "a code out of view long enough starts over")
    }

    static func aChangedPayloadRestartsTheTally() {
        var arbiter = CodeArbiter(requiredRepeats: 3)
        _ = arbiter.admit(single("ALPHA"))
        _ = arbiter.admit(single("ALPHA"))
        let outcome = arbiter.admit(single("BETA"))
        expectEqual(
            outcome,
            .confirming(progress: 1, required: 3),
            "a different payload starts its own tally")
    }

    static func payloadInspection() {
        expect(PayloadInspector.accept("") == nil, "an empty payload is rejected")
        expect(
            PayloadInspector.accept(String(repeating: "x", count: PayloadInspector.maximumLength + 1)) == nil,
            "an oversized payload is rejected")
        expectEqual(PayloadInspector.accept(factor), factor, "a normal payload passes through unchanged")

        // Nothing is trimmed: the copy button must hand over exactly what the
        // code contained, so padding is reported rather than removed.
        expectEqual(PayloadInspector.accept("  spaced  "), "  spaced  ", "whitespace is preserved, not trimmed")
        expect(
            PayloadInspector.notices(for: "  spaced  ").contains(.surroundingWhitespace),
            "surrounding whitespace is reported")
        expect(
            PayloadInspector.notices(for: "a\u{202E}b").contains(.bidirectionalOverrides(count: 1)),
            "a direction override is reported")
        expect(
            PayloadInspector.notices(for: "a\u{0007}b").contains(.controlCharacters(count: 1)),
            "a control character is reported")
        expect(
            PayloadInspector.notices(for: factor).isEmpty,
            "a plain hexadecimal factor raises nothing")
        expectEqual(
            PayloadInspector.displayText(for: "a\u{0007}b"),
            "a‹U+0007›b",
            "control characters are made visible in the display copy")
    }

    /// Walks both language tables and checks that nothing was left blank or
    /// left in the other language.
    ///
    /// The plain strings are reached through Mirror rather than listed here, so
    /// a string added to Strings tomorrow is covered without this test being
    /// touched — which is the only way a completeness check stays true.
    static func bothLanguagesAreComplete() {
        let german = Mirror(reflecting: Strings.german)
        let english = Mirror(reflecting: Strings.english)

        var germanPlain: [String: String] = [:]
        var englishPlain: [String: String] = [:]
        for child in german.children {
            if let label = child.label, let value = child.value as? String {
                germanPlain[label] = value
            }
        }
        for child in english.children {
            if let label = child.label, let value = child.value as? String {
                englishPlain[label] = value
            }
        }

        expect(!germanPlain.isEmpty, "the German table exposes plain strings")
        expectEqual(germanPlain.count, englishPlain.count, "both tables carry the same plain strings")

        for (label, value) in germanPlain {
            expect(!value.trimmingCharacters(in: .whitespaces).isEmpty, "German \(label) is not blank")
            guard let counterpart = englishPlain[label] else {
                expect(false, "English is missing \(label)")
                continue
            }
            expect(!counterpart.trimmingCharacters(in: .whitespaces).isEmpty, "English \(label) is not blank")
        }

        // Nothing but the app's own name should be identical in both tables; a
        // match anywhere else is a translation that was never written.
        for (label, value) in germanPlain where label != "menuCopy" {
            if let counterpart = englishPlain[label], counterpart == value {
                expect(false, "\(label) is the same in both languages — untranslated")
            }
        }

        // The closures cannot be reached through Mirror, so they are called.
        let cases: [(String, (Strings) -> String)] = [
            ("confirming", { $0.confirming(3, 8) }),
            ("conflict", { $0.conflict(2) }),
            ("acceptedMatching", { $0.acceptedMatching(2) }),
            ("acceptedRepeated", { $0.acceptedRepeated(8) }),
            ("copied", { $0.copied(90) }),
            ("accessDenied", { $0.accessDenied("a", "b") }),
            ("noticeControlCharacters", { $0.noticeControlCharacters(1) }),
            ("noticeBidirectional", { $0.noticeBidirectional(1) }),
            ("noticeInvisible", { $0.noticeInvisible(1) }),
        ]
        for (label, render) in cases {
            for language in Language.allCases {
                let rendered = render(language.strings)
                expect(!rendered.isEmpty, "\(label) renders in \(language.rawValue)")
            }
        }

        // The number has to survive into the sentence in both languages, which
        // is the failure a hand-written translation actually makes.
        expect(Strings.german.copied(90).contains("90"), "the German clipboard notice states the delay")
        expect(Strings.english.copied(90).contains("90"), "the English clipboard notice states the delay")
        expect(Strings.german.confirming(3, 8).contains("3"), "the German progress notice states the count")
        expect(Strings.english.confirming(3, 8).contains("8"), "the English progress notice states the target")

        expectEqual(Language.allCases.count, 2, "two languages are offered")
        for language in Language.allCases {
            expect(!language.ownName.isEmpty, "\(language.rawValue) names itself for the switch")
        }
    }
}
