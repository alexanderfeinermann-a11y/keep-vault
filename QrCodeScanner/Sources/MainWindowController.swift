import AVFoundation
import AppKit
import Foundation

// The window: camera on top, result below, the two buttons that act on it, and
// the language switch.
//
// Several settings here exist only to keep the scanned value off the disk, and
// they are not the ones an interface normally needs. AppKit writes a good deal
// to storage on an app's behalf — window state, learned spellings, find-panel
// history — and every one of those paths would carry the payload with it. They
// are switched off individually because there is no single switch for them.

@MainActor
final class MainWindowController: NSObject, NSWindowDelegate, ScanSessionDelegate {
    /// What the status line is currently saying, kept as a case rather than as
    /// finished text. Switching language has to re-render whatever is already
    /// on screen, and a stored sentence cannot be translated after the fact.
    private enum Status {
        case requestingCamera
        case ready
        case confirming(progress: Int, required: Int)
        case conflict(count: Int)
        case acceptedMatching(count: Int)
        case acceptedRepeated(count: Int)
        case copied(seconds: Int)
        case clipboardCleared
        case failed(ScannerFailure)

        func text(_ strings: Strings) -> String {
            switch self {
            case .requestingCamera: return strings.requestingCamera
            case .ready: return strings.ready
            case .confirming(let progress, let required): return strings.confirming(progress, required)
            case .conflict(let count): return strings.conflict(count)
            case .acceptedMatching(let count): return strings.acceptedMatching(count)
            case .acceptedRepeated(let count): return strings.acceptedRepeated(count)
            case .copied(let seconds): return strings.copied(seconds)
            case .clipboardCleared: return strings.clipboardCleared
            case .failed(let failure): return failure.message(strings)
            }
        }

        var tone: Tone {
            switch self {
            case .requestingCamera, .ready, .confirming, .clipboardCleared: return .neutral
            case .acceptedMatching, .acceptedRepeated, .copied: return .good
            case .conflict: return .warning
            case .failed: return .bad
            }
        }
    }

    private enum Tone {
        case neutral, good, warning, bad

        var color: NSColor {
            switch self {
            case .neutral: return .secondaryLabelColor
            case .good: return .systemGreen
            case .warning: return .systemOrange
            case .bad: return .systemRed
            }
        }
    }

    private let window: NSWindow
    private let session = ScanSession()
    private let clipboard = VolatileClipboard()

    private let previewView = NSView()
    private let statusLabel = NSTextField(labelWithString: "")
    private let noticeLabel = NSTextField(labelWithString: "")
    private let languageLabel = NSTextField(labelWithString: "")
    private let languageControl = NSSegmentedControl()
    private let resultView = NSTextView()
    private let resultScroll = NSScrollView()
    private let copyButton = NSButton()
    private let rescanButton = NSButton()

    /// The scanned value, held here and nowhere else.
    private var payload: String?

    private var status: Status = .requestingCamera
    private var notices: [PayloadNotice] = []

    private var strings: Strings { Localization.shared.strings }

    override init() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 800),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "QR-Scanner"
        window.center()
        // An autosave name would put the window frame into the defaults. The
        // language is the only thing this app is allowed to remember.
        window.setFrameAutosaveName("")

        // AppKit otherwise writes the window's contents into
        // ~/Library/Saved Application State so it can restore them at the next
        // launch. For this app that file would be a copy of the scanned value.
        window.isRestorable = false

        super.init()
        window.delegate = self
        buildInterface()
        applyLanguage()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applyLanguage),
            name: .languageChanged,
            object: nil)
    }

    func show() {
        // The window goes up before the camera is requested. macOS attaches the
        // permission prompt to the asking application, and a process with
        // nothing on screen has nothing to attach it to — the request is then
        // recorded as refused without the user ever being asked.
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)

        session.delegate = self
        previewView.layer?.addSublayer(session.previewLayer)
        session.previewLayer.frame = previewView.bounds
        setStatus(.requestingCamera)
        session.requestAccessAndStart()
    }

    // MARK: - Interface

    private func buildInterface() {
        let content = NSView()
        window.contentView = content

        previewView.wantsLayer = true
        previewView.layer?.backgroundColor = NSColor.black.cgColor
        previewView.layer?.cornerRadius = 8
        previewView.layer?.masksToBounds = true
        previewView.postsFrameChangedNotifications = true
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(previewFrameChanged),
            name: NSView.frameDidChangeNotification,
            object: previewView)

        statusLabel.font = .systemFont(ofSize: 13, weight: .medium)
        statusLabel.lineBreakMode = .byWordWrapping
        statusLabel.maximumNumberOfLines = 2

        noticeLabel.font = .systemFont(ofSize: 11)
        noticeLabel.textColor = .systemOrange
        noticeLabel.lineBreakMode = .byWordWrapping
        noticeLabel.maximumNumberOfLines = 4

        configureResultView()

        copyButton.bezelStyle = .rounded
        copyButton.keyEquivalent = "\r"
        copyButton.target = self
        copyButton.action = #selector(copyPayload)
        copyButton.isEnabled = false

        rescanButton.bezelStyle = .rounded
        rescanButton.target = self
        rescanButton.action = #selector(rescan)
        rescanButton.isEnabled = false

        languageLabel.font = .systemFont(ofSize: 11)
        languageLabel.textColor = .secondaryLabelColor

        languageControl.segmentCount = Language.allCases.count
        languageControl.segmentStyle = .rounded
        languageControl.trackingMode = .selectOne
        for (index, language) in Language.allCases.enumerated() {
            languageControl.setLabel(language.ownName, forSegment: index)
            languageControl.setWidth(84, forSegment: index)
        }
        languageControl.target = self
        languageControl.action = #selector(languageChanged)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow - 1, for: .horizontal)

        let buttons = NSStackView(views: [copyButton, rescanButton, spacer, languageLabel, languageControl])
        buttons.orientation = .horizontal
        buttons.spacing = 10
        buttons.alignment = .centerY

        let stack = NSStackView(views: [previewView, statusLabel, resultScroll, noticeLabel, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            stack.topAnchor.constraint(equalTo: content.topAnchor),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor),

            previewView.leadingAnchor.constraint(equalTo: stack.leadingAnchor, constant: 16),
            previewView.trailingAnchor.constraint(equalTo: stack.trailingAnchor, constant: -16),
            previewView.heightAnchor.constraint(equalToConstant: 430),

            resultScroll.leadingAnchor.constraint(equalTo: stack.leadingAnchor, constant: 16),
            resultScroll.trailingAnchor.constraint(equalTo: stack.trailingAnchor, constant: -16),
            resultScroll.heightAnchor.constraint(equalToConstant: 120),

            buttons.leadingAnchor.constraint(equalTo: stack.leadingAnchor, constant: 16),
            buttons.trailingAnchor.constraint(equalTo: stack.trailingAnchor, constant: -16),

            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: stack.trailingAnchor, constant: -16),
            noticeLabel.trailingAnchor.constraint(lessThanOrEqualTo: stack.trailingAnchor, constant: -16),
        ])
    }

    private func configureResultView() {
        resultScroll.hasVerticalScroller = true
        resultScroll.borderType = .bezelBorder
        resultScroll.documentView = resultView
        resultScroll.drawsBackground = true

        resultView.isEditable = false
        resultView.isSelectable = true
        resultView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        resultView.textContainerInset = NSSize(width: 6, height: 6)
        resultView.autoresizingMask = [.width]
        resultView.isVerticallyResizable = true

        // Every one of these has a path to storage. The spelling checker learns
        // words into the user's dictionary, the substitution engines consult
        // and update their own state, the find panel keeps a search history in
        // the defaults, and the data detectors hand text to other services.
        // None of them are wanted for a value that is only ever displayed.
        resultView.isContinuousSpellCheckingEnabled = false
        resultView.isAutomaticSpellingCorrectionEnabled = false
        resultView.isGrammarCheckingEnabled = false
        resultView.isAutomaticQuoteSubstitutionEnabled = false
        resultView.isAutomaticDashSubstitutionEnabled = false
        resultView.isAutomaticTextReplacementEnabled = false
        resultView.isAutomaticDataDetectionEnabled = false
        resultView.isAutomaticLinkDetectionEnabled = false
        resultView.usesFindPanel = false
        resultView.usesFontPanel = false
        resultView.allowsUndo = false
    }

    @objc private func previewFrameChanged() {
        // The preview layer is not in the Auto Layout tree, so it is resized by
        // hand. Without this the picture keeps the size the window had when it
        // opened.
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        session.previewLayer.frame = previewView.bounds
        CATransaction.commit()
    }

    /// Re-renders every visible string, including whatever the status line and
    /// the notices are already saying.
    @objc private func applyLanguage() {
        let strings = self.strings
        copyButton.title = strings.copyButton
        rescanButton.title = strings.rescanButton
        languageLabel.stringValue = strings.languageLabel
        if let index = Language.allCases.firstIndex(of: Localization.shared.language) {
            languageControl.selectedSegment = index
        }
        statusLabel.stringValue = status.text(strings)
        statusLabel.textColor = status.tone.color
        noticeLabel.stringValue = notices.map { $0.message(strings) }.joined(separator: " ")
    }

    // MARK: - Actions

    @objc private func languageChanged() {
        let index = languageControl.selectedSegment
        guard index >= 0, index < Language.allCases.count else { return }
        Localization.shared.select(Language.allCases[index])
    }

    @objc private func copyPayload() {
        guard let payload else { return }
        clipboard.copy(payload) { [weak self] in
            self?.setStatus(.clipboardCleared)
        }
        setStatus(.copied(seconds: Int(clipboard.lifetime)))
    }

    @objc private func rescan() {
        payload = nil
        resultView.string = ""
        notices = []
        copyButton.isEnabled = false
        rescanButton.isEnabled = false
        setStatus(.ready)
        session.resume()
    }

    private func setStatus(_ status: Status) {
        self.status = status
        statusLabel.stringValue = status.text(strings)
        statusLabel.textColor = status.tone.color
    }

    // MARK: - ScanSessionDelegate

    func scanSession(_ session: ScanSession, didObserve outcome: ScanOutcome) {
        switch outcome {
        case .searching:
            guard payload == nil else { return }
            setStatus(.ready)

        case .confirming(let progress, let required):
            guard payload == nil else { return }
            setStatus(.confirming(progress: progress, required: required))

        case .conflict(let payloads):
            guard payload == nil else { return }
            // Two codes that disagree are never both right. On a key sheet the
            // two codes are meant to be identical, so this means the wrong
            // sheet or a second sheet is in view; anywhere else it means the
            // camera can see more than one code and cannot know which is meant.
            setStatus(.conflict(count: payloads.count))

        case .accepted(let value, let corroboration):
            present(value, corroboration: corroboration)
        }
    }

    func scanSession(_ session: ScanSession, didFailWith failure: ScannerFailure) {
        setStatus(.failed(failure))
        if case .accessDenied = failure {
            noticeLabel.stringValue = strings.cameraDeniedHint
        }
    }

    private func present(_ value: String, corroboration: Corroboration) {
        payload = value
        resultView.string = PayloadInspector.displayText(for: value)
        copyButton.isEnabled = true
        rescanButton.isEnabled = true

        switch corroboration {
        case .matchingCodes(let count):
            setStatus(.acceptedMatching(count: count))
        case .repeatedReads(let count):
            setStatus(.acceptedRepeated(count: count))
        }

        notices = PayloadInspector.notices(for: value)
        noticeLabel.stringValue = notices.map { $0.message(strings) }.joined(separator: " ")
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        // Release the camera before the process goes, so the indicator light
        // going out matches the window disappearing.
        session.stop()
        clipboard.clearIfStillOurs()
        NSApplication.shared.terminate(nil)
    }
}
