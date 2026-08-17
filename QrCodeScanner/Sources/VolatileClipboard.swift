import AppKit
import Foundation

// The copy button, and the one place a scanned value leaves this process.
//
// Everything else here is arranged so the payload never reaches storage. The
// pasteboard is the exception that cannot be argued away: it is owned by
// pbcopy's server, not by this app, and that server may persist its contents
// and — with Universal Clipboard — hand them to the user's other devices. No
// entitlement or sandbox setting available to an app changes that.
//
// What can be done is done. The item is marked with the concealed type that
// clipboard managers honour, so the well-behaved ones do not record it in their
// history; it is cleared again after a short delay; and the delay is stated in
// the interface rather than left as a surprise. What cannot be done is claimed
// nowhere: see README.md, "Was diese App nicht verhindern kann".

@MainActor
final class VolatileClipboard {
    /// The de-facto marker clipboard managers watch for. A pasteboard item
    /// carrying it is meant to be passed along but not written into a history.
    /// Password managers have used it for years; it is a convention, not an
    /// enforcement, which is why the clearing timer exists as well.
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    /// Long enough to switch windows and paste, short enough that the value is
    /// not still sitting there hours later.
    let lifetime: TimeInterval

    private var expiry: Timer?
    private var changeCountAtCopy: Int?
    private var onExpiry: (() -> Void)?

    init(lifetime: TimeInterval = 90) {
        self.lifetime = lifetime
    }

    /// Puts the payload on the pasteboard and schedules its removal.
    ///
    /// - Parameter onExpiry: run when the value is cleared, so the interface can
    ///   stop telling the user it is available to paste.
    func copy(_ payload: String, onExpiry: @escaping () -> Void) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.declareTypes([.string, Self.concealedType], owner: nil)
        pasteboard.setString(payload, forType: .string)
        pasteboard.setString(payload, forType: Self.concealedType)

        changeCountAtCopy = pasteboard.changeCount
        self.onExpiry = onExpiry

        expiry?.invalidate()
        expiry = Timer.scheduledTimer(withTimeInterval: lifetime, repeats: false) { [weak self] _ in
            Task { @MainActor in
                self?.clearIfStillOurs()
            }
        }
    }

    /// Removes the value, but only if it is still the one this app put there.
    ///
    /// The user may well have copied something else in the meantime, and
    /// wiping their current clipboard because a scan expired would be its own
    /// small disaster. The change count is what tells the two cases apart.
    func clearIfStillOurs() {
        defer {
            expiry?.invalidate()
            expiry = nil
            changeCountAtCopy = nil
        }

        guard let stamp = changeCountAtCopy, NSPasteboard.general.changeCount == stamp else {
            onExpiry?()
            onExpiry = nil
            return
        }

        NSPasteboard.general.clearContents()
        onExpiry?()
        onExpiry = nil
    }

    deinit {
        expiry?.invalidate()
    }
}
