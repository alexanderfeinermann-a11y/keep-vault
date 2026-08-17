import AppKit
import Foundation

// QR-Scanner — reads a QR code through the webcam and shows its content.
//
// A normal double-clickable app: one window, one camera, one result. It is
// sandboxed and declares exactly one capability, the camera. It has no file
// access at all, because it has nothing to read and nothing to write.
//
// The scanned value exists in this process's memory and, if the user asks for
// it, on the pasteboard for ninety seconds. It is never written to a file.

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate {
    private var controller: MainWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.regular)
        installMenu()
        controller = MainWindowController()
        controller?.show()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(installMenu),
            name: .languageChanged,
            object: nil)
    }

    /// Refuses state restoration at the application level as well as the window
    /// level. This is the switch that decides whether AppKit may write the
    /// app's interface state — which here would include the scanned value — to
    /// ~/Library/Saved Application State between launches.
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// A minimal menu bar, present so the standard shortcuts exist at all.
    ///
    /// Without an application menu ⌘Q does not work and ⌘C never reaches the
    /// selected text in the result field, which for this app would be an odd
    /// omission.
    @objc private func installMenu() {
        let strings = Localization.shared.strings
        let mainMenu = NSMenu()

        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: strings.menuAbout, action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: strings.menuHide, action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: strings.menuQuit, action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        mainMenu.addItem(appItem)

        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: strings.menuEdit)
        editMenu.addItem(withTitle: strings.menuCopy, action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: strings.menuSelectAll, action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        mainMenu.addItem(editItem)

        NSApplication.shared.mainMenu = mainMenu
    }
}

@main
private enum QrScannerApp {
    @MainActor
    static func main() {
        let application = NSApplication.shared
        // NSApplication holds its delegate weakly, so this local is what keeps
        // it alive. run() does not return until the app terminates, so the
        // local outlives everything that uses it.
        let delegate = AppDelegate()
        application.delegate = delegate
        application.run()
    }
}
