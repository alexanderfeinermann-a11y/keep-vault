import AVFoundation
import AppKit
import Foundation

// Keep Vault Scanner — reads one printed key-sheet factor from the camera.
//
// The factor is a 512-bit secret. Camera access is therefore confined to this
// helper rather than granted to the app core: the core never gains the ability
// to look through the camera, and this process exists only for the seconds a
// scan takes.
//
// The helper prints exactly one validated factor to standard output and exits.
// It writes no file, touches no pasteboard, logs nothing, and keeps no state.
// Its entitlements are the sandbox and the camera — nothing else, not even file
// access, because it has no reason to read or write anything.

/// A factor is exactly the payload the key sheet encodes: 128 hexadecimal
/// characters. Validating here means a QR code found in the camera's view that
/// happens to contain something else can never be handed to the core.
private let factorLength = 128

private func validFactor(_ payload: String) -> String? {
    let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count == factorLength else {
        return nil
    }

    guard trimmed.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
        return nil
    }

    return trimmed.uppercased()
}

private final class ScanController: NSObject, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private let window: NSWindow
    private var finished = false

    init(title: String) {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 520),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.title = title
        window.center()
        super.init()
    }

    /// Puts the window on screen before the camera is requested.
    ///
    /// macOS attaches the camera prompt to the asking application. A process
    /// with nothing on screen has nothing to attach it to, and the request is
    /// recorded as refused without the user ever being asked.
    func presentWindow() {
        let placeholder = NSView(frame: window.contentLayoutRect)
        placeholder.wantsLayer = true
        placeholder.layer?.backgroundColor = NSColor.black.cgColor
        window.contentView = placeholder
        window.makeKeyAndOrderFront(nil)
    }

    func start() throws {
        guard let device = AVCaptureDevice.default(for: .video) else {
            throw ScannerFailure(message: "Es wurde keine Kamera gefunden.")
        }

        let input = try AVCaptureDeviceInput(device: device)
        guard session.canAddInput(input) else {
            throw ScannerFailure(message: "Die Kamera konnte nicht geoeffnet werden.")
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            throw ScannerFailure(message: "Der QR-Decoder konnte nicht eingerichtet werden.")
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
        guard output.availableMetadataObjectTypes.contains(.qr) else {
            throw ScannerFailure(message: "Diese Kamera unterstuetzt keine QR-Erkennung.")
        }
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        let view = NSView(frame: window.contentLayoutRect)
        view.wantsLayer = true
        preview.frame = view.bounds
        preview.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        view.layer?.addSublayer(preview)
        window.contentView = view
        window.makeKeyAndOrderFront(nil)

        session.startRunning()
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !finished else {
            return
        }

        for object in metadataObjects {
            guard let code = object as? AVMetadataMachineReadableCodeObject,
                  code.type == .qr,
                  let payload = code.stringValue,
                  var factor = validFactor(payload) else {
                continue
            }

            finished = true
            session.stopRunning()
            let delivered = sendFactor(factor, over: replyDescriptor)
            if !delivered {
                FileHandle.standardError.write(Data("Das Ergebnis konnte nicht zurueckgegeben werden.\n".utf8))
            }

            // Overwrite the copy this process holds before it goes away. The
            // value still lives in the pipe and in the core, which locks it;
            // nothing further can be done about the frame buffers the camera
            // stack owns, and a printed sheet in front of a lens is visible by
            // construction.
            factor.withUTF8 { buffer in
                let raw = UnsafeMutableRawPointer(mutating: buffer.baseAddress)
                if let raw {
                    memset_s(raw, buffer.count, 0, buffer.count)
                }
            }

            exit(delivered ? 0 : 5)
        }
    }

    func cancel() {
        session.stopRunning()
        exit(2)
    }
}

private struct ScannerFailure: Error {
    let message: String
}

private final class ApplicationDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var controller: ScanController?
    private let title: String

    init(title: String) {
        self.title = title
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Ask explicitly rather than letting the first capture attempt trigger
        // the prompt, so a refusal is reported cleanly instead of appearing as
        // a camera that never produces frames.
        // Put a window on screen before asking. macOS attaches the camera
        // prompt to the asking application, and an accessory process with
        // nothing visible has nothing to attach it to — the request was
        // recorded as refused without the user ever seeing it.
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)
        controller = ScanController(title: title)
        controller?.presentWindow()

        let statusBefore = describeAuthorization(AVCaptureDevice.authorizationStatus(for: .video))
        AVCaptureDevice.requestAccess(for: .video) { granted in
            DispatchQueue.main.async {
                guard granted else {
                    // Report which of the two very different failures happened.
                    // "Nicht entschieden" means macOS never asked the user and
                    // refused on its own; "verweigert" means an answer is on
                    // record and only the user can change it. Collapsing both
                    // into one message sends people to the wrong remedy.
                    let statusAfter = describeAuthorization(AVCaptureDevice.authorizationStatus(for: .video))
                    reportFailure("Der Kamerazugriff wurde verweigert "
                        + "(Status vorher: \(statusBefore), nachher: \(statusAfter)).")
                    exit(3)
                }

                do {
                    try self.controller?.start()
                } catch let failure as ScannerFailure {
                    reportFailure(failure.message)
                    exit(4)
                } catch {
                    reportFailure("Der Scanner konnte nicht starten: \(error)")
                    exit(4)
                }
            }
        }
    }

    func windowWillClose(_ notification: Notification) {
        controller?.cancel()
    }
}

/// Where the scanned factor is handed back. Set once from the command line
/// before the capture session starts.
private nonisolated(unsafe) var replySocketPath = ""

/// The open connection back to Keep Vault, established before the camera is
/// touched so a failure to reach the caller is reported instead of scanned for.
private nonisolated(unsafe) var replyDescriptor: Int32 = -1

/// Hands the scanned factor back to Keep Vault over a private Unix socket.
///
/// The helper is started through LaunchServices so that macOS treats it as its
/// own application: that is what lets it hold the camera permission under its
/// own name instead of borrowing one it cannot be given. A process launched
/// that way has no pipe back to its caller, so the caller passes the path of a
/// socket it already listens on, inside a directory only this user can enter.
/// The value therefore never reaches the file system.
/// Records a failure where the caller can actually read it.
///
/// Started through LaunchServices, this process has no stderr the caller can
/// see, so a failure would otherwise be silent: the window never appears and
/// Keep Vault waits for a factor that will never arrive. The reason is written
/// beside the reply socket, in the private directory the caller created.
private func reportFailure(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    guard !replySocketPath.isEmpty else { return }
    let directory = (replySocketPath as NSString).deletingLastPathComponent
    let path = (directory as NSString).appendingPathComponent("failure.txt")
    try? message.write(toFile: path, atomically: true, encoding: .utf8)
}

private func connectReply(to path: String) -> Int32 {
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { return -1 }

    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    guard pathBytes.count < capacity else {
        close(descriptor)
        return -1
    }
    withUnsafeMutablePointer(to: &address.sun_path) { destination in
        destination.withMemoryRebound(to: CChar.self, capacity: capacity) { raw in
            for (index, byte) in pathBytes.enumerated() {
                raw[index] = CChar(bitPattern: byte)
            }
            raw[pathBytes.count] = 0
        }
    }

    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
            connect(descriptor, raw, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else {
        close(descriptor)
        return -1
    }
    return descriptor
}

/// Ends the scan when Keep Vault lets go of the connection.
///
/// The helper is opened as an application, so the caller cannot terminate it:
/// the process it started was `open`, which exits immediately. The connection
/// is therefore the link between them. When the user cancels or the scan times
/// out, Keep Vault closes its end, the read below returns end-of-file, and the
/// camera is released instead of staying live behind a window nobody is
/// watching.
private func exitWhenCallerDisconnects(_ descriptor: Int32) {
    DispatchQueue.global(qos: .utility).async {
        var byte: UInt8 = 0
        while true {
            let count = read(descriptor, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            if count <= 0 {
                exit(2)
            }
        }
    }
}

private func sendFactor(_ factor: String, over descriptor: Int32) -> Bool {
    guard descriptor >= 0 else { return false }
    var payload = Array((factor + "\n").utf8)
    defer { memset_s(&payload, payload.count, 0, payload.count) }
    var offset = 0
    while offset < payload.count {
        let written = payload.withUnsafeBytes { buffer in
            write(descriptor, buffer.baseAddress!.advanced(by: offset), payload.count - offset)
        }
        if written <= 0 {
            if errno == EINTR { continue }
            return false
        }
        offset += written
    }
    return true
}

private func describeAuthorization(_ status: AVAuthorizationStatus) -> String {
    switch status {
    case .notDetermined: return "nicht entschieden"
    case .restricted: return "durch Richtlinie gesperrt"
    case .denied: return "verweigert"
    case .authorized: return "erlaubt"
    @unknown default: return "unbekannt"
    }
}

@main
private enum KeepVaultScanner {
    static func main() {
        let arguments = CommandLine.arguments
        // Find the verb rather than trusting its position. LaunchServices may
        // insert its own arguments, such as the -psn_ process serial number,
        // ahead of the ones the caller passed, and a fixed index turns that
        // into an immediate exit with no visible cause.
        guard let verb = arguments.firstIndex(of: "scan-factor"),
              arguments.count >= verb + 3 else {
            FileHandle.standardError.write(Data("Usage: scan-factor <title> <reply-socket>\n".utf8))
            exit(64)
        }

        let socketPath = arguments[verb + 2]
        guard socketPath.hasPrefix("/"), socketPath.count < 104 else {
            FileHandle.standardError.write(Data("Ungueltiger Rueckgabepfad.\n".utf8))
            exit(64)
        }
        replySocketPath = socketPath

        let rawTitle = arguments[verb + 1]
        guard rawTitle.count <= 256,
              !rawTitle.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
            FileHandle.standardError.write(Data("Ungueltiger Fenstertitel.\n".utf8))
            exit(64)
        }

        replyDescriptor = connectReply(to: socketPath)
        guard replyDescriptor >= 0 else {
            reportFailure("Die Verbindung zu Keep Vault kam nicht zustande.")
            exit(5)
        }
        exitWhenCallerDisconnects(replyDescriptor)

        let application = NSApplication.shared
        let delegate = ApplicationDelegate(title: rawTitle)
        application.delegate = delegate
        application.setActivationPolicy(.accessory)
        application.activate(ignoringOtherApps: true)
        application.run()
    }
}
