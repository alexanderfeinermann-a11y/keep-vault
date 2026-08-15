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
            FileHandle.standardOutput.write(Data((factor + "\n").utf8))

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

            exit(0)
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
        AVCaptureDevice.requestAccess(for: .video) { granted in
            DispatchQueue.main.async {
                guard granted else {
                    FileHandle.standardError.write(Data("Der Kamerazugriff wurde verweigert.\n".utf8))
                    exit(3)
                }

                do {
                    let controller = ScanController(title: self.title)
                    self.controller = controller
                    try controller.start()
                } catch let failure as ScannerFailure {
                    FileHandle.standardError.write(Data((failure.message + "\n").utf8))
                    exit(4)
                } catch {
                    FileHandle.standardError.write(Data(("Der Scanner konnte nicht starten: \(error)\n").utf8))
                    exit(4)
                }
            }
        }
    }

    func windowWillClose(_ notification: Notification) {
        controller?.cancel()
    }
}

@main
private enum KeepVaultScanner {
    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count >= 2, arguments[1] == "scan-factor" else {
            FileHandle.standardError.write(Data("Usage: scan-factor <title>\n".utf8))
            exit(64)
        }

        let rawTitle = arguments.count > 2 ? arguments[2] : "QR-Code scannen"
        guard rawTitle.count <= 256,
              !rawTitle.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
            FileHandle.standardError.write(Data("Ungueltiger Fenstertitel.\n".utf8))
            exit(64)
        }

        let application = NSApplication.shared
        let delegate = ApplicationDelegate(title: rawTitle)
        application.delegate = delegate
        application.setActivationPolicy(.accessory)
        application.activate(ignoringOtherApps: true)
        application.run()
    }
}
