// AVFoundation predates Swift's concurrency annotations, so its types are not
// marked Sendable even where the documentation says they may be used across
// queues. AVCaptureSession.startRunning() and stopRunning() are exactly that
// case: both block, and both are meant to be called off the main queue.
@preconcurrency import AVFoundation
import AppKit
import Foundation
import Vision

// The camera half of the app: opens a capture session, decodes every QR code
// in each frame, and reports only what the arbiter accepts.
//
// Detection is done by Vision, not by AVCaptureMetadataOutput.
//
// That is not a preference. AVCaptureMetadataOutput reads machine-readable
// codes on iOS only; on macOS the same class offers face metadata and nothing
// else, so .qr never appears among its available types and it silently never
// reports a code. It is an easy mistake to make, because the class exists on
// macOS, compiles against .qr, and simply never fires.
//
// Vision's barcode request works on macOS and gives what the arbiter needs
// anyway: every code in the frame, each with its own payload and its own
// position, so two printed codes can be told apart from one code seen twice.

enum ScannerFailure: Error, Equatable {
    case noCamera
    case cameraUnavailable
    case decoderUnavailable

    /// The authorization status before and after asking, as raw values rather
    /// than finished sentences, so the message can be rebuilt in the other
    /// language when the user switches.
    case accessDenied(before: AVAuthorizationStatus, after: AVAuthorizationStatus)

    func message(_ strings: Strings) -> String {
        switch self {
        case .noCamera:
            return strings.noCamera
        case .cameraUnavailable:
            return strings.cameraUnavailable
        case .decoderUnavailable:
            return strings.decoderUnavailable
        case .accessDenied(let before, let after):
            // Which of the two very different refusals happened decides what the
            // user has to do about it. "Not determined" means macOS never asked;
            // "denied" means an answer is on record and only System Settings can
            // change it.
            return strings.accessDenied(Self.describe(before, strings), Self.describe(after, strings))
        }
    }

    private static func describe(_ status: AVAuthorizationStatus, _ strings: Strings) -> String {
        switch status {
        case .notDetermined: return strings.statusNotDetermined
        case .restricted: return strings.statusRestricted
        case .denied: return strings.statusDenied
        case .authorized: return strings.statusAuthorized
        @unknown default: return strings.statusUnknown
        }
    }
}

@MainActor
protocol ScanSessionDelegate: AnyObject {
    func scanSession(_ session: ScanSession, didObserve outcome: ScanOutcome)
    func scanSession(_ session: ScanSession, didFailWith failure: ScannerFailure)
}

@MainActor
final class ScanSession: NSObject {
    weak var delegate: ScanSessionDelegate?

    let previewLayer: AVCaptureVideoPreviewLayer

    private let session = AVCaptureSession()
    private let output = AVCaptureVideoDataOutput()
    private let captureQueue = DispatchQueue(label: "de.michael-feinermann.qr-scanner.capture")
    private var arbiter = CodeArbiter()
    private var isSuspended = true

    /// Read and written only on `captureQueue`, which is serial, so no lock is
    /// needed. It exists to stop the frame work early while a result is on
    /// screen; the main-actor check in `handle` is what actually decides
    /// whether an outcome is delivered.
    private nonisolated(unsafe) var isPausedOnCaptureQueue = true

    /// When the last frame was handed to Vision, on the capture clock.
    /// Capture-queue only, like the pause flag.
    private nonisolated(unsafe) var lastDecodedAt: CMTime = .invalid

    /// Decoding every frame of 1080p video keeps a core busy for as long as the
    /// user is hunting for the right distance, and buys nothing: a sheet held
    /// in front of a camera does not change meaningfully between one frame and
    /// the next. At this rate the arbiter's eight confirmations still take
    /// about half a second.
    private nonisolated static let decodesPerSecond = 15.0

    private nonisolated let request: VNDetectBarcodesRequest = {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        return request
    }()

    override init() {
        previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.videoGravity = .resizeAspectFill
        super.init()
    }

    /// Asks for the camera explicitly rather than letting the first capture
    /// attempt trigger the prompt, so a refusal is reported as a refusal
    /// instead of appearing as a camera that never produces a picture.
    func requestAccessAndStart() {
        let before = AVCaptureDevice.authorizationStatus(for: .video)
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            Task { @MainActor in
                guard let self else { return }
                guard granted else {
                    let after = AVCaptureDevice.authorizationStatus(for: .video)
                    self.delegate?.scanSession(self, didFailWith: .accessDenied(before: before, after: after))
                    return
                }
                do {
                    try self.start()
                } catch let failure as ScannerFailure {
                    self.delegate?.scanSession(self, didFailWith: failure)
                } catch {
                    self.delegate?.scanSession(self, didFailWith: .cameraUnavailable)
                }
            }
        }
    }

    private func start() throws {
        guard session.inputs.isEmpty else {
            resume()
            return
        }

        guard let device = AVCaptureDevice.default(for: .video) else {
            throw ScannerFailure.noCamera
        }

        guard let input = try? AVCaptureDeviceInput(device: device) else {
            throw ScannerFailure.cameraUnavailable
        }

        session.beginConfiguration()
        guard session.canAddInput(input) else {
            session.commitConfiguration()
            throw ScannerFailure.cameraUnavailable
        }
        session.addInput(input)

        guard session.canAddOutput(output) else {
            session.commitConfiguration()
            throw ScannerFailure.decoderUnavailable
        }
        output.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        // A frame that arrives while the previous one is still being decoded is
        // dropped rather than queued. The alternative is a backlog that grows
        // for as long as decoding is slower than capture, which shows up as a
        // scanner that reacts to what the sheet looked like a second ago.
        output.alwaysDiscardsLateVideoFrames = true
        output.setSampleBufferDelegate(self, queue: captureQueue)
        session.addOutput(output)
        session.commitConfiguration()

        resume()
        delegate?.scanSession(self, didObserve: .searching)
    }

    /// Stops looking without tearing the session down.
    ///
    /// Called as soon as a payload is accepted. The camera stays open but the
    /// app stops reading, so a result on screen cannot be replaced by whatever
    /// drifts through the frame next while the user is reaching for the copy
    /// button.
    func suspend() {
        isSuspended = true
        arbiter.reset()
        captureQueue.async { self.isPausedOnCaptureQueue = true }
    }

    func resume() {
        arbiter.reset()
        isSuspended = false
        captureQueue.async { self.isPausedOnCaptureQueue = false }
        startRunning()
    }

    /// Releases the camera. The indicator light going out is the only honest
    /// signal that the app has stopped watching, so this runs whenever the
    /// window closes rather than being left to process exit.
    func stop() {
        isSuspended = true
        captureQueue.async { self.isPausedOnCaptureQueue = true }
        guard session.isRunning else { return }
        let session = self.session
        DispatchQueue.global(qos: .userInitiated).async {
            session.stopRunning()
        }
    }

    private func startRunning() {
        guard !session.isRunning else { return }
        // startRunning blocks until the device is configured, which is long
        // enough to stall the first paint of the window if it runs here.
        let session = self.session
        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    private func handle(_ detections: [Detection]) {
        guard !isSuspended else { return }

        let outcome = arbiter.admit(detections)
        if case .accepted = outcome {
            suspend()
        }
        delegate?.scanSession(self, didObserve: outcome)
    }
}

extension ScanSession: AVCaptureVideoDataOutputSampleBufferDelegate {
    nonisolated func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        guard !isPausedOnCaptureQueue,
              let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else {
            return
        }

        let timestamp = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        if lastDecodedAt.isValid, timestamp.isValid {
            let elapsed = CMTimeGetSeconds(CMTimeSubtract(timestamp, lastDecodedAt))
            guard elapsed >= 1.0 / Self.decodesPerSecond else { return }
        }
        lastDecodedAt = timestamp

        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: .up, options: [:])
        do {
            try handler.perform([request])
        } catch {
            // A single frame that failed to decode is not worth reporting: the
            // next one arrives in a thirtieth of a second.
            return
        }

        // The frame is turned into plain values here, before anything crosses
        // to the main actor, so no capture or Vision object outlives the queue
        // it belongs to.
        let detections: [Detection] = (request.results ?? []).compactMap { observation in
            guard let payload = observation.payloadStringValue,
                  let accepted = PayloadInspector.accept(payload) else {
                return nil
            }
            let box = observation.boundingBox
            return Detection(payload: accepted, center: CGPoint(x: box.midX, y: box.midY))
        }

        Task { @MainActor in
            self.handle(detections)
        }
    }
}
