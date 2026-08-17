import AppKit
import CoreGraphics
import Foundation
import Vision

// Runs a PDF or image through the same decoding and arbitration path the app
// uses on camera frames, and reports what it decided.
//
// The camera cannot be pointed at a file, so this is how the pipeline is
// checked against a real Schlüsselzettel: same Vision request, same symbology,
// same Detection values, same CodeArbiter. What it prints is what the app
// would do with that sheet held in front of the lens.
//
//   xcrun swiftc -parse-as-library -O \
//     QrCodeScanner/Sources/CodeArbiter.swift \
//     QrCodeScanner/Sources/PayloadInspector.swift \
//     QrCodeScanner/tools/scan-file.swift -o /tmp/scan-file
//   /tmp/scan-file sheet.pdf

private func renderFirstPage(of url: URL) -> CGImage? {
    if let document = CGPDFDocument(url as CFURL), let page = document.page(at: 1) {
        let box = page.getBoxRect(.mediaBox)
        // Roughly 200 dpi. A QR code photographed by a webcam is far coarser
        // than this, so it is deliberately generous: the point is to check the
        // pipeline, not to find the resolution limit.
        let scale: CGFloat = 200.0 / 72.0
        let width = Int(box.width * scale)
        let height = Int(box.height * scale)
        guard let context = CGContext(
            data: nil, width: width, height: height,
            bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            return nil
        }
        context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        context.scaleBy(x: scale, y: scale)
        context.drawPDFPage(page)
        return context.makeImage()
    }

    guard let image = NSImage(contentsOf: url) else { return nil }
    return image.cgImage(forProposedRect: nil, context: nil, hints: nil)
}

/// Blanks out a rectangle, standing in for the coffee stain or crease that
/// makes one of the two printed codes unreadable.
private func obscuring(_ image: CGImage, rect: CGRect) -> CGImage? {
    guard let context = CGContext(
        data: nil, width: image.width, height: image.height,
        bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
        return nil
    }
    context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
    context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
    context.fill(rect)
    return context.makeImage()
}

private func detections(in image: CGImage) -> [Detection] {
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    let handler = VNImageRequestHandler(cgImage: image, orientation: .up, options: [:])
    do {
        try handler.perform([request])
    } catch {
        FileHandle.standardError.write(Data("Vision failed: \(error)\n".utf8))
        return []
    }
    return (request.results ?? []).compactMap { observation in
        guard let payload = observation.payloadStringValue,
              let accepted = PayloadInspector.accept(payload) else {
            return nil
        }
        let box = observation.boundingBox
        return Detection(payload: accepted, center: CGPoint(x: box.midX, y: box.midY))
    }
}

private func abbreviate(_ payload: String) -> String {
    payload.count <= 24 ? payload : "\(payload.prefix(12))…\(payload.suffix(8)) (\(payload.count) Zeichen)"
}

private func describe(_ outcome: ScanOutcome) -> String {
    switch outcome {
    case .searching:
        return "searching"
    case .confirming(let progress, let required):
        return "confirming \(progress)/\(required)"
    case .conflict(let payloads):
        return "conflict between \(payloads.count) different payloads"
    case .accepted(let payload, .matchingCodes(let count)):
        return "accepted \(abbreviate(payload)) — confirmed by \(count) matching codes"
    case .accepted(let payload, .repeatedReads(let count)):
        return "accepted \(abbreviate(payload)) — single code, \(count) identical reads"
    }
}

@main
private enum ScanFile {
    static func main() {
        guard CommandLine.arguments.count >= 2 else {
            FileHandle.standardError.write(Data("Usage: scan-file <pdf-or-image>\n".utf8))
            exit(64)
        }

        let url = URL(fileURLWithPath: CommandLine.arguments[1])
        guard let image = renderFirstPage(of: url) else {
            FileHandle.standardError.write(Data("Could not render \(url.path)\n".utf8))
            exit(1)
        }
        print("image: \(image.width)x\(image.height)")

        let found = detections(in: image)
        print("codes found: \(found.count)")
        for detection in found {
            let x = String(format: "%.3f", detection.center.x)
            let y = String(format: "%.3f", detection.center.y)
            print("  at (\(x), \(y)): \(abbreviate(detection.payload))")
        }

        let distinct = Set(found.map(\.payload))
        print("distinct payloads: \(distinct.count)")

        var arbiter = CodeArbiter()
        print("both codes readable -> \(describe(arbiter.admit(found)))")

        // Now the case the sheet is printed twice for: one code destroyed.
        guard found.count >= 2 else {
            print("only one code on this sheet; damage case not exercised")
            exit(0)
        }

        let sorted = found.sorted { $0.center.x < $1.center.x }
        let victim = sorted[0]
        let side = CGFloat(min(image.width, image.height)) * 0.18
        let damaged = obscuring(
            image,
            rect: CGRect(
                x: victim.center.x * CGFloat(image.width) - side / 2,
                y: victim.center.y * CGFloat(image.height) - side / 2,
                width: side,
                height: side))

        guard let damaged, case let remaining = detections(in: damaged) else {
            print("could not build the damaged variant")
            exit(1)
        }
        print("after destroying the left code, codes found: \(remaining.count)")

        var fallback = CodeArbiter()
        var outcome: ScanOutcome = .searching
        for _ in 0 ..< 8 {
            outcome = fallback.admit(remaining)
        }
        print("one code destroyed -> \(describe(outcome))")

        if case .accepted(let payload, _) = outcome, distinct.contains(payload) {
            print("RESULT: the surviving code returned the same content as the intact sheet")
            exit(0)
        }
        print("RESULT: the damaged sheet did not yield the sheet's content")
        exit(1)
    }
}
