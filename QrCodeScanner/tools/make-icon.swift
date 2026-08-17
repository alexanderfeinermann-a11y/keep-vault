import AppKit
import CoreImage
import Foundation
import ImageIO
import UniformTypeIdentifiers

// Draws the app icon: a real QR code on a rounded tile.
//
// The icon is generated rather than committed as a binary, so what it contains
// is readable in this file instead of being taken on trust. The code encodes
// the app's name; anyone who points a scanner at the icon gets "QR-Scanner"
// back, which is the honest thing for a QR code sitting in a Dock to say.
//
// Correction level L on a short string keeps the module count low (version 1,
// 21x21). That matters: at 16 points a denser code collapses into grey mush,
// while these modules stay individually visible.

let message = "QR-Scanner"
let sizes = [16, 32, 64, 128, 256, 512, 1024]

guard CommandLine.arguments.count >= 2 else {
    FileHandle.standardError.write(Data("Usage: make-icon.swift <output-iconset-directory>\n".utf8))
    exit(64)
}
let outputDirectory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try? FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

// MARK: - The QR code itself

func makeQrMask() -> CGImage {
    guard let generator = CIFilter(name: "CIQRCodeGenerator") else {
        fatalError("CIQRCodeGenerator is unavailable.")
    }
    generator.setValue(Data(message.utf8), forKey: "inputMessage")
    generator.setValue("L", forKey: "inputCorrectionLevel")
    guard let generated = generator.outputImage else {
        fatalError("The QR code could not be generated.")
    }

    // Black modules become opaque white, the background becomes transparent, so
    // the tile shows through around the code.
    guard let recolour = CIFilter(name: "CIFalseColor") else {
        fatalError("CIFalseColor is unavailable.")
    }
    recolour.setValue(generated, forKey: kCIInputImageKey)
    recolour.setValue(CIColor(red: 1, green: 1, blue: 1, alpha: 1), forKey: "inputColor0")
    recolour.setValue(CIColor(red: 0, green: 0, blue: 0, alpha: 0), forKey: "inputColor1")

    guard let output = recolour.outputImage,
          let cgImage = CIContext().createCGImage(output, from: output.extent) else {
        fatalError("The QR code could not be rendered.")
    }
    return cgImage
}

let qrMask = makeQrMask()

// MARK: - One icon at one size

func renderIcon(side: Int) -> CGImage {
    let dimension = CGFloat(side)
    guard let context = CGContext(
        data: nil,
        width: side,
        height: side,
        bitsPerComponent: 8,
        bytesPerRow: 0,
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
        fatalError("The icon bitmap could not be created.")
    }

    context.interpolationQuality = .high

    // macOS icons do not fill their canvas; the rounded tile sits inside it
    // with room to breathe, so this one lines up with everything else in the
    // Dock instead of looking oversized.
    let inset = dimension * 0.0703
    let tile = CGRect(x: inset, y: inset, width: dimension - 2 * inset, height: dimension - 2 * inset)
    let radius = tile.width * 0.2237

    let tilePath = CGPath(
        roundedRect: tile,
        cornerWidth: radius,
        cornerHeight: radius,
        transform: nil)

    context.saveGState()
    context.addPath(tilePath)
    context.clip()
    let gradient = CGGradient(
        colorsSpace: CGColorSpaceCreateDeviceRGB(),
        colors: [
            CGColor(red: 0.22, green: 0.27, blue: 0.38, alpha: 1),
            CGColor(red: 0.09, green: 0.11, blue: 0.17, alpha: 1),
        ] as CFArray,
        locations: [0, 1])!
    context.drawLinearGradient(
        gradient,
        start: CGPoint(x: tile.minX, y: tile.maxY),
        end: CGPoint(x: tile.maxX, y: tile.minY),
        options: [])
    context.restoreGState()

    // The QR code is snapped to whole pixels per module. Anything else lands
    // module edges between pixels, and the small sizes turn soft exactly where
    // a QR code needs to be crisp.
    let modules = CGFloat(qrMask.width)
    let available = tile.width * 0.74
    var scale = (available / modules).rounded(.down)
    if scale < 1 { scale = available / modules }
    let codeSide = modules * scale
    let codeOrigin = CGPoint(
        x: (dimension - codeSide) / 2,
        y: (dimension - codeSide) / 2)

    context.interpolationQuality = .none
    context.draw(qrMask, in: CGRect(origin: codeOrigin, size: CGSize(width: codeSide, height: codeSide)))

    guard let image = context.makeImage() else {
        fatalError("The icon could not be rendered.")
    }
    return image
}

func write(_ image: CGImage, to url: URL) {
    guard let destination = CGImageDestinationCreateWithURL(
        url as CFURL, UTType.png.identifier as CFString, 1, nil) else {
        fatalError("The icon could not be written: \(url.path)")
    }
    CGImageDestinationAddImage(destination, image, nil)
    guard CGImageDestinationFinalize(destination) else {
        fatalError("The icon could not be finalised: \(url.path)")
    }
}

var rendered: [Int: CGImage] = [:]
for side in sizes {
    rendered[side] = renderIcon(side: side)
}

// The names iconutil expects inside an .iconset directory.
let entries: [(name: String, side: Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

for entry in entries {
    write(rendered[entry.side]!, to: outputDirectory.appendingPathComponent(entry.name))
}

print("icon modules=\(qrMask.width)x\(qrMask.height) files=\(entries.count)")
