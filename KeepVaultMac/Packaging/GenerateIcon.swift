import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else {
    fputs("usage: GenerateIcon.swift OUTPUT.png\n", stderr)
    exit(64)
}

let output = URL(fileURLWithPath: CommandLine.arguments[1])
let canvas = NSSize(width: 1024, height: 1024)
let image = NSImage(size: canvas)
image.lockFocus()

guard let context = NSGraphicsContext.current?.cgContext else {
    fputs("unable to create icon graphics context\n", stderr)
    exit(1)
}

context.setAllowsAntialiasing(true)
context.setShouldAntialias(true)

let outerRect = NSRect(x: 42, y: 42, width: 940, height: 940)
let outerPath = NSBezierPath(roundedRect: outerRect, xRadius: 226, yRadius: 226)
let background = NSGradient(colorsAndLocations:
    (NSColor(deviceRed: 0.055, green: 0.075, blue: 0.14, alpha: 1.0), 0.0),
    (NSColor(deviceRed: 0.04, green: 0.17, blue: 0.25, alpha: 1.0), 0.52),
    (NSColor(deviceRed: 0.02, green: 0.29, blue: 0.31, alpha: 1.0), 1.0)
)!
background.draw(in: outerPath, angle: -45)

NSColor(deviceWhite: 1.0, alpha: 0.10).setStroke()
outerPath.lineWidth = 8
outerPath.stroke()

let safeRect = NSRect(x: 206, y: 190, width: 612, height: 644)
let safePath = NSBezierPath(roundedRect: safeRect, xRadius: 86, yRadius: 86)
NSColor(deviceRed: 0.055, green: 0.075, blue: 0.11, alpha: 0.96).setFill()
safePath.fill()
NSColor(deviceRed: 0.35, green: 0.91, blue: 0.78, alpha: 0.84).setStroke()
safePath.lineWidth = 18
safePath.stroke()

let inset = NSBezierPath(roundedRect: safeRect.insetBy(dx: 34, dy: 34), xRadius: 58, yRadius: 58)
NSColor(deviceWhite: 1.0, alpha: 0.09).setStroke()
inset.lineWidth = 5
inset.stroke()

let dialCenter = NSPoint(x: 512, y: 520)
let dialRadius: CGFloat = 178
let dialRect = NSRect(
    x: dialCenter.x - dialRadius,
    y: dialCenter.y - dialRadius,
    width: dialRadius * 2,
    height: dialRadius * 2)
let dial = NSBezierPath(ovalIn: dialRect)
let dialGradient = NSGradient(colorsAndLocations:
    (NSColor(deviceRed: 0.17, green: 0.23, blue: 0.29, alpha: 1.0), 0.0),
    (NSColor(deviceRed: 0.05, green: 0.08, blue: 0.13, alpha: 1.0), 1.0)
)!
dialGradient.draw(in: dial, relativeCenterPosition: NSPoint(x: -0.25, y: 0.30))
NSColor(deviceRed: 0.47, green: 0.98, blue: 0.83, alpha: 0.95).setStroke()
dial.lineWidth = 13
dial.stroke()

for tick in 0..<16 {
    let angle = CGFloat(tick) * .pi * 2 / 16 + .pi / 2
    let inner = tick % 4 == 0 ? dialRadius - 36 : dialRadius - 24
    let outer = dialRadius - 9
    let tickPath = NSBezierPath()
    tickPath.move(to: NSPoint(
        x: dialCenter.x + cos(angle) * inner,
        y: dialCenter.y + sin(angle) * inner))
    tickPath.line(to: NSPoint(
        x: dialCenter.x + cos(angle) * outer,
        y: dialCenter.y + sin(angle) * outer))
    NSColor(deviceWhite: 0.93, alpha: tick % 4 == 0 ? 0.96 : 0.48).setStroke()
    tickPath.lineWidth = tick % 4 == 0 ? 10 : 6
    tickPath.lineCapStyle = .round
    tickPath.stroke()
}

let spindle = NSBezierPath(ovalIn: NSRect(x: 459, y: 467, width: 106, height: 106))
NSColor(deviceRed: 0.42, green: 0.97, blue: 0.80, alpha: 1.0).setFill()
spindle.fill()

let pointer = NSBezierPath()
pointer.move(to: NSPoint(x: 512, y: 512))
pointer.line(to: NSPoint(x: 590, y: 610))
NSColor(deviceWhite: 0.98, alpha: 0.96).setStroke()
pointer.lineWidth = 22
pointer.lineCapStyle = .round
pointer.stroke()

let keyhole = NSBezierPath()
keyhole.appendOval(in: NSRect(x: 481, y: 431, width: 62, height: 62))
keyhole.move(to: NSPoint(x: 496, y: 454))
keyhole.line(to: NSPoint(x: 482, y: 382))
keyhole.line(to: NSPoint(x: 542, y: 382))
keyhole.line(to: NSPoint(x: 528, y: 454))
keyhole.close()
NSColor(deviceRed: 0.025, green: 0.08, blue: 0.11, alpha: 1.0).setFill()
keyhole.fill()

let hinges = [NSRect(x: 762, y: 646, width: 42, height: 94), NSRect(x: 762, y: 284, width: 42, height: 94)]
for hingeRect in hinges {
    let hinge = NSBezierPath(roundedRect: hingeRect, xRadius: 18, yRadius: 18)
    NSColor(deviceRed: 0.38, green: 0.91, blue: 0.78, alpha: 0.94).setFill()
    hinge.fill()
}

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fputs("unable to encode icon PNG\n", stderr)
    exit(1)
}

try png.write(to: output, options: .atomic)
