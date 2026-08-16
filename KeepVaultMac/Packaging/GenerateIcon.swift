import AppKit
import Foundation

// Draws the Keep Vault mark: a bevelled shield carrying a maze of glowing
// traces that converge on a keyhole.
//
// The motif is drawn rather than shipped as artwork so every size is rendered
// at full resolution instead of resampled, and so the icon stays reviewable as
// source. Two things carry the identity at 16 points, where the maze is no
// longer resolvable: the shield silhouette and the keyhole. Everything else is
// detail for the large sizes and is deliberately kept low in contrast so it
// never muddies the small ones.

guard CommandLine.arguments.count >= 2 else {
    fputs("usage: GenerateIcon.swift OUTPUT.png [EMBLEM.png]\n", stderr)
    exit(64)
}

let iconOutput = URL(fileURLWithPath: CommandLine.arguments[1])
let emblemOutput = CommandLine.arguments.count >= 3
    ? URL(fileURLWithPath: CommandLine.arguments[2])
    : nil

let canvasSide: CGFloat = 1024

let tealBright = NSColor(deviceRed: 0.31, green: 0.95, blue: 0.86, alpha: 1.0)
let tealMid = NSColor(deviceRed: 0.20, green: 0.78, blue: 0.72, alpha: 1.0)
let tealDeep = NSColor(deviceRed: 0.11, green: 0.50, blue: 0.50, alpha: 1.0)
let slateFace = NSColor(deviceRed: 0.10, green: 0.14, blue: 0.19, alpha: 1.0)
let slateFaceDark = NSColor(deviceRed: 0.05, green: 0.07, blue: 0.10, alpha: 1.0)
let steelLight = NSColor(deviceRed: 0.80, green: 0.84, blue: 0.88, alpha: 1.0)
let steelDark = NSColor(deviceRed: 0.36, green: 0.41, blue: 0.47, alpha: 1.0)

/// The shield outline: a peaked top edge over straight shoulders that sweep
/// into a single bottom point.
func shieldPath(in rect: NSRect) -> NSBezierPath {
    let path = NSBezierPath()
    let cx = rect.midX
    let top = rect.maxY
    let bottom = rect.minY
    let shoulder = top - (rect.height * 0.085)
    let waist = bottom + (rect.height * 0.36)

    path.move(to: NSPoint(x: rect.minX, y: shoulder))
    path.line(to: NSPoint(x: cx, y: top))
    path.line(to: NSPoint(x: rect.maxX, y: shoulder))
    path.line(to: NSPoint(x: rect.maxX, y: waist))
    path.curve(
        to: NSPoint(x: cx, y: bottom),
        controlPoint1: NSPoint(x: rect.maxX, y: bottom + (rect.height * 0.15)),
        controlPoint2: NSPoint(x: cx + (rect.width * 0.31), y: bottom + (rect.height * 0.035)))
    path.curve(
        to: NSPoint(x: rect.minX, y: waist),
        controlPoint1: NSPoint(x: cx - (rect.width * 0.31), y: bottom + (rect.height * 0.035)),
        controlPoint2: NSPoint(x: rect.minX, y: bottom + (rect.height * 0.15)))
    path.close()
    return path
}

/// The keyhole: a round bore over a tapered slot.
func keyholePath(center: NSPoint, radius: CGFloat) -> NSBezierPath {
    let path = NSBezierPath()
    let slotHalfTop = radius * 0.42
    let slotHalfBottom = radius * 0.66
    let slotBottom = center.y - (radius * 3.05)

    path.appendArc(
        withCenter: center,
        radius: radius,
        startAngle: 250,
        endAngle: 290,
        clockwise: false)
    path.line(to: NSPoint(x: center.x + slotHalfBottom, y: slotBottom))
    path.line(to: NSPoint(x: center.x - slotHalfBottom, y: slotBottom))
    path.line(to: NSPoint(x: center.x - slotHalfTop, y: center.y - radius))
    path.close()
    return path
}

/// One of the small steel clasps that grip the shield rim.
func drawClasp(at point: NSPoint, angle: CGFloat, scale: CGFloat) {
    NSGraphicsContext.saveGraphicsState()
    let transform = NSAffineTransform()
    transform.translateX(by: point.x, yBy: point.y)
    transform.rotate(byDegrees: angle)
    transform.scale(by: scale)
    transform.concat()

    let body = NSBezierPath(roundedRect: NSRect(x: -46, y: -30, width: 92, height: 60), xRadius: 14, yRadius: 14)
    let gradient = NSGradient(starting: steelLight, ending: steelDark)!
    gradient.draw(in: body, angle: -60)
    NSColor(deviceWhite: 0.0, alpha: 0.35).setStroke()
    body.lineWidth = 5
    body.stroke()

    // A pair of chevrons, as on the reference mark.
    let chevron = NSBezierPath()
    chevron.move(to: NSPoint(x: -20, y: 16))
    chevron.line(to: NSPoint(x: 4, y: 0))
    chevron.line(to: NSPoint(x: -20, y: -16))
    chevron.lineWidth = 8
    chevron.lineCapStyle = .round
    chevron.lineJoinStyle = .round
    NSColor(deviceWhite: 0.20, alpha: 0.85).setStroke()
    chevron.stroke()

    NSGraphicsContext.restoreGraphicsState()
}

/// Draws the mark. The plate behind it is optional so the same routine produces
/// both the app icon and a transparent emblem for use inside the app.
func drawMark(withPlate: Bool) {
    guard let context = NSGraphicsContext.current?.cgContext else {
        fputs("unable to create icon graphics context\n", stderr)
        exit(1)
    }
    context.setAllowsAntialiasing(true)
    context.setShouldAntialias(true)

    if withPlate {
        let plateRect = NSRect(x: 42, y: 42, width: 940, height: 940)
        let plate = NSBezierPath(roundedRect: plateRect, xRadius: 226, yRadius: 226)
        let background = NSGradient(colorsAndLocations:
            (NSColor(deviceRed: 0.05, green: 0.07, blue: 0.10, alpha: 1.0), 0.0),
            (NSColor(deviceRed: 0.07, green: 0.11, blue: 0.16, alpha: 1.0), 0.55),
            (NSColor(deviceRed: 0.05, green: 0.14, blue: 0.19, alpha: 1.0), 1.0)
        )!
        background.draw(in: plate, angle: -90)
        NSColor(deviceWhite: 1.0, alpha: 0.10).setStroke()
        plate.lineWidth = 8
        plate.stroke()
    }

    let shieldRect = NSRect(x: 214, y: 132, width: 596, height: 748)
    let shield = shieldPath(in: shieldRect)

    // Outer glow, so the mark separates from a dark desktop.
    NSGraphicsContext.saveGraphicsState()
    context.setShadow(
        offset: .zero,
        blur: 46,
        color: tealMid.withAlphaComponent(0.55).cgColor)
    slateFaceDark.setFill()
    shield.fill()
    NSGraphicsContext.restoreGraphicsState()

    // Bevelled steel rim.
    let rim = NSGradient(colorsAndLocations:
        (steelLight, 0.0),
        (steelDark, 0.45),
        (NSColor(deviceRed: 0.62, green: 0.68, blue: 0.74, alpha: 1.0), 1.0)
    )!
    rim.draw(in: shield, angle: -60)

    // Recessed face.
    let faceRect = shieldRect.insetBy(dx: 34, dy: 34)
    let face = shieldPath(in: NSRect(
        x: faceRect.minX,
        y: faceRect.minY + 10,
        width: faceRect.width,
        height: faceRect.height - 6))
    let faceGradient = NSGradient(starting: slateFace, ending: slateFaceDark)!
    faceGradient.draw(in: face, angle: -90)

    let center = NSPoint(x: shieldRect.midX, y: shieldRect.minY + (shieldRect.height * 0.46))

    NSGraphicsContext.saveGraphicsState()
    face.addClip()

    // The maze: concentric arcs broken by gaps, the way the reference reads.
    // Kept at moderate alpha so it never competes with the keyhole when the
    // icon is drawn at 16 or 32 points.
    let arcSpecs: [(CGFloat, CGFloat, CGFloat, CGFloat)] = [
        (112, 20, 160, 7),
        (112, 200, 340, 7),
        (162, 62, 118, 9),
        (162, 152, 300, 9),
        (212, 8, 84, 9),
        (212, 108, 172, 9),
        (212, 196, 344, 9),
        (262, 40, 140, 8),
        (262, 214, 326, 8),
    ]
    for (radius, start, end, width) in arcSpecs {
        let arc = NSBezierPath()
        arc.appendArc(withCenter: center, radius: radius, startAngle: start, endAngle: end, clockwise: false)
        arc.lineWidth = width
        arc.lineCapStyle = .round
        tealMid.withAlphaComponent(0.85).setStroke()
        arc.stroke()
    }

    // Orthogonal traces running out of the maze, as circuitry.
    let traceSpecs: [[NSPoint]] = [
        [NSPoint(x: center.x - 250, y: center.y + 150), NSPoint(x: center.x - 150, y: center.y + 150), NSPoint(x: center.x - 150, y: center.y + 244)],
        [NSPoint(x: center.x + 250, y: center.y + 150), NSPoint(x: center.x + 150, y: center.y + 150), NSPoint(x: center.x + 150, y: center.y + 244)],
        [NSPoint(x: center.x - 262, y: center.y - 74), NSPoint(x: center.x - 186, y: center.y - 74), NSPoint(x: center.x - 186, y: center.y - 168)],
        [NSPoint(x: center.x + 262, y: center.y - 74), NSPoint(x: center.x + 186, y: center.y - 74), NSPoint(x: center.x + 186, y: center.y - 168)],
    ]
    for points in traceSpecs {
        let trace = NSBezierPath()
        trace.move(to: points[0])
        for point in points.dropFirst() {
            trace.line(to: point)
        }
        trace.lineWidth = 8
        trace.lineCapStyle = .round
        trace.lineJoinStyle = .round
        tealDeep.withAlphaComponent(0.9).setStroke()
        trace.stroke()

        let node = NSBezierPath(ovalIn: NSRect(x: points[0].x - 11, y: points[0].y - 11, width: 22, height: 22))
        tealMid.withAlphaComponent(0.9).setFill()
        node.fill()
    }

    // The bright spine: one unbroken path from the top of the shield straight
    // through the keyhole, which is what makes the mark read as a key slot.
    let spine = NSBezierPath(rect: NSRect(
        x: center.x - 21,
        y: shieldRect.minY + 62,
        width: 42,
        height: shieldRect.maxY - shieldRect.minY - 132))
    let spineGradient = NSGradient(colorsAndLocations:
        (tealBright.withAlphaComponent(0.55), 0.0),
        (tealBright, 0.46),
        (tealBright.withAlphaComponent(0.80), 1.0)
    )!
    spineGradient.draw(in: spine, angle: -90)

    NSGraphicsContext.restoreGraphicsState()

    // Keyhole escutcheon, then the bore itself. The plate is kept dark and the
    // bore pure black: at small sizes the eye finds the icon by that black
    // shape against the glow, so anything that lightens it costs legibility.
    let escutcheon = NSBezierPath(ovalIn: NSRect(
        x: center.x - 112,
        y: center.y - 112,
        width: 224,
        height: 224))
    let escutcheonGradient = NSGradient(
        starting: NSColor(deviceRed: 0.19, green: 0.24, blue: 0.29, alpha: 1.0),
        ending: NSColor(deviceRed: 0.07, green: 0.10, blue: 0.13, alpha: 1.0))!
    escutcheonGradient.draw(in: escutcheon, angle: -60)

    NSGraphicsContext.saveGraphicsState()
    context.setShadow(offset: .zero, blur: 30, color: tealBright.withAlphaComponent(1.0).cgColor)
    tealBright.setStroke()
    escutcheon.lineWidth = 11
    escutcheon.stroke()
    NSGraphicsContext.restoreGraphicsState()

    let keyhole = keyholePath(center: NSPoint(x: center.x, y: center.y + 30), radius: 74)
    NSColor(deviceRed: 0.01, green: 0.02, blue: 0.03, alpha: 1.0).setFill()
    keyhole.fill()

    // Steel clasps gripping the rim.
    drawClasp(at: NSPoint(x: shieldRect.minX + 86, y: shieldRect.maxY - 96), angle: -32, scale: 0.86)
    drawClasp(at: NSPoint(x: shieldRect.maxX - 86, y: shieldRect.maxY - 96), angle: 32, scale: 0.86)
    drawClasp(at: NSPoint(x: shieldRect.minX + 26, y: center.y + 62), angle: -84, scale: 0.80)
    drawClasp(at: NSPoint(x: shieldRect.maxX - 26, y: center.y + 62), angle: 84, scale: 0.80)
}

func render(to url: URL, withPlate: Bool) {
    let image = NSImage(size: NSSize(width: canvasSide, height: canvasSide))
    image.lockFocus()
    drawMark(withPlate: withPlate)
    image.unlockFocus()

    guard let tiff = image.tiffRepresentation,
          let bitmap = NSBitmapImageRep(data: tiff),
          let png = bitmap.representation(using: .png, properties: [:]) else {
        fputs("unable to encode the icon as PNG\n", stderr)
        exit(1)
    }

    do {
        try png.write(to: url, options: .atomic)
    } catch {
        fputs("unable to write \(url.path): \(error)\n", stderr)
        exit(1)
    }
}

render(to: iconOutput, withPlate: true)
if let emblemOutput {
    render(to: emblemOutput, withPlate: false)
}
