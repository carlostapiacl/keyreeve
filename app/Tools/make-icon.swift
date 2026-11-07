// Draws the app icon from code, so it can be reviewed in a diff like any other file.
// A guard in a dark suit stops a robot at the door: an agent waits until the person says yes.
import AppKit

func render(_ size: Int, to path: String) {
    let side = CGFloat(size)
    let image = NSImage(size: NSSize(width: side, height: side), flipped: false) { rect in
        // Points on a 0...1 grid, y up.
        func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: x * side, y: y * side) }
        func box(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ r: CGFloat = 0) -> NSBezierPath {
            NSBezierPath(roundedRect: NSRect(x: x * side, y: y * side, width: w * side, height: h * side),
                         xRadius: r * side, yRadius: r * side)
        }
        func limb(_ from: NSPoint, _ to: NSPoint, _ width: CGFloat) -> NSBezierPath {
            let path = NSBezierPath()
            path.move(to: from)
            path.line(to: to)
            path.lineWidth = width * side
            path.lineCapStyle = .round
            return path
        }
        let yellow = NSColor(calibratedRed: 0.98, green: 0.78, blue: 0.16, alpha: 1)
        let ink = NSColor(calibratedRed: 0.07, green: 0.07, blue: 0.08, alpha: 1)

        let tile = NSBezierPath(roundedRect: rect.insetBy(dx: side * 0.09, dy: side * 0.09), xRadius: side * 0.19, yRadius: side * 0.19)
        NSGradient(
            starting: NSColor(calibratedRed: 1.0, green: 0.84, blue: 0.30, alpha: 1),
            ending: NSColor(calibratedRed: 0.96, green: 0.70, blue: 0.08, alpha: 1))?.draw(in: tile, angle: -90)
        tile.addClip()
        ink.setFill()
        ink.setStroke()

        // The guard: long hair, a dark suit, one arm out.
        let hair = NSBezierPath()                            // hair, down to the shoulders
        hair.move(to: p(0.205, 0.53))
        hair.curve(to: p(0.225, 0.70), controlPoint1: p(0.215, 0.60), controlPoint2: p(0.215, 0.66))
        hair.curve(to: p(0.355, 0.70), controlPoint1: p(0.25, 0.77), controlPoint2: p(0.33, 0.77))
        hair.curve(to: p(0.375, 0.53), controlPoint1: p(0.365, 0.66), controlPoint2: p(0.365, 0.60))
        hair.close()
        hair.fill()
        NSBezierPath(ovalIn: NSRect(x: 0.225 * side, y: 0.58 * side, width: 0.13 * side, height: 0.15 * side)).fill()  // head
        box(0.27, 0.52, 0.04, 0.05).fill()                  // neck
        let suit = NSBezierPath()
        suit.move(to: p(0.17, 0.50))
        suit.curve(to: p(0.23, 0.545), controlPoint1: p(0.17, 0.53), controlPoint2: p(0.20, 0.545))
        suit.line(to: p(0.35, 0.545))
        suit.curve(to: p(0.41, 0.50), controlPoint1: p(0.38, 0.545), controlPoint2: p(0.41, 0.53))
        suit.line(to: p(0.39, 0.25))
        suit.line(to: p(0.19, 0.25))
        suit.close()
        suit.fill()
        yellow.setFill()                                     // shirt and tie
        let shirt = NSBezierPath()
        shirt.move(to: p(0.255, 0.545))
        shirt.line(to: p(0.325, 0.545))
        shirt.line(to: p(0.29, 0.44))
        shirt.close()
        shirt.fill()
        ink.setFill()
        let tie = NSBezierPath()
        tie.move(to: p(0.282, 0.54))
        tie.line(to: p(0.298, 0.54))
        tie.line(to: p(0.302, 0.47))
        tie.line(to: p(0.29, 0.455))
        tie.line(to: p(0.278, 0.47))
        tie.close()
        tie.fill()
        box(0.20, 0.08, 0.075, 0.19).fill()                 // legs
        box(0.305, 0.08, 0.075, 0.19).fill()
        limb(p(0.38, 0.505), p(0.55, 0.505), 0.05).stroke() // arm
        limb(p(0.20, 0.49), p(0.21, 0.32), 0.05).stroke()   // other arm, down
        box(0.53, 0.495, 0.12, 0.04, 0.008).fill()          // pistol: slide
        let grip = NSBezierPath()
        grip.move(to: p(0.535, 0.50))
        grip.line(to: p(0.575, 0.50))
        grip.line(to: p(0.565, 0.43))
        grip.line(to: p(0.525, 0.43))
        grip.close()
        grip.fill()

        // The robot, hands up.
        box(0.68, 0.17, 0.17, 0.2, 0.03).fill()              // body
        box(0.695, 0.39, 0.14, 0.12, 0.035).fill()           // head
        limb(p(0.765, 0.51), p(0.765, 0.57), 0.02).stroke()  // antenna
        NSBezierPath(ovalIn: NSRect(x: 0.748 * side, y: 0.56 * side, width: 0.034 * side, height: 0.034 * side)).fill()
        limb(p(0.69, 0.34), p(0.64, 0.45), 0.035).stroke()   // arms up
        limb(p(0.84, 0.34), p(0.89, 0.45), 0.035).stroke()
        box(0.70, 0.08, 0.05, 0.1).fill()                    // legs
        box(0.78, 0.08, 0.05, 0.1).fill()
        yellow.setFill()
        NSBezierPath(ovalIn: NSRect(x: 0.72 * side, y: 0.435 * side, width: 0.035 * side, height: 0.035 * side)).fill()  // eyes
        NSBezierPath(ovalIn: NSRect(x: 0.775 * side, y: 0.435 * side, width: 0.035 * side, height: 0.035 * side)).fill()
        box(0.735, 0.405, 0.06, 0.012, 0.006).fill()         // mouth
        return true
    }
    guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
        let png = bitmap.representation(using: .png, properties: [:])
    else { fatalError("could not draw the icon") }
    try? png.write(to: URL(fileURLWithPath: path))
}

let folder = CommandLine.arguments[1]
try? FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    render(size, to: "\(folder)/icon_\(size)x\(size).png")
    render(size * 2, to: "\(folder)/icon_\(size)x\(size)@2x.png")
}
