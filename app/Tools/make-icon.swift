// Draws the app icon from code, so it can be reviewed in a diff like any other file.
import AppKit

func render(_ size: Int, to path: String) {
    let side = CGFloat(size)
    let image = NSImage(size: NSSize(width: side, height: side), flipped: false) { rect in
        let inset = rect.insetBy(dx: side * 0.09, dy: side * 0.09)
        let shape = NSBezierPath(roundedRect: inset, xRadius: side * 0.19, yRadius: side * 0.19)
        NSGradient(
            starting: NSColor(calibratedRed: 0.13, green: 0.17, blue: 0.24, alpha: 1),
            ending: NSColor(calibratedRed: 0.07, green: 0.09, blue: 0.13, alpha: 1))?.draw(in: shape, angle: -90)
        let config = NSImage.SymbolConfiguration(pointSize: side * 0.44, weight: .medium)
            .applying(.init(paletteColors: [NSColor(calibratedRed: 0.96, green: 0.76, blue: 0.33, alpha: 1)]))
        if let key = NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil)?
            .withSymbolConfiguration(config) {
            let box = key.size
            key.draw(in: NSRect(x: (side - box.width) / 2, y: (side - box.height) / 2, width: box.width, height: box.height))
        }
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
