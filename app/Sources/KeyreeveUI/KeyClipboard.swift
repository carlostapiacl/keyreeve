import AppKit

/// Puts a key on the clipboard for a short while. It is marked so clipboard history tools skip it, and
/// it is taken off only if it is still what the clipboard holds, so it never erases what you copied next.
struct KeyClipboard {
    static let seconds = 60
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    let pasteboard: NSPasteboard
    private(set) var ours: Int?

    init(pasteboard: NSPasteboard = .general) { self.pasteboard = pasteboard }

    mutating func copy(_ value: String) {
        pasteboard.clearContents()
        pasteboard.declareTypes([.string, Self.concealed, Self.transient], owner: nil)
        pasteboard.setString(value, forType: .string)
        pasteboard.setString("", forType: Self.concealed)
        pasteboard.setString("", forType: Self.transient)
        ours = pasteboard.changeCount
    }

    mutating func clear() {
        defer { ours = nil }
        if let ours, pasteboard.changeCount == ours { pasteboard.clearContents() }
    }
}
