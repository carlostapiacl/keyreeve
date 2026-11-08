import AppKit

/// A new key taken from the clipboard for a rotation by hand. The clipboard is cleared once it is read,
/// so the key does not wait there for the next paste, and it is never shown.
@MainActor
enum PastedKey {
    static func take(from board: NSPasteboard = .general) -> String? {
        guard let text = board.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty,
            !text.contains(where: \.isWhitespace)
        else { return nil }
        board.clearContents()
        return text
    }
}
