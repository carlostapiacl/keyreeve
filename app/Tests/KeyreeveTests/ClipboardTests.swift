import AppKit
import Testing

@testable import KeyreeveUI

struct ClipboardTests {
    func board() -> NSPasteboard { NSPasteboard(name: .init("keyreeve-test-\(UUID().uuidString)")) }

    @Test func testAKeyIsMarkedAndThenLeaves() {
        let pasteboard = board()
        var clipboard = KeyClipboard(pasteboard: pasteboard)
        clipboard.copy("CANARY")
        #expect(pasteboard.string(forType: .string) == "CANARY")
        #expect(pasteboard.types?.contains(.init("org.nspasteboard.ConcealedType")) == true)
        clipboard.clear()
        #expect(pasteboard.string(forType: .string) == nil)
    }

    @Test func testSomethingYouCopiedAfterwardsStays() {
        let pasteboard = board()
        var clipboard = KeyClipboard(pasteboard: pasteboard)
        clipboard.copy("CANARY")
        pasteboard.clearContents()
        pasteboard.setString("yours", forType: .string)
        clipboard.clear()
        #expect(pasteboard.string(forType: .string) == "yours")
    }
}
