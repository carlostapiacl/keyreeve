import Foundation
import KeyreeveCatalog
import KeyreeveVault
@testable import KeyreeveUI
import Testing

@MainActor
struct ReviewTests {
    @Test func reviewingSaysWhatHappensToEachKeyAndLeavesAWaitingValue() {
        let model = RenderTests().model()
        var new = CatalogItem(path: "added/new.txt", lastResult: "works")
        new.newFrom = "claude"
        var waiting = CatalogItem(path: "added/waiting.txt", lastResult: "works")
        waiting.waitingFrom = "claude"
        let refused = CatalogItem(path: "old.txt", lastResult: "rejected")
        let fine = CatalogItem(path: "fine.txt", lastResult: "works")
        let plan = model.reviewPlan(for: [new, waiting, refused, fine])
        #expect(plan.new.map(\.path) == ["added/new.txt"])
        #expect(plan.left.map(\.path) == ["added/waiting.txt"])
        #expect(plan.quieted.map(\.path) == ["old.txt"])
        // A file others can read is closed only where there is a folder to close it in.
        #expect(plan.openFiles.isEmpty)
    }

    @Test func onlySealedKeysWithAProviderAreOpenedToAgentsInBulk() {
        let model = RenderTests().model()
        var sealed = CatalogItem(path: "s.txt")
        sealed.vault = .sealed
        var loose = CatalogItem(path: "l.txt")
        loose.vault = .sealed
        var index = KeyIndex()
        index.keys = [KeyIndex.Key(id: "resend-x", source: "s.txt", provider: "resend"), KeyIndex.Key(id: "loose", source: "l.txt")]
        model.keyIndex = index
        #expect(model.agentReachable([sealed, loose, CatalogItem(path: "file-only.txt")]).map(\.id) == ["resend-x"])
    }
}
