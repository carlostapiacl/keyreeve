import Foundation
import KeyreeveCatalog
import Testing
@testable import KeyreeveUI

@MainActor
struct OpeningTests {
    /// Between the fingerprint and the first read, nothing says there is no list, so the welcome stays away.
    @Test func theWelcomeWaitsForTheFirstRead() {
        let model = AppModel(
            files: KeyreeveFiles(directory: FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-opening-\(UUID())")),
            binary: nil)
        model.startedWithoutFolder = false
        model.unlocked = true
        #expect(!model.firstLoadDone)
        #expect(!model.needsWelcome)
        model.firstLoadDone = true
        #expect(model.needsWelcome)
    }
}
