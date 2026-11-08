import Foundation
import KeyreeveCatalog
@testable import KeyreeveUI
import Testing

@MainActor
struct MemoTests {
    @Test func testAKeptValueIsWorkedOutAgainOnlyWhenItsKeyChanges() {
        let memo = ViewMemo()
        var made = 0
        let make = { () -> Int in made += 1; return made }
        #expect(memo.value("x", key: [1, "a"], make) == 1)
        #expect(memo.value("x", key: [1, "a"], make) == 1)
        #expect(memo.value("x", key: [2, "a"], make) == 2)
        #expect(memo.value("y", key: [2, "a"], make) == 3)
    }

    @Test func testNewKeysChangeTheCountsAndTheVersion() {
        let model = RenderTests().model()
        let before = model.itemsVersion
        model.items = [CatalogItem(path: "only", lastResult: "works")]
        #expect(model.itemsVersion != before)
        #expect(model.summary.active == 1)
        #expect(model.summary.count(.result("works")) == 1)
    }
}
