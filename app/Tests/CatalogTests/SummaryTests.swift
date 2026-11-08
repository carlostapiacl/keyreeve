import Foundation
import KeyreeveCatalog
import Testing

/// The counts kept with the keys say what filtering would say.
struct SummaryTests {
    @Test func testEachChipCountsWhatItsFilterShows() {
        let items = [
            CatalogItem(path: "a", tags: ["shop"], lastResult: "works", recipes: ["github"], criticality: 5),
            CatalogItem(path: "b", tags: ["status:archived"], lastResult: "works"),
            CatalogItem(path: "c", lastResult: "rejected", lastChecked: "2026-01-01", recipes: ["github"]),
            CatalogItem(path: "d", level: "none", tags: ["shop"]),
            CatalogItem(path: "e", lastResult: "no_result", recipes: ["github"], rotateDays: 1),
        ]
        let summary = CatalogSummary(items: items)
        for chip in CatalogSummary.chips {
            #expect(summary.count(chip) == filter(items, by: chip, search: "").count, "\(chip)")
        }
        #expect(summary.active == 4)
        #expect(summary.toReview == items.filter { $0.attention != nil }.count)
        #expect(summary.projects.first?.tag == "shop")
    }
}
