import Testing

@testable import KeyreeveCatalog

struct CatalogTests {
    let header = "path,level,tags,format,labels,modified,mode,reviewed,last_result,last_checked\n"

    @Test func testReadsWhatTheCommandWrites() throws {
        let items = try CatalogParser.parse(
            header + "\"'=a,\"\"b\"\".txt\",never,one two,env,A B,2026-01-02,600,true,works,2026-02-03\n")
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].path, "=a,\"b\".txt")
        XCTAssertEqual(items[0].tags, ["one", "two"])
        XCTAssertEqual(items[0].lastResult, "works")
    }

    @Test func testAnOlderCatalogStillOpens() throws {
        let items = try CatalogParser.parse(
            "path,level,tags,format,labels,modified,mode,reviewed\na,ask,,env,,2026-01-02,600,true\n")
        XCTAssertEqual(items[0].lastResult, "")
    }

    @Test func testAMissingColumnIsAnError() {
        XCTAssertThrowsError(try CatalogParser.parse("path,level\na,ask\n"))
    }

    @Test func testAttentionPicksWhatMatters() {
        XCTAssertNotNil(CatalogItem(path: "a", tags: ["status:backup"], lastResult: "works").attention)
        XCTAssertNil(CatalogItem(path: "a", tags: ["status:backup"], lastResult: "rejected").attention)
        XCTAssertNotNil(CatalogItem(path: "a", lastResult: "rejected").attention)
        XCTAssertNotNil(CatalogItem(path: "a", mode: "644").attention)
        XCTAssertNil(CatalogItem(path: "a.pub", level: "none", mode: "644").attention)
        XCTAssertNotNil(CatalogItem(path: "a", reviewed: false).attention)
        XCTAssertNil(CatalogItem(path: "a").attention)
    }

    @Test func testFiltersBySidebarAndSearch() {
        let items = [
            CatalogItem(path: "shop.env", level: "never", tags: ["shop"]),
            CatalogItem(path: "blog.txt", tags: ["blog"], lastResult: "rejected"),
        ]
        XCTAssertEqual(filter(items, by: .all, search: "").count, 2)
        XCTAssertEqual(filter(items, by: .attention, search: "").map(\.path), ["blog.txt"])
        XCTAssertEqual(filter(items, by: .level("never"), search: "").map(\.path), ["shop.env"])
        XCTAssertEqual(filter(items, by: .tag("blog"), search: "").map(\.path), ["blog.txt"])
        XCTAssertEqual(filter(items, by: .all, search: " SHOP ").map(\.path), ["shop.env"])
    }
}
