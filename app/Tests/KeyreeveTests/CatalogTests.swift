import Foundation
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

struct StatsTests {
    @Test func testStatsCountSecretsAndRankWhatMattersFirst() throws {
        let now = Date(timeIntervalSince1970: 1_793_923_200)  // 2026-11-06
        let items = [
            CatalogItem(path: "z-unread", tags: ["shop"], modified: "2026-11-01", mode: "644"),
            CatalogItem(path: "a-live", tags: ["revoke", "shop"], modified: "2024-02-13", lastResult: "works"),
            CatalogItem(path: "b.pub", level: "none", tags: ["shop"], modified: "2026-11-01", mode: "644"),
            CatalogItem(path: "c", tags: ["blog"], modified: "2026-07-01", lastResult: "rejected", recipes: ["meta"]),
            CatalogItem(path: "d", level: "never", modified: "2026-09-20", lastResult: "no_result", recipes: ["x"]),
        ]
        let stats = CatalogStats(items: items, now: now)
        XCTAssertEqual(stats.total, 5)
        XCTAssertEqual(stats.secrets, 4)
        XCTAssertEqual(stats.needLook.map(\.path), ["a-live", "c", "z-unread"])
        XCTAssertEqual(stats.works, 1)
        XCTAssertEqual(stats.rejected, 1)
        XCTAssertEqual(stats.noAnswer, 1)
        XCTAssertEqual(stats.neverChecked, 1)
        XCTAssertEqual(stats.checked, 3)
        XCTAssertEqual(stats.canCheck, 1)
        XCTAssertEqual(stats.ages.map(\.count), [1, 1, 1, 1])
        XCTAssertEqual(stats.projects.first?.label, "shop")
        XCTAssertEqual(stats.projects.first?.count, 2)
    }

    @Test func testExtraProjectsFoldIntoOther() {
        let items = (0..<5).map { CatalogItem(path: "k\($0)", tags: ["p\($0)"]) }
        let stats = CatalogStats(items: items, maxProjects: 3)
        XCTAssertEqual(stats.projects.map(\.label).last, "Other")
        XCTAssertEqual(stats.projects.last?.count, 2)
    }

    @Test func testActivityIsNewestFirstAndAPassFromAnyRecipeCounts() {
        let history = """
            {"at":100,"file":"a","recipe":"meta","result":"rejected"}
            {"at":100,"file":"a","recipe":"instagram","result":"works"}
            {"torn
            {"at":50,"file":"b","recipe":"x","result":"rejected"}
            """
        let usage = #"{"at":200,"name":"c","command":"deploy.sh"}"#
        let activity = ActivityItem.parse(history: history, usage: usage)
        XCTAssertEqual(activity.map(\.key), ["c", "a", "b"])
        XCTAssertEqual(activity[1].kind, .checked(result: "works"))
        XCTAssertEqual(activity[0].kind, .used(by: "deploy.sh"))
    }
}

struct CheckTests {
    @Test func testOnlyKeysWithARecipeAndAnAllowedLevelAreChecked() {
        XCTAssertFalse(CatalogItem(path: "a").canCheck)
        XCTAssertFalse(CatalogItem(path: "a", level: "never", recipes: ["github"]).canCheck)
        XCTAssertFalse(CatalogItem(path: "a", level: "none", recipes: ["github"]).canCheck)
        XCTAssertEqual(CatalogItem(path: "a", level: "free", recipes: ["github"]).canCheck, true)
        XCTAssertNotNil(CatalogItem(path: "a").whyNoCheck)
    }

    @Test func testThePlanSkipsWhatItMustNotCheckAndEscapesNames() throws {
        let plan = try CheckRunner.plan(for: [
            CatalogItem(path: "a \"b\".txt", recipes: ["meta", "instagram"], field: "TOKEN"),
            CatalogItem(path: "secret.txt", level: "never", recipes: ["github"]),
        ])
        let parsed = try JSONSerialization.jsonObject(with: plan) as? [String: [[String: String]]]
        let keys = try #require(parsed?["keys"])
        XCTAssertEqual(keys.map { $0["recipe"]! }, ["meta", "instagram"])
        XCTAssertEqual(keys[0]["file"], "a \"b\".txt")
        XCTAssertEqual(keys[0]["field"], "TOKEN")
    }

    /// Runs the real command when KEYREEVE_BIN is set. It contacts the provider with a made-up key.
    @Test func testARealCheckUpdatesTheCatalogAndLeavesNoValueBehind() throws {
        guard let binary = ProcessInfo.processInfo.environment["KEYREEVE_BIN"] else { return }
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("keyreeve-check-\(UUID().uuidString)")
        defer { try? manager.removeItem(at: root) }
        let keys = root.appendingPathComponent("keys")
        try manager.createDirectory(at: keys, withIntermediateDirectories: true)
        try "CANARYtoken0000000000000000000000000000\n".write(
            to: keys.appendingPathComponent("hosting.txt"), atomically: true, encoding: .utf8)
        let files = KeyreeveFiles(directory: root.appendingPathComponent("private"))
        let tool = URL(fileURLWithPath: binary)
        try manager.createDirectory(at: files.directory, withIntermediateDirectories: true)
        let inventory = Process()
        inventory.executableURL = tool
        inventory.arguments = ["inventory", keys.path, "--out", files.inventory.path]
        inventory.standardOutput = FileHandle.nullDevice
        try inventory.run()
        inventory.waitUntilExit()

        let item = CatalogItem(path: "hosting.txt", recipes: ["hetzner"])
        try CheckRunner.run([item], binary: tool, keysFolder: keys, files: files)

        let catalog = try String(contentsOf: files.catalog, encoding: .utf8)
        let rows = try CatalogParser.parse(catalog)
        XCTAssertEqual(rows.first?.lastResult, "rejected")
        XCTAssertFalse(manager.fileExists(atPath: files.plan.path))
        for url in [files.catalog, files.history, files.inventory] {
            XCTAssertFalse(try String(contentsOf: url, encoding: .utf8).contains("CANARY"))
        }

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: keys.appendingPathComponent("hosting.txt").path)
        try CheckRunner.refresh(binary: tool, keysFolder: keys, files: files)
        XCTAssertEqual(try CatalogParser.parse(String(contentsOf: files.catalog, encoding: .utf8)).first?.mode, "644")
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: keys.appendingPathComponent("hosting.txt").path)
        try CheckRunner.refresh(binary: tool, keysFolder: keys, files: files)
        let refreshed = try CatalogParser.parse(String(contentsOf: files.catalog, encoding: .utf8))
        XCTAssertEqual(refreshed.first?.mode, "600")
        XCTAssertEqual(refreshed.first?.lastResult, "rejected")
    }
}
