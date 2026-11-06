import Foundation
import KeyreeveUI
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

struct ActionTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let directory = ProviderDirectory([
        ProviderInfo(id: "langsmith", name: "LangSmith", dashboard: "https://smith.langchain.com/settings"),
        ProviderInfo(id: "aws", name: "AWS", dashboard: "https://console.aws.amazon.com/iam/home", can_identify: true),
        ProviderInfo(id: "acme", name: "Acme", hosts: ["a.co"], source: "local", approved: false, can_identify: true),
    ])

    @Test func testProvidersComeFromTheirFiles() {
        let data = Data(#"[{"id":"x","name":"X","dashboard":null,"hosts":[],"source":"builtin","approved":true,"can_check":true,"can_identify":false,"can_rotate":false,"can_rotate_by_hand":false,"single_rotation":false,"tested":{},"self_hosted":false,"suggested_name":null,"problem":null,"programs":[],"actions":[]}]"#.utf8)
        XCTAssertEqual(ProviderDirectory.parse(data).name(of: "x"), "X")
        XCTAssertEqual(ProviderDirectory.parse(Data("nope".utf8)).all.count, 0)
        XCTAssertEqual(directory.usable.map(\.id), ["langsmith", "aws"])
        XCTAssertEqual(directory.all[2].needsApproval, true)
    }

    @Test func testOnlyAKeyWithAnApprovedProviderCanBeIdentified() {
        XCTAssertEqual(directory.canIdentify(CatalogItem(path: "a", recipes: ["aws"])), true)
        XCTAssertEqual(directory.canIdentify(CatalogItem(path: "a", recipes: ["acme"])), false)
        XCTAssertEqual(directory.canIdentify(CatalogItem(path: "a", recipes: ["langsmith"])), false)
        XCTAssertEqual(directory.canIdentify(CatalogItem(path: "a", level: "never", recipes: ["aws"])), false)
    }

    @Test func testAnArchivedKeyLeavesTheListsUnlessItStillWorks() {
        let dead = CatalogItem(path: "dead", tags: ["status:archived"], lastResult: "rejected")
        let alive = CatalogItem(path: "alive", tags: ["status:archived"], lastResult: "works", name: "Old cloud")
        let open = CatalogItem(path: "open")
        XCTAssertNil(dead.attentionRanked(at: now))
        XCTAssertEqual(alive.attentionRanked(at: now)?.rank, 6)
        let items = [dead, alive, open]
        XCTAssertEqual(filter(items, by: .all, search: "").map(\.path), ["open"])
        XCTAssertEqual(filter(items, by: .archive, search: "").map(\.path), ["dead", "alive"])
        XCTAssertEqual(filter(items, by: .attention, search: "").map(\.path), ["alive"])
        let stats = CatalogStats(items: items, now: now)
        XCTAssertEqual(stats.archived, 2)
        XCTAssertEqual(stats.secrets, 1)
        XCTAssertEqual(stats.needLook.map(\.path), ["alive"])
        XCTAssertEqual(alive.title, "Old cloud")
        XCTAssertEqual(dead.title, "dead")
    }

    @Test func testFiltersByResultAndSummarizesARun() {
        let items = [
            CatalogItem(path: "a", lastResult: "works"), CatalogItem(path: "b", lastResult: "rejected"),
            CatalogItem(path: "c", lastResult: "no_result"), CatalogItem(path: "d", lastResult: "forbidden"),
            CatalogItem(path: "e"), CatalogItem(path: "f.pub", level: "none"),
            CatalogItem(path: "g", tags: ["status:archived"], lastResult: "works"),
        ]
        XCTAssertEqual(filter(items, by: .result("works"), search: "").map(\.path), ["a"])
        XCTAssertEqual(filter(items, by: .result("no_answer"), search: "").map(\.path), ["c", "d"])
        XCTAssertEqual(filter(items, by: .result(""), search: "").map(\.path), ["e"])
        let run = RunSummary(items: items, checked: ["a", "b", "c", "d"])
        XCTAssertEqual(run.checked, 4)
        XCTAssertEqual(run.works, 1)
        XCTAssertEqual(run.rejected, 1)
        XCTAssertEqual(run.noAnswer, 2)
    }

    @Test func testOnlyApprovedFilesOfferTheirButtons() {
        let button = CustomAction(id: "go", label: "Go", label_es: "Ir", open: "https://x.com")
        let providers = ProviderDirectory([
            ProviderInfo(id: "mine", name: "Mine", source: "local", approved: true, actions: [button]),
            ProviderInfo(id: "other", name: "Other", source: "local", approved: false, actions: [button]),
        ])
        XCTAssertEqual(providers.customActions(for: CatalogItem(path: "a", recipes: ["mine"])).count, 1)
        XCTAssertEqual(providers.customActions(for: CatalogItem(path: "a", recipes: ["other"])).count, 0)
    }

    @Test func testAFingerprintLastsTheChosenPeriod() {
        var window = ConfirmationWindow()
        XCTAssertFalse(window.isOpen(minutes: 5, at: now))
        window.confirm(at: now)
        XCTAssertEqual(window.isOpen(minutes: 5, at: now.addingTimeInterval(299)), true)
        XCTAssertFalse(window.isOpen(minutes: 5, at: now.addingTimeInterval(300)))
        XCTAssertFalse(window.isOpen(minutes: 0, at: now))  // zero means every time
        XCTAssertFalse(window.isOpen(minutes: 5, at: now.addingTimeInterval(-10)))  // a clock moved back ends it
        window.close()
        XCTAssertFalse(window.isOpen(minutes: 5, at: now))
    }

    @Test func testAnInternalSecretOffersNoCheck() {
        let item = CatalogItem(path: "jwt", tags: ["internal"], recipes: ["aws"])
        XCTAssertFalse(item.canCheck)
        XCTAssertNotNil(item.whyNoCheck)
        XCTAssertEqual(filter([item], by: .internalOnly, search: "").count, 1)
    }

    @Test func testASelfHostedProviderNeedsAnAddressFirst() {
        let hosted = ProviderDirectory([ProviderInfo(id: "panel", name: "Panel", can_identify: true, self_hosted: true)])
        let bare = CatalogItem(path: "a", recipes: ["panel"])
        XCTAssertEqual(hosted.needsHost(bare), true)
        XCTAssertFalse(hosted.canCheck(bare))
        XCTAssertFalse(hosted.canIdentify(bare))
        let set = CatalogItem(path: "a", recipes: ["panel"], host: "panel.example.com")
        XCTAssertEqual(hosted.canCheck(set), true)
        XCTAssertEqual(hosted.canIdentify(set), true)
    }

    @Test func testAgeComparesAgainstTheProvidersSuggestion() {
        let old = CatalogItem(path: "a", modified: "2020-01-01", rotateDays: 90)
        let fresh = CatalogItem(path: "b", modified: "2026-12-30", rotateDays: 90)
        let none = CatalogItem(path: "c", modified: "2020-01-01")
        XCTAssertEqual(old.isOlderThanSuggested(at: now), true)
        XCTAssertFalse(fresh.isOlderThanSuggested(at: Date(timeIntervalSince1970: 1_798_761_600)))
        XCTAssertFalse(none.isOlderThanSuggested(at: now))
        XCTAssertEqual(CatalogStats(items: [old, none], now: now).stale, 1)
    }

    @Test func testAPlanCarriesTheServer() throws {
        let plan = try CheckRunner.plan(for: [CatalogItem(path: "a", recipes: ["panel"], host: "panel.example.com")])
        XCTAssertEqual(String(decoding: plan, as: UTF8.self).contains("panel.example.com"), true)
    }

    @Test func testMostCriticalComesFirst() {
        let items = [
            CatalogItem(path: "low", criticality: 1), CatalogItem(path: "none"),
            CatalogItem(path: "top", criticality: 5), CatalogItem(path: "high", criticality: 4),
        ]
        XCTAssertEqual(filter(items, by: .all, search: "").map(\.path), ["top", "high", "low", "none"])
        XCTAssertEqual(filter(items, by: .critical, search: "").map(\.path), ["top", "high"])
        XCTAssertEqual(CatalogStats(items: items, now: now).critical, 2)
        let same = [
            CatalogItem(path: "b", tags: ["revoke"], lastResult: "works", criticality: 2),
            CatalogItem(path: "a", tags: ["revoke"], lastResult: "works", criticality: 5),
        ]
        XCTAssertEqual(CatalogStats(items: same, now: now).needLook.map(\.path), ["a", "b"])
    }

    @Test func testSearchFindsNamesAndAccounts() {
        let item = CatalogItem(
            path: "x.csv", name: "Old cloud", description: "billing test",
            details: KeyDetails(provider: "aws", fields: ["account": "211"]))
        XCTAssertEqual(filter([item], by: .all, search: "old").count, 1)
        XCTAssertEqual(filter([item], by: .all, search: "billing").count, 1)
        XCTAssertEqual(filter([item], by: .all, search: "211").count, 1)
        XCTAssertEqual(filter([item], by: .all, search: "nope").count, 0)
    }

    @Test func testALiveKeyToRevokeOffersTheProviderThenAConfirmedRevocation() {
        let item = CatalogItem(path: "a", tags: ["revoke"], lastResult: "works", recipes: ["langsmith"])
        let list = actions(for: item, providers: directory, at: now)
        XCTAssertEqual(list.first, .openProvider(URL(string: "https://smith.langchain.com/settings")!))
        XCTAssertEqual(list.contains(.confirmRevoked), true)
        XCTAssertEqual(list.contains(.markRevoked), false)
        XCTAssertEqual(list.last, .ignore)
    }

    @Test func testAKeyThatCannotBeCheckedIsMarkedByHand() {
        let item = CatalogItem(path: "a", tags: ["revoke", "provider:aws"], lastResult: "works")
        let list = actions(for: item, providers: directory, at: now)
        XCTAssertEqual(list.contains(.markRevoked), true)
        XCTAssertEqual(list.contains(.confirmRevoked), false)
    }

    @Test func testEachProblemGetsItsOwnActions() {
        XCTAssertEqual(actions(for: CatalogItem(path: "a", mode: "644"), providers: directory, at: now), [.fixPermissions, .ignore])
        XCTAssertEqual(
            actions(for: CatalogItem(path: "a", lastResult: "rejected"), providers: directory, at: now), [.checkAgain, .notInUse, .ignore])
        XCTAssertEqual(actions(for: CatalogItem(path: "a", reviewed: false), providers: directory, at: now), [.ignore])
        XCTAssertEqual(actions(for: CatalogItem(path: "a"), providers: directory, at: now), [])
    }

    @Test func testIgnoringLastsUntilItsDate() {
        var item = CatalogItem(path: "a", tags: ["revoke"], lastResult: "works")
        item.ignoredUntil = now.addingTimeInterval(86_400)
        XCTAssertNil(item.attentionRanked(at: now))
        XCTAssertNotNil(item.attentionRanked(at: now.addingTimeInterval(90_000)))
    }

    @Test func testADoneKeyAsksForNothing() {
        let item = CatalogItem(path: "a", tags: ["status:revoked"], lastResult: "rejected")
        XCTAssertNil(item.attentionRanked(at: now))
    }

    @Test func testEditsMergeAndFixingPermissionsStaysInTheFolder() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("keyreeve-edit-\(UUID().uuidString)")
        defer { try? manager.removeItem(at: root) }
        let files = KeyreeveFiles(directory: root.appendingPathComponent("private"))
        try files.saveEdit(KeyEdit(level: "free"), for: "a")
        try files.saveEdit(KeyEdit(tags: ["x"]), for: "a")
        let saved = try JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: files.edits))
        XCTAssertEqual(saved["a"], KeyEdit(tags: ["x"], level: "free"))
        try files.saveEdit(KeyEdit(name: "N", description: "D"), for: "a")
        let named = try JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: files.edits))
        XCTAssertEqual(named["a"]?.name, "N")
        XCTAssertEqual(named["a"]?.level, "free")
        let mode = try manager.attributesOfItem(atPath: files.edits.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)

        try files.ignore("a", until: Date(timeIntervalSince1970: 1_900_000_000))
        XCTAssertEqual(files.ignoredKeys()["a"], Date(timeIntervalSince1970: 1_900_000_000))

        let keys = root.appendingPathComponent("keys")
        try manager.createDirectory(at: keys, withIntermediateDirectories: true)
        let inside = keys.appendingPathComponent("k.txt")
        let outside = root.appendingPathComponent("outside.txt")
        for file in [inside, outside] {
            try "x".write(to: file, atomically: true, encoding: .utf8)
            try manager.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        }
        try manager.createSymbolicLink(at: keys.appendingPathComponent("link"), withDestinationURL: outside)
        try files.fixPermissions(of: "k.txt", in: keys)
        XCTAssertEqual((try manager.attributesOfItem(atPath: inside.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertThrowsError(try files.fixPermissions(of: "../outside.txt", in: keys))
        XCTAssertThrowsError(try files.fixPermissions(of: "link", in: keys))
        XCTAssertEqual((try manager.attributesOfItem(atPath: outside.path)[.posixPermissions] as? NSNumber)?.intValue, 0o644)
    }
}

struct LanguageTests {
    /// Reads the app's own source, so a new text without a translation fails here.
    @Test func testEveryTextOnScreenHasASpanishTranslation() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources")
        let pattern = try NSRegularExpression(pattern: #"\bT\(\s*"((?:[^"\\]|\\.)*)""#)
        var missing = Set<String>()
        var count = 0
        for case let url as URL in FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)!
        where url.pathExtension == "swift" {
            let text = try String(contentsOf: url, encoding: .utf8)
            let range = NSRange(text.startIndex..., in: text)
            for match in pattern.matches(in: text, range: range) {
                let key = String(text[Range(match.range(at: 1), in: text)!])
                count += 1
                if spanish[key] == nil { missing.insert(key) }
            }
        }
        XCTAssertGreaterThan(count, 60)
        XCTAssertEqual(missing.sorted(), [])
    }

    /// Swift stops a program at a repeated key in a table, so a repeat here would crash the app in Spanish.
    @Test func testTheTableHasNoRepeatedKeys() throws {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/KeyreeveCatalog/Strings.swift")
        let text = try String(contentsOf: file, encoding: .utf8)
        let lines = text.components(separatedBy: "\n").filter { $0.hasPrefix("    \"") && $0.contains("\":") }
        let keys = lines.map { $0.components(separatedBy: "\":")[0] }
        XCTAssertEqual(Set(keys).count, keys.count)
        XCTAssertGreaterThan(keys.count, 100)
    }

    @Test func testTranslationsKeepTheirPlaceholders() {
        for (english, translated) in spanish {
            for mark in ["%d", "%@"] {
                XCTAssertEqual(
                    english.components(separatedBy: mark).count, translated.components(separatedBy: mark).count,
                    english)
            }
        }
    }

    @Test func testAMissingWordFallsBackToEnglish() {
        XCTAssertEqual(translate("Check", to: .spanish), "Probar")
        XCTAssertEqual(translate("Check", to: .english), "Check")
        XCTAssertEqual(translate("Not in the table", to: .spanish), "Not in the table")
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
        XCTAssertEqual(stats.projects.count, 4)
        XCTAssertNil(stats.projects.last?.target)
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

/// What the app hands the command, seen by a stand-in command that writes down what it got.
struct SealedRunTests {
    func standIn() throws -> (root: URL, binary: URL, files: KeyreeveFiles) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-run-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let binary = root.appendingPathComponent("stand-in.sh")
        try """
            #!/bin/sh
            printf '%s\\n' "$@" > '\(root.path)/args'
            env > '\(root.path)/env'
            cat > '\(root.path)/stdin'
            """.write(to: binary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: binary.path)
        return (root, binary, KeyreeveFiles(directory: root))
    }

    func read(_ root: URL, _ name: String) throws -> String {
        try String(contentsOf: root.appendingPathComponent(name), encoding: .utf8)
    }

    @Test func testASealedCopyTravelsOnStdinAlone() throws {
        let (root, binary, files) = try standIn()
        defer { try? FileManager.default.removeItem(at: root) }
        let item = CatalogItem(path: "a.txt", recipes: ["github"])
        // The stand-in writes no catalog, and the run stops there, after the part under test.
        _ = try? CheckRunner.run([item], binary: binary, keysFolder: root, files: files, sealed: ["a.txt": "CANARY-value"])
        #expect(try read(root, "stdin").contains("CANARY-value"))
        #expect(try read(root, "args").contains("--sealed-stdin"))
        XCTAssertFalse(try read(root, "args").contains("CANARY"))
        XCTAssertFalse(try read(root, "env").contains("CANARY"))
    }

    @Test func testWithNoSealedCopyNothingIsSentOrAsked() throws {
        let (root, binary, files) = try standIn()
        defer { try? FileManager.default.removeItem(at: root) }
        let item = CatalogItem(path: "a.txt", recipes: ["github"])
        _ = try? CheckRunner.run([item], binary: binary, keysFolder: root, files: files)
        XCTAssertFalse(try read(root, "args").contains("--sealed-stdin"))
    }

    @Test func testAnActionGetsItsKeyOnStdin() throws {
        let (root, binary, _) = try standIn()
        defer { try? FileManager.default.removeItem(at: root) }
        let action = CustomAction(id: "go", label: "Go", needs_key: true)
        _ = try? CheckRunner.runAction(
            provider: "p", action: action, item: CatalogItem(path: "a.txt"), binary: binary, keysFolder: root,
            sealed: "CANARY-value")
        XCTAssertEqual(try read(root, "stdin"), "CANARY-value")
        XCTAssertFalse(try read(root, "args").contains("CANARY"))
        XCTAssertFalse(try read(root, "args").contains("a.txt"))
    }

    @Test func testEachEndingSaysWhatIsTrue() throws {
        func message(_ outcome: String, _ manual: [String]) throws -> String {
            let list = String(decoding: try JSONEncoder().encode(manual), as: UTF8.self)
            return rotationMessage(try JSONDecoder().decode(RotationReport.self, from: Data(#"{"outcome":"\#(outcome)","manual":\#(list)}"#.utf8)))
        }
        let done = try message("completed", ["broken still holds the old key: update it by hand"])
        #expect(done == T("Rotated. Some steps need you: see Vault."))
        #expect(try message("completed", ["the id of the previous key is unknown: revoke it by hand"]) == T("Rotated. The old key still works: revoke it at the provider."))
        #expect(try message("completed", ["revoke the old key at the provider"]) == T("Rotated. The old key still works: revoke it at the provider."))
        #expect(try message("rolled_back", ["a key may have been created: check the provider"]) == T("Undone, but check the provider: see Vault."))
        #expect(try message("rolled_back", ["revoke the unused key x by hand"]) == T("Undone, but the new key is still alive at the provider: revoke it by hand (see Vault)."))
    }

    @Test @MainActor func testACompletedRotationDoesNotClaimARevocationItDidNotDo() throws {
        let manual = try JSONDecoder().decode(RotationReport.self, from: Data(#"{"outcome":"completed","manual":["x"]}"#.utf8))
        let clean = try JSONDecoder().decode(RotationReport.self, from: Data(#"{"outcome":"completed","manual":[]}"#.utf8))
        XCTAssertFalse(rotationMessage(manual) == rotationMessage(clean))
    }

    @Test func testARotationPlanHidesThePathFromTheProvider() throws {
        var places = KeyPlaces()
        places.files = ["/a/.env"]
        places.overlapMinutes = 60
        let item = CatalogItem(path: "private/client.env", recipes: ["resend"], field: "TOKEN")
        let plan = RotationPlan(item: item, places: places, admin: nil, original: nil)
        XCTAssertEqual(plan.overlap_secs, 3600)
        XCTAssertEqual(plan.field, "TOKEN")
        XCTAssertFalse(plan.issued_name.contains("client"))
        XCTAssertFalse(KeyPlaces().isDecided)
        XCTAssertNil(ProviderDirectory([ProviderInfo(id: "resend", name: "R", can_rotate: false)]).rotator(of: item))
        XCTAssertNotNil(ProviderDirectory([ProviderInfo(id: "resend", name: "R", can_rotate: true)]).rotator(of: item))
        XCTAssertNotNil(ProviderDirectory([ProviderInfo(id: "resend", name: "R", can_rotate_by_hand: true)]).rotator(of: item))
    }

    @Test func testTheFirstKeysOfferedAreLiveAndLeastCritical() {
        let list = vaultCandidates([
            CatalogItem(path: "dead-low", lastResult: "rejected", criticality: 1),
            CatalogItem(path: "live-high", lastResult: "works", criticality: 5),
            CatalogItem(path: "live-low", lastResult: "works", criticality: 2),
            CatalogItem(path: "live-unrated", lastResult: "works"),
            CatalogItem(path: "public", level: "none", lastResult: "works"),
            CatalogItem(path: "binary", format: "binary", lastResult: "works"),
        ])
        XCTAssertEqual(list.map(\.path), ["live-low", "live-high", "live-unrated", "dead-low"])
    }
}
