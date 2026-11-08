import Foundation
import KeyreeveVault
import Testing

/// An agent hears that a key's last check failed before it tries the key, and nothing for one that works.
struct CheckHistoryTests {
    @Test func theLatestCheckCountsAndAPassAtTheSameMomentWins() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("history-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        try """
            {"at":100,"file":"a.txt","recipe":"maps","result":"works"}
            {"at":200,"file":"a.txt","recipe":"maps","result":"rejected"}
            {"at":100,"file":"b.txt","recipe":"maps","result":"works"}
            {"at":300,"file":"c.txt","recipe":"maps","result":"rejected"}
            {"at":300,"file":"c.txt","recipe":"instagram","result":"works"}
            {"at":300,"file":"c.txt","recipe":"other","result":"rejected"}
            not a line
            """.write(to: url, atomically: true, encoding: .utf8)
        let last = CheckHistory.latest(in: url)
        #expect(last["a.txt"]?.result == "rejected")
        #expect(last["c.txt"]?.result == "works")
        #expect(CheckHistory.warning(last["a.txt"]) == "last check rejected on 1970-01-01: it may not work")
        #expect(CheckHistory.warning(last["b.txt"]) == nil && CheckHistory.warning(nil) == nil)
    }

    @Test func theListingSaysWhichAccountEachKeyIsAndWhatThePersonWrote() throws {
        let keys = [
            "maps-work": KeyIndex.Key(id: "maps-work", source: "a.txt", provider: "maps", account: "team-bot ", description: "Shop, read only"),
            "maps-home": KeyIndex.Key(id: "maps-home", source: "h.json", provider: "maps", account: "home-office"),
        ]
        let bridge = AgentBridge(
            policy: { AgentPolicy(levels: ["maps-work": .free]) }, names: { ["maps-work", "maps-home"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            describe: { keys })
        let text = try AgentTests().call(bridge, "list_keys", [:]).text
        #expect(text.contains("maps-work (account team-bot, \u{201C}Shop, read only\u{201D}): free"))
        #expect(text.contains("maps-home (maps, home-office)"))
    }

    @Test func theListingSaysWhichKeysFailedTheirLastCheck() throws {
        let bridge = AgentBridge(
            policy: { AgentPolicy(levels: ["dead": .free]) }, names: { ["dead", "closed"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            describe: { ["closed": KeyIndex.Key(id: "closed", source: "c.txt", provider: "maps")] },
            checkWarnings: { ["dead": "last check rejected on 2026-11-08: it may not work", "closed": "last check rejected on 2026-11-07: it may not work"] })
        let text = try AgentTests().call(bridge, "list_keys", [:]).text
        #expect(text.contains("dead: free: one fingerprint after Keyreeve starts, then no questions for up to 24 h; use_key with any command; last check rejected on 2026-11-08"))
        #expect(text.contains("closed (maps, last check rejected on 2026-11-07: it may not work)"))
    }
}
