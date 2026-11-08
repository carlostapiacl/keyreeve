import Foundation
import KeyreeveVault
import Testing

/// Every log as one list, and the words the app writes when permissions change.
struct TimelineTests {
    func home() throws -> URL {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("timeline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        return home
    }

    @Test func theLogsComeTogetherInTimeOrderWithIdentifiers() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        // Written by file name, as copying from the app does, and shown by the key's name.
        try AuditLog(url: home.appendingPathComponent("audit.jsonl")).append(
            event: "used", key: "pexels.txt", declared: .init(agent: "claude", reason: "find a photo"), now: t0.addingTimeInterval(20))
        AgentTranscript(url: home.appendingPathComponent(AgentTranscript.fileName)).append(.init(
            at: t0.addingTimeInterval(30), agent: "claude", key: "pexels", command: "curl -s x", reason: "find a photo",
            exit: 0, output: "secret-looking output", milliseconds: 412))
        try "{\"at\": 1800000000, \"file\": \"pexels.txt\", \"recipe\": \"pexels\", \"result\": \"works\"}\n"
            .write(to: home.appendingPathComponent("history.jsonl"), atomically: true, encoding: .utf8)
        try "{\"name\":\"pexels.txt\",\"command\":\"compare\",\"at\":1800000010}\nnot json\n"
            .write(to: home.appendingPathComponent("usage.jsonl"), atomically: true, encoding: .utf8)
        let index = KeyIndex(keys: [KeyIndex.Key(id: "pexels", source: "pexels.txt", provider: "pexels")])
        let rows = Timeline.read(home: home, index: index)
        #expect(rows.map(\.source) == ["checks", "terminal", "audit", "agents"])
        #expect(rows.allSatisfy { $0.key == "pexels" })
        #expect(rows[3].program == "curl" && rows[3].detail == "exit 0, 412 ms")
        // What a command printed never reaches the timeline.
        #expect(!Timeline.jsonl(rows).contains("secret-looking"))
        #expect(Timeline.read(home: home, index: index, since: t0.addingTimeInterval(15)).count == 2)
    }

    @Test func csvKeepsCellsWholeAndFormulasAsText() {
        let row = Timeline.Row(
            at: Date(timeIntervalSince1970: 0), source: "audit", event: "used", key: "k", detail: "a, \"b\"", reason: "=SUM(A1)")
        let lines = Timeline.csv([row]).split(separator: "\n")
        #expect(lines[0] == "at,source,event,key,agent,program,detail,reason")
        #expect(lines[1] == "1970-01-01T00:00:00Z,audit,used,k,,,\"a, \"\"b\"\"\",'=SUM(A1)")
    }

    @Test func sinceReadsMinutesHoursAndDays() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(Timeline.start(from: "7d", now: now) == now.addingTimeInterval(-7 * 86400))
        #expect(Timeline.start(from: "24h", now: now) == now.addingTimeInterval(-86400))
        #expect(Timeline.start(from: "30m", now: now) == now.addingTimeInterval(-1800))
        #expect(Timeline.start(from: "week", now: now) == nil)
        #expect(Timeline.start(from: "-1d", now: now) == nil)
    }

    @Test func aPolicyChangeIsDescribedInWords() {
        let before = AgentPolicy(levels: ["pexels": .ask])
        let after = AgentPolicy(
            commands: ["vps": ["/Users/me/tools/deploy.sh"]], levels: ["pexels": .free, "resend": .free],
            agents: ["resend": ["claude"]], until: ["resend": Date(timeIntervalSince1970: 1_800_003_600)])
        let changes = after.changes(from: before)
        #expect(changes.map(\.key) == ["pexels", "resend", "vps"])
        #expect(changes[0].detail == "ask -> free")
        #expect(changes[1].detail == "only me -> free, agents claude, until 2027-01-15T09:00:00Z")
        #expect(changes[2].detail == "only me -> ask, programs deploy.sh")
        #expect(before.changes(from: after).first?.detail == "free -> ask")
        #expect(after.changes(from: after).isEmpty)
    }
}
