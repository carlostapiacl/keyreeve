import Foundation
import KeyreeveVault
import Testing

/// An agent asking for a provider whose key is not saved yet, and the file the requests live in.
struct UnsavedRequestTests {
    final class World: @unchecked Sendable {
        var policy = AgentPolicy()
        var entries: [AccessRequests.Entry] = []
        var answer = AgentBridge.Announcement.later
        var announced = 0
        var now = Date(timeIntervalSince1970: 1_800_000_000)
    }

    func bridge(_ world: World) -> AgentBridge {
        AgentBridge(
            policy: { world.policy }, names: { ["pexels"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            now: { world.now }, agent: "claude",
            offered: { ["resend", "openai"] },
            requests: { world.entries },
            addRequest: { world.entries.append($0) },
            announce: { _ in
                world.announced += 1
                return world.answer
            })
    }

    func ask(_ bridge: AgentBridge, _ key: String = "resend") throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, "request_access", ["key": key, "reason": "send a test email", "duration": "4h"])
    }

    @Test func providersNotSavedAreListedByNameOnly() throws {
        let text = try AgentTests().call(bridge(World()), "list_keys", [:]).text
        #expect(text.hasSuffix("Not saved yet, ask with request_access by provider: openai, resend"))
    }

    @Test func aRequestIsKeptAndAnnouncedOnceUntilItIsAnswered() throws {
        let world = World()
        let bridge = bridge(world)
        let first = try ask(bridge)
        #expect(!first.error && first.text.hasPrefix("Waiting"))
        let asked = try #require(world.entries.first)
        #expect(asked.event == .asked && asked.provider == "resend" && asked.hours == 4 && asked.reason == "send a test email")
        // Asking again while it waits does not show the window again.
        #expect(try ask(bridge).text.hasPrefix("Still waiting"))
        #expect(world.announced == 1 && world.entries.count == 1)
        // The app saves it as resend-test and opens it.
        world.entries.append(AccessRequests.Entry(
            id: asked.id, at: world.now, event: .allowed, agent: "claude", provider: "resend", hours: 4, key: "resend-test"))
        world.policy = AgentPolicy(levels: ["resend-test": .free], agents: ["resend-test": ["claude"]])
        #expect(try ask(bridge).text.contains("Use use_key with key resend-test"))
    }

    @Test func aNoFromTheWindowOrTheAppStopsTheAgentAsking() throws {
        let world = World()
        world.answer = .deny
        let bridge = bridge(world)
        #expect(try ask(bridge).error)
        #expect(world.entries.map(\.event) == [.asked, .declined])
        #expect(try ask(bridge).text.contains("within the hour"))
        #expect(world.announced == 1)
        // Declined in the app, a fresh session can ask again after an hour.
        let fresh = World()
        fresh.entries = [
            AccessRequests.Entry(id: "r-1", at: fresh.now, event: .asked, agent: "claude", provider: "resend"),
            AccessRequests.Entry(id: "r-1", at: fresh.now, event: .declined, agent: "claude", provider: "resend"),
        ]
        let other = self.bridge(fresh)
        #expect(try ask(other).error)
        fresh.now += 3601
        #expect(!(try ask(other).error) && fresh.announced == 1)
    }

    @Test func whilePausedEveryAgentIsRefusedWithNoWindow() throws {
        final class Switch: @unchecked Sendable { var on = true }
        let paused = Switch()
        let world = World()
        var logged: [String] = []
        let bridge = AgentBridge(
            policy: { AgentPolicy(levels: ["pexels": .free]) }, names: { ["pexels"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            service: { _ in Issue.record("a paused agent reached the service"); return KeyService.Response(ok: false) },
            log: { event, key, detail, _ in logged.append("\(event) \(key) \(detail)") },
            offered: { ["resend"] }, requests: { world.entries }, addRequest: { world.entries.append($0) },
            announce: { _ in world.announced += 1; return .open },
            paused: { paused.on })
        let use = try AgentTests().call(bridge, "use_key", ["key": "pexels", "command": ["curl"], "reason": "r"])
        #expect(use.error && use.text.contains("paused"))
        #expect(try ask(bridge).error)
        #expect(try AgentTests().call(bridge, "list_keys", [:]).text.contains("paused"))
        #expect(world.announced == 0 && world.entries.isEmpty)
        #expect(logged == ["refused pexels paused", "refused resend paused"])
        paused.on = false
        #expect(!(try AgentTests().call(bridge, "list_keys", [:]).text.contains("paused")))
    }

    @Test func thePauseIsAFileThatComesAndGoes() {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("home-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        #expect(!AgentBridge.isPaused(home: home))
        AgentBridge.setPaused(true, home: home)
        #expect(AgentBridge.isPaused(home: home))
        AgentBridge.setPaused(false, home: home)
        #expect(!AgentBridge.isPaused(home: home))
    }

    @Test func aProviderThatCannotBeSavedIsNotAsked() throws {
        let world = World()
        #expect(try ask(bridge(world), "stripe").error)
        #expect(world.entries.isEmpty && world.announced == 0)
    }

    @Test func theFileKeepsEveryLineAndOnlyUnansweredArePending() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("requests-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        try AccessRequests.append(.init(id: "r-1", at: at, event: .asked, agent: "claude", provider: "resend", reason: "a\nb"), to: url)
        try AccessRequests.append(.init(id: "r-2", at: at, event: .asked, agent: "codex", provider: "openai"), to: url)
        try AccessRequests.append(.init(id: "r-1", at: at, event: .allowed, agent: "claude", provider: "resend", key: "resend"), to: url)
        let read = AccessRequests.read(from: url)
        #expect(read.count == 3 && read[0].reason == "a b")
        #expect(AccessRequests.pending(read).map(\.id) == ["r-2"])
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
    }
}
