import Foundation
import KeyreeveVault
import Testing

/// An agent asking for a closed key, the person's answer, and keys opened for some hours.
struct AccessRequestTests {
    final class World: @unchecked Sendable {
        var policy = AgentPolicy()
        var saved = 0
        var now = Date(timeIntervalSince1970: 1_800_000_000)
        var asked: [AccessRequest] = []
        var answers: [AccessDecision?] = []
        var logged: [String] = []
        var requests: [KeyService.Request] = []
    }

    func bridge(_ world: World, agent: String = "claude") -> AgentBridge {
        AgentBridge(
            policy: { world.policy }, names: { ["pexels", "resend"] },
            open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") },
            record: { _, _, _ in },
            approve: { _ in .once },
            now: { world.now },
            agent: agent,
            service: { request in
                world.requests.append(request)
                if request.op == "grants" { return KeyService.Response(ok: true, grants: []) }
                return KeyService.Response(
                    ok: true, standIn: "S", proxy: KeyService.ProxyEndpoint(port: 9, ca: "/ca.pem", bundle: "/b.pem"),
                    variable: "RESEND_API_KEY", grant: "g-1")
            },
            runPrepared: { _ in AgentBridge.Output(status: 0, text: "") },
            log: { event, key, detail, _ in world.logged.append("\(event) \(key) \(detail)") },
            describe: { ["resend": KeyIndex.Key(id: "resend", source: "resend.txt", provider: "resend")] },
            decideAccess: { request in
                world.asked.append(request)
                return world.answers.isEmpty ? nil : world.answers.removeFirst()
            },
            updatePolicy: { change in
                change(&world.policy)
                world.saved += 1
            })
    }

    func request(_ bridge: AgentBridge, _ arguments: [String: Any]) throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, "request_access", arguments)
    }

    @Test func closedKeysAreListedByNameAndProviderOnly() throws {
        let world = World()
        world.policy = AgentPolicy(levels: ["pexels": .free])
        let text = try AgentTests().call(bridge(world), "list_keys", [:]).text
        #expect(text.hasPrefix("pexels: free"))
        #expect(text.hasSuffix("Closed, ask with request_access: resend (resend)"))
    }

    @Test func aYesOpensTheKeyToThatAgentAloneAndUseKeyAsksNothingMore() throws {
        let world = World()
        world.answers = [AccessDecision(hours: 4)]
        let bridge = bridge(world)
        let result = try request(bridge, ["key": "resend", "reason": "rotate the test key", "duration": "4h"])
        #expect(!result.error && result.text.contains("free until"))
        let asked = try #require(world.asked.first)
        #expect(asked.key == "resend" && asked.provider == "resend" && asked.agent == "claude")
        #expect(asked.hours == 4 && asked.reason == "rotate the test key")
        #expect(world.policy.levels["resend"] == .free)
        #expect(world.policy.agents["resend"] == ["claude"])
        #expect(world.policy.until["resend"] == world.now.addingTimeInterval(4 * 3600))
        // The permission the service gives never outlasts the opening.
        world.now += 3600
        let used = try AgentTests().call(bridge, "use_key", ["key": "resend", "command": ["curl", "x"], "reason": "r"])
        #expect(!used.error)
        // One fingerprint at the service, for any command, and no window.
        #expect(world.requests.last?.seconds == 3 * 3600 && world.requests.last?.anyProgram == true)
        #expect(!world.requests.contains { $0.op == "grants" })
        // Another agent still cannot.
        #expect(try AgentTests().call(self.bridge(world, agent: "codex"), "use_key", ["key": "resend", "command": ["curl"], "reason": "r"]).error)
    }

    @Test func aKeyOpenedForHoursClosesByItself() throws {
        let world = World()
        world.answers = [AccessDecision(hours: 1)]
        let bridge = bridge(world)
        #expect(!(try request(bridge, ["key": "resend", "reason": "check it"]).error))
        // Left out, the suggestion is an hour.
        #expect(world.asked.first?.hours == 1)
        world.now += 3601
        let used = try AgentTests().call(bridge, "use_key", ["key": "resend", "command": ["curl"], "reason": "r"])
        #expect(used.error && used.text.contains("request_access"))
        #expect(world.logged.contains("refused resend closed again"))
        #expect(try AgentTests().call(bridge, "list_keys", [:]).text.contains("Closed, ask with request_access: pexels, resend"))
    }

    @Test func aNoSavesNothingAndTheAgentCannotKeepAsking() throws {
        let world = World()
        let bridge = bridge(world)
        let first = try request(bridge, ["key": "resend", "reason": "please"])
        #expect(first.error && first.text.contains("said no"))
        let second = try request(bridge, ["key": "resend", "reason": "please, again"])
        #expect(second.error && second.text.contains("already said no"))
        #expect(world.asked.count == 1 && world.saved == 0)
    }

    @Test func nothingIsAskedForAKeyThatIsMissingOpenOrBadlyAsked() throws {
        let world = World()
        world.policy = AgentPolicy(levels: ["pexels": .ask])
        let bridge = bridge(world)
        #expect(try request(bridge, ["key": "stripe", "reason": "x"]).error)
        #expect(try request(bridge, ["key": "resend", "reason": "x", "duration": "48h"]).error)
        #expect(try request(bridge, ["key": "resend", "reason": "x", "duration": "forever"]).error)
        #expect(try request(bridge, ["key": "resend"]).error)
        // A key open at Ask is asked about at use_key, where the person can say yes for hours.
        #expect(try request(bridge, ["key": "pexels", "reason": "x"]).text.contains("already open"))
        #expect(world.asked.isEmpty && world.saved == 0)
    }

    @Test func alwaysLeavesTheKeyFreeWithNoEnd() throws {
        let world = World()
        world.answers = [AccessDecision(hours: nil)]
        let bridge = bridge(world)
        let result = try request(bridge, ["key": "resend", "reason": "every day", "duration": "always"])
        #expect(result.text.contains("free, always"))
        #expect(world.asked.first?.hours == nil)
        #expect(world.policy.levels["resend"] == .free && world.policy.until["resend"] == nil)
        world.now += 30 * 86400
        #expect(!(try AgentTests().call(bridge, "use_key", ["key": "resend", "command": ["curl"], "reason": "r"]).error))
    }

    @Test func aKeyOpenToAnotherAgentIsNotReopenedOnNewTerms() throws {
        let world = World()
        let closes = world.now.addingTimeInterval(3600)
        world.policy = AgentPolicy(levels: ["resend": .free], agents: ["resend": ["claude"]], until: ["resend": closes])
        world.answers = [AccessDecision(hours: nil)]
        let asked = try request(bridge(world, agent: "codex"), ["key": "resend", "reason": "x", "duration": "always"])
        #expect(asked.error && asked.text.contains("other agents"))
        #expect(world.asked.isEmpty && world.saved == 0)
        #expect(world.policy.until["resend"] == closes && world.policy.agents["resend"] == ["claude"])
    }

    @Test func aYesForAKeyChangedWhileTheWindowWasOpenChangesNothing() throws {
        let world = World()
        // The person opens the key to codex in the app while claude's window waits.
        let bridge = AgentBridge(
            policy: { world.policy }, names: { ["resend"] }, open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            now: { world.now }, agent: "claude",
            decideAccess: { _ in
                world.policy = AgentPolicy(levels: ["resend": .ask], agents: ["resend": ["codex"]])
                return AccessDecision(hours: nil)
            },
            updatePolicy: { change in
                change(&world.policy)
                world.saved += 1
            })
        let result = try request(bridge, ["key": "resend", "reason": "x"])
        #expect(result.error && result.text.contains("changed while the person was asked"))
        #expect(world.policy.levels["resend"] == .ask && world.policy.agents["resend"] == ["codex"])
    }

    @Test func writersAtTheSameTimeKeepEveryChange() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("agents-\(UUID().uuidString).toml")
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(atPath: url.path + ".lock")
        }
        DispatchQueue.concurrentPerform(iterations: 30) { index in
            _ = try? AgentPolicy.update(at: url) { $0.levels["key-\(index)"] = .ask }
        }
        #expect(AgentPolicy.load(from: url).levels.count == 30)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
    }

    @Test func alwaysIsNeverChosenForThePerson() {
        #expect(AccessDecision.startingHours(for: nil) == 24)
        #expect(AccessDecision.startingHours(for: 4) == 4)
        #expect(AccessDecision.startingHours(for: 48) == 24)
    }

    @Test func untilIsWrittenAndReadBack() throws {
        let closes = Date(timeIntervalSince1970: 1_800_003_600)
        let policy = AgentPolicy(levels: ["resend": .ask], agents: ["resend": ["claude"]], until: ["resend": closes])
        let read = try AgentPolicy.parse(policy.toml)
        #expect(read == policy)
        #expect(read.level(of: "resend", at: closes.addingTimeInterval(-1)) == .ask)
        #expect(read.level(of: "resend", at: closes) == nil)
        #expect(throws: VaultError.self) { try AgentPolicy.parse("[[key]]\nkey = \"a\"\nuntil = \"tomorrow\"\n") }
    }
}
