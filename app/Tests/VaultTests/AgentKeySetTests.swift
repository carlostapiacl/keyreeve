import Foundation
import KeyreeveVault
import Testing

/// An agent asking for several keys with request_access: one window, one fingerprint, and nothing it can set itself.
struct AgentKeySetTests {
    final class World: @unchecked Sendable {
        var policy = AgentPolicy()
        var windows: [AccessBatch] = []
        var answer: AccessBatch.Answer?
        var logged: [String] = []
    }

    func bridge(_ world: World, _ f: SetFixture) -> AgentBridge {
        AgentBridge(
            policy: { world.policy }, names: { ["meta-ads", "calcom", "sentry"] },
            open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") },
            record: { _, _, _ in },
            approve: { _ in nil },
            now: { f.now },
            agent: "claude",
            service: { f.service.handle($0, caller: f.caller) },
            runPrepared: { _ in AgentBridge.Output(status: 0, text: "CANARY-free output") },
            log: { event, key, detail, _ in world.logged.append("\(event) \(key) \(detail)") },
            describe: { (try? KeyIndex.parse(SetFixture.index).agentDescriptions) ?? [:] },
            decideAccessMany: { batch in
                world.windows.append(batch)
                return world.answer
            },
            updatePolicy: { change in change(&world.policy) })
    }

    func ask(_ bridge: AgentBridge, _ keys: [String]) throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, "request_access", ["keys": keys, "reason": "weekly report", "duration": "4h"])
    }

    @Test func oneWindowAndOneFingerprintOpenEveryKeyLeftTicked() throws {
        let f = SetFixture()
        let world = World()
        world.answer = AccessBatch.Answer(keys: ["meta-ads", "sentry"], hours: 4)
        let bridge = bridge(world, f)
        let answer = try ask(bridge, ["meta-ads", "calcom", "sentry", "hidden"])
        #expect(!answer.error)
        #expect(world.windows.count == 1 && world.windows[0].items.map(\.key) == ["meta-ads", "calcom", "sentry"])
        #expect(world.windows[0].hours == 4)
        #expect(f.fingerprints.count == 1 && f.windows.isEmpty, "the agent's window was the question; the service only asks the finger")
        #expect(world.policy.levels == ["meta-ads": .free, "sentry": .free])
        #expect(world.policy.agents["meta-ads"] == ["claude"])
        #expect(world.policy.level(of: "calcom") == nil, "unticked stays closed")
        #expect(answer.text.contains("calcom: the person left it unticked"))
        #expect(answer.text.contains("hidden: no key by that name"))
        // The keys are open in the service too, so the next use_key asks nothing.
        let used = try AgentTests().call(bridge, "use_key", ["key": "sentry", "command": ["curl", "x"], "reason": "r"])
        #expect(!used.error && f.fingerprints.count == 1)
        // An unticked key is not asked for again in this session.
        let again = try ask(bridge, ["calcom"])
        #expect(again.text.contains("already said no") && world.windows.count == 1)
        #expect(!answer.text.contains("CANARY") && !used.text.contains("CANARY-meta"))
    }

    @Test func aClosedWindowOpensNothingAndChangesNothing() throws {
        let f = SetFixture()
        let world = World()
        let answer = try ask(bridge(world, f), ["meta-ads", "calcom"])
        #expect(answer.error && answer.text.contains("said no"))
        #expect(world.policy == AgentPolicy())
        #expect(f.fingerprints.isEmpty && f.granted.isEmpty)
    }

    @Test func noFingerprintOpensNothing() throws {
        let f = SetFixture()
        f.fingerRefused = true
        let world = World()
        world.answer = AccessBatch.Answer(keys: ["meta-ads", "calcom"], hours: 1)
        let answer = try ask(bridge(world, f), ["meta-ads", "calcom"])
        #expect(answer.error)
        #expect(world.policy == AgentPolicy() && f.granted.isEmpty)
    }

    /// No tool makes or changes a set, and a set an agent writes by hand still shows every key and asks the finger.
    @Test func anAgentCannotGrantItselfThroughASet() throws {
        let f = SetFixture()
        let world = World()
        let list = bridge(world, f).handle(#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#) ?? ""
        #expect(!list.contains("\"name\":\"key_set") && !list.contains("make_set") && !list.contains("save_set"))
        // A set written straight into the file grants nothing: the window and the finger still come.
        f.sets.sets = [KeySets.Set(name: "mine", keys: ["meta-ads", "calcom"])]
        f.answer = { _ in nil }
        let answer = f.service.handle(
            KeyService.Request(op: "use-many", program: "curl", agent: "claude", cwd: "/w", keys: ["meta-ads", "calcom"], set: "mine"),
            caller: f.caller)
        #expect(!answer.ok && f.windows.count == 1 && f.granted.isEmpty)
    }
}
