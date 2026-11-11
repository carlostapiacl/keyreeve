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

    @Test func theAccountTheAgentNamesIsKeptWithTheRequest() throws {
        let world = World()
        _ = try AgentTests().call(
            bridge(world), "request_access",
            ["key": "resend", "reason": "r", "account": "  acme\n<b>  "])
        #expect(world.entries.first?.account == "acme <b>")
        // An older line with no account still reads.
        let line = #"{"agent":"claude","at":"2026-11-08T00:00:00Z","event":"asked","id":"r-1","provider":"sentry"}"#
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("requests-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: file) }
        try (line + "\n").write(to: file, atomically: true, encoding: .utf8)
        #expect(AccessRequests.read(from: file).first?.account == nil)
    }

    @Test func anAgentAsksToRotateAKeyAndLearnsHowItWentWithoutSeeingIt() throws {
        let world = World()
        let bridge = bridge(world)
        let rotate = { try AgentTests().call(bridge, "rotate_key", ["key": "pexels", "reason": "it leaked"]) }
        #expect(try rotate().text.hasPrefix("Waiting"))
        let asked = try #require(world.entries.first)
        #expect(asked.isRotation && asked.key == "pexels" && asked.reason == "it leaked" && world.announced == 1)
        #expect(try rotate().text.hasPrefix("Still waiting") && world.announced == 1)
        // A rotation request is not a request for a provider's key.
        #expect(AccessRequests.latest(agent: "claude", provider: asked.provider, in: world.entries) == nil)
        world.entries.append(AccessRequests.Entry(
            id: asked.id, at: world.now, event: .allowed, agent: "claude", provider: asked.provider, key: "pexels",
            kind: "rotate", result: "completed. Rotated. The old key is revoked."))
        #expect(try rotate().text == "The person rotated pexels. How it went: completed. Rotated. The old key is revoked.")
        #expect(try AgentTests().call(bridge, "rotate_key", ["key": "nope", "reason": "r"]).error)
        #expect(try AgentTests().call(bridge, "rotate_key", ["key": "pexels"]).error)
    }

    @Test func aRotationThatDidNotFinishIsSaidOnceAndAskedAgain() throws {
        let world = World()
        let bridge = bridge(world)
        _ = try AgentTests().call(bridge, "rotate_key", ["key": "pexels", "reason": "it leaked"])
        let asked = try #require(world.entries.first)
        world.entries.append(AccessRequests.Entry(
            id: asked.id, at: world.now, event: .allowed, agent: "claude", provider: asked.provider, key: "pexels",
            kind: "rotate", result: "rolled_back. Nothing changed"))
        let again = try AgentTests().call(bridge, "rotate_key", ["key": "pexels", "reason": "try again"]).text
        #expect(again.hasPrefix("The last try did not finish: rolled_back. Nothing changed. A new request is waiting."))
        #expect(world.entries.filter { $0.event == .asked }.count == 2 && world.announced == 2)
        #expect(try AgentTests().call(bridge, "rotate_key", ["key": "pexels", "reason": "r"]).text.hasPrefix("Still waiting"))
    }

    @Test func aNoToARotationIsKeptAndTheAgentStops() throws {
        let world = World()
        world.answer = .deny
        let bridge = bridge(world)
        #expect(try AgentTests().call(bridge, "rotate_key", ["key": "pexels", "reason": "old"]).error)
        #expect(world.entries.map(\.event) == [.asked, .declined] && world.entries.allSatisfy(\.isRotation))
        world.answer = .later
        #expect(try AgentTests().call(bridge, "rotate_key", ["key": "pexels", "reason": "old"]).error)
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

    @Test func aProviderWithASavedKeyIsAskedForByThatKey() throws {
        let world = World()
        let bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { ["resend-work"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            describe: { ["resend-work": KeyIndex.Key(id: "resend-work", source: "r.txt", provider: "resend")] },
            offered: { ["resend", "openai"] }, requests: { world.entries }, addRequest: { world.entries.append($0) })
        let text = try AgentTests().call(bridge, "list_keys", [:]).text
        #expect(text.contains("Closed, ask with request_access: resend-work (resend)"))
        #expect(text.hasSuffix("Not saved yet, ask with request_access by provider: openai"))
    }

    /// A key of the same provider for another account is another key: pointed to it, or asked for as new.
    @Test func anotherAccountOfASavedProviderIsAnotherKey() throws {
        let world = World()
        let keys = [
            "meta": KeyIndex.Key(id: "meta", source: "m.txt", provider: "meta", account: "acme"),
            "meta-globex": KeyIndex.Key(id: "meta-globex", source: "a.txt", provider: "meta", account: "globex"),
        ]
        let bridge = AgentBridge(
            policy: { AgentPolicy(levels: ["meta": .free]) }, names: { ["meta", "meta-globex"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude", describe: { keys },
            offered: { ["meta"] }, requests: { world.entries }, addRequest: { world.entries.append($0) })
        let ask = { (account: String) in
            try AgentTests().call(bridge, "request_access", ["key": "meta", "reason": "insights", "account": account]).text
        }
        #expect(try ask("globex").contains("is meta-globex, not meta"))
        #expect(world.entries.isEmpty)
        #expect(try ask("initech").hasPrefix("Waiting: no meta key is saved yet"))
        #expect(world.entries.last?.account == "initech" && world.entries.last?.provider == "meta")
        // The same account as the key by that name is that key.
        #expect(try ask("acme").contains("already open"))
    }

    /// An agent may ask for a key to need no fingerprint; the person decides in a window that starts on no, gives
    /// their finger to seal the copy, and the key keeps the agents it was open to.
    @Test func noFingerprintIsAskedAndThePersonDecides() throws {
        final class Box: @unchecked Sendable {
            var policy = AgentPolicy(levels: ["bot": .free], agents: ["bot": ["nightly-bot", "claude"]])
            var answer = false
            var marked: [String] = []
            var failSeal = false
        }
        let box = Box()
        let bridge = AgentBridge(
            policy: { box.policy }, names: { ["bot", "other"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude", updatePolicy: { change in change(&box.policy) },
            decideNoFingerprint: { _ in box.answer },
            markUnattended: { key, _ in
                if box.failSeal { throw VaultError("no finger") }
                box.marked.append(key)
            })
        let ask = { (key: String) in
            try AgentTests().call(bridge, "request_access", ["key": key, "reason": "the bot polls all day", "duration": "no-fingerprint"])
        }
        // A no changes nothing, and is not asked again in this session.
        #expect(try ask("bot").error)
        #expect(box.policy.levels["bot"] == .free && box.marked.isEmpty)
        #expect(try ask("bot").text.contains("already said no"))
        // A finger not given changes nothing either.
        let other = AgentBridge(
            policy: { box.policy }, names: { ["bot"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude", updatePolicy: { change in change(&box.policy) },
            decideNoFingerprint: { _ in true }, markUnattended: { _, _ in throw VaultError("no finger") })
        #expect(try AgentTests().call(other, "request_access", ["key": "bot", "reason": "r", "duration": "no-fingerprint"]).error)
        #expect(box.policy.levels["bot"] == .free)
        // A yes with the finger: always, sealed, and the agents it had stay.
        let fresh = AgentBridge(
            policy: { box.policy }, names: { ["bot"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude", updatePolicy: { change in change(&box.policy) },
            decideNoFingerprint: { _ in true }, markUnattended: { key, _ in box.marked.append(key) })
        #expect(!(try AgentTests().call(fresh, "request_access", ["key": "bot", "reason": "r", "duration": "no-fingerprint"]).error))
        #expect(box.policy.levels["bot"] == .always && box.marked == ["bot"])
        #expect(box.policy.agents["bot"] == ["nightly-bot", "claude"])
        #expect(try AgentTests().call(fresh, "request_access", ["key": "bot", "reason": "r", "duration": "no-fingerprint"]).text.contains("already needs no fingerprint"))
    }

    /// Keys not offered to agents stay out of list_keys, unless the person shows their names with a fingerprint: names,
    /// providers and descriptions, for an hour, and each listing is logged.
    @Test func everyNameIsShownOnlyAfterTheFinger() throws {
        final class Box: @unchecked Sendable {
            var asked: [String] = []
            var answer = true
            var logged: [String] = []
        }
        let box = Box()
        var personal = KeyIndex.Key(id: "bank-login", source: "bank.txt", provider: "bank", account: "me", description: "Login del banco")
        personal.more.reviewed = true
        var old = KeyIndex.Key(id: "old-token", source: "old.txt")
        old.more.archived = true
        let offered = KeyIndex.Key(id: "netlify", source: "n.txt", provider: "netlify")
        let make = {
            AgentBridge(
                policy: { AgentPolicy(levels: ["netlify": .free]) }, names: { ["netlify"] },
                open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
                agent: "claude", log: { event, _, _, _ in box.logged.append(event) },
                describe: { ["netlify": offered] },
                everyKey: { [offered, personal, old] },
                allowEveryName: { who, why in
                    box.asked.append(who + ": " + why)
                    return box.answer
                })
        }
        let bridge = make()
        let plain = try AgentTests().call(bridge, "list_keys", [:]).text
        #expect(!plain.contains("bank-login") && plain.contains("list_keys with all"))
        #expect(box.asked.isEmpty)
        #expect(try AgentTests().call(bridge, "list_keys", ["all": true]).error)
        let all = try AgentTests().call(bridge, "list_keys", ["all": true, "reason": "find the bank key"]).text
        #expect(all.contains("bank-login (bank, me) \u{201C}Login del banco\u{201D}") && all.contains("Archived: old-token"))
        #expect(box.asked == ["claude: find the bank key"] && box.logged == ["listed"])
        // One yes covers the hour: no second prompt, and the listing is logged again.
        _ = try AgentTests().call(bridge, "list_keys", ["all": true, "reason": "again"])
        #expect(box.asked.count == 1 && box.logged == ["listed", "listed"])
        // A no shows nothing and is not asked again in the session.
        box.answer = false
        let other = make()
        #expect(try AgentTests().call(other, "list_keys", ["all": true, "reason": "r"]).error)
        #expect(try AgentTests().call(other, "list_keys", ["all": true, "reason": "r"]).text.contains("already said no"))
        #expect(box.asked.count == 2)
    }

    /// A server older than the Keyreeve in place changes no permission, and the agent hears why.
    @Test func anOutdatedServerChangesNoPermission() throws {
        final class Box: @unchecked Sendable { var policy = AgentPolicy(levels: ["kept": .free]) }
        let box = Box()
        let bridge = AgentBridge(
            policy: { box.policy }, names: { ["kept", "asked"] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude", decideAccess: { _ in AccessDecision(hours: 1) },
            updatePolicy: { _ in throw VaultError(AgentBridge.outdated) })
        let answer = try AgentTests().call(bridge, "request_access", ["key": "asked", "reason": "r"])
        #expect(answer.error && answer.text.contains("start the session again"))
        #expect(box.policy.levels == ["kept": .free])
    }

    @Test func requestsWrittenAtTheSameTimeAreAllKept() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("requests-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        DispatchQueue.concurrentPerform(iterations: 50) { index in
            try? AccessRequests.append(
                .init(id: "r-\(index)", at: at, event: .asked, agent: "claude", provider: "resend", reason: String(repeating: "x", count: 150)),
                to: url)
        }
        #expect(AccessRequests.read(from: url).count == 50)
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
