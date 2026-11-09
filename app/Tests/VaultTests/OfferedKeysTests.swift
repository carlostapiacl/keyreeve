import Foundation
import KeyreeveVault
import Testing

/// Identifiers given in bulk wait, not offered: agents do not see them until a person offers one.
struct OfferedKeysTests {
    final class World: @unchecked Sendable {
        var index = KeyIndex()
        var policy = AgentPolicy()
        var asked: [AccessRequest] = []
    }

    /// A bridge that reads the keys as the vault's agent server does, from the same helpers.
    func bridge(_ world: World, sealed: Set<String>) -> AgentBridge {
        AgentBridge(
            policy: { world.policy }, names: { world.index.agentNames(sealed: sealed) },
            open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") },
            record: { _, _, _ in },
            approve: { _ in .once },
            agent: "claude",
            service: { _ in KeyService.Response(ok: false, error: "no key") },
            describe: { world.index.agentDescriptions },
            decideAccess: { request in
                world.asked.append(request)
                return nil
            },
            updatePolicy: { change in change(&world.policy) })
    }

    /// One key a person offered, and two given identifiers in bulk, as "Give them identifiers" does.
    func world() throws -> World {
        let world = World()
        try world.index.add(KeyIndex.Key(id: "resend", source: "resend.txt", provider: "resend"))
        try world.index.addUnoffered(KeyIndex.Key(id: "bank-login", source: "bank.txt", provider: "bank", account: "me"))
        try world.index.addUnoffered(KeyIndex.Key(id: "root-password", source: "root.txt"))
        return world
    }

    let sealed: Set<String> = ["resend.txt", "bank.txt", "root.txt"]

    @Test func keysGivenIdentifiersInBulkAreNotListed() throws {
        let world = try world()
        let text = try AgentTests().call(bridge(world, sealed: sealed), "list_keys", [:]).text
        #expect(text == "No key is allowed for agents yet.\nClosed, ask with request_access: resend (resend)")
        #expect(!text.contains("bank"))
        #expect(!text.contains("root"))
    }

    @Test func askingForOneAnswersAsForANameThatIsNotThere() throws {
        let world = try world()
        let agents = bridge(world, sealed: sealed)
        let waiting = try AgentTests().call(agents, "request_access", ["key": "root-password", "reason": "deploy"])
        let unknown = try AgentTests().call(agents, "request_access", ["key": "no-such-key", "reason": "deploy"])
        #expect(waiting.error && unknown.error)
        #expect(waiting.text == unknown.text.replacingOccurrences(of: "no-such-key", with: "root-password"))
        #expect(world.asked.isEmpty, "the person is never asked about a key agents cannot see")
        #expect(world.policy == AgentPolicy())
    }

    @Test func usingOneAnswersAsForANameThatIsNotThere() throws {
        let world = try world()
        // Even with a level left over from before, a key not offered is not one agents can use.
        world.policy = AgentPolicy(levels: ["root-password": .free, "no-such-key": .free])
        let agents = bridge(world, sealed: sealed)
        func use(_ key: String) throws -> (text: String, error: Bool) {
            try AgentTests().call(agents, "use_key", ["key": key, "command": ["true"], "reason": "deploy"])
        }
        let waiting = try use("root-password")
        let unknown = try use("no-such-key")
        #expect(waiting.error && unknown.error)
        #expect(waiting.text == unknown.text.replacingOccurrences(of: "no-such-key", with: "root-password"))
        let listed = try AgentTests().call(agents, "list_keys", [:]).text
        #expect(!listed.contains("root-password"))
    }

    @Test func offeringOneListsItAsClosed() throws {
        let world = try world()
        world.index.offer(id: "bank-login")
        let text = try AgentTests().call(bridge(world, sealed: sealed), "list_keys", [:]).text
        #expect(text.hasSuffix("Closed, ask with request_access: bank-login (bank, me), resend (resend)"))
        #expect(!text.contains("root-password"))
        world.index.withdraw(id: "bank-login")
        #expect(!(try AgentTests().call(bridge(world, sealed: sealed), "list_keys", [:]).text.contains("bank")))
    }

    @Test func theFileKeepsWhatWasNotOffered() throws {
        let world = try world()
        let text = world.index.toml
        #expect(text.components(separatedBy: "offered = false").count == 3)
        let read = try KeyIndex.parse(text)
        #expect(read.keys.map(\.id) == ["resend"])
        #expect(read.unoffered.map(\.id) == ["bank-login", "root-password"])
        #expect(read == world.index)
        // A bulk identifier is never one a waiting key already has.
        #expect(throws: VaultError.self) { try world.index.addUnoffered(KeyIndex.Key(id: "resend", source: "x.txt")) }
        var removed = world.index
        removed.remove(id: "root-password")
        #expect(removed.unoffered.map(\.id) == ["bank-login"])
    }
}
