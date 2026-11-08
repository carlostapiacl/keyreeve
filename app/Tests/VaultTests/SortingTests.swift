import Foundation
import KeyreeveVault
import Testing

/// An agent sorting the whole folder: it reads the list the app publishes, and leaves proposals.
struct SortingTests {
    final class World: @unchecked Sendable {
        var inventory: Data? = Data(#"{"keys":[{"path":"a.txt"},{"path":"b.env"}],"providers":[]}"#.utf8)
        var entries: [AccessRequests.Entry] = []
        var saved: [String: Data] = [:]
        var answer = AgentBridge.Announcement.later
    }

    func bridge(_ world: World) -> AgentBridge {
        AgentBridge(
            policy: { AgentPolicy() }, names: { [] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            requests: { world.entries }, addRequest: { world.entries.append($0) }, announce: { _ in world.answer },
            inventory: { world.inventory }, saveProposal: { world.saved[$0] = $1 })
    }

    func propose(_ bridge: AgentBridge, _ changes: Any) throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, "propose", ["reason": "sort the folder", "changes": changes])
    }

    @Test func nothingIsListedOrProposedUntilThePersonLetsAgentsSort() throws {
        let world = World()
        world.inventory = nil
        let bridge = bridge(world)
        let list = try AgentTests().call(bridge, "inventory", [:])
        #expect(list.error && list.text.contains("Agents can sort my keys"))
        #expect(try propose(bridge, [["path": "a.txt", "kind": "public"]]).error)
        #expect(world.entries.isEmpty && world.saved.isEmpty)
    }

    @Test func aProposalIsKeptWholeAndWaitsForThePerson() throws {
        let world = World()
        let bridge = bridge(world)
        #expect(try AgentTests().call(bridge, "inventory", [:]).text.contains("a.txt"))
        let first = try propose(bridge, [["path": "a.txt", "kind": "public", "what": "An account id"], ["path": "b.env", "check": true]])
        #expect(!first.error && first.text.hasPrefix("2 changes are waiting"))
        let asked = try #require(world.entries.first)
        #expect(asked.kind == "sort" && asked.reason == "sort the folder" && world.saved[asked.id] != nil)
        // One list at a time.
        #expect(try propose(bridge, [["path": "a.txt", "kind": "internal"]]).text.hasPrefix("Still waiting"))
        #expect(world.entries.count == 1)
        // Once answered, the next one is kept.
        world.entries.append(AccessRequests.Entry(id: asked.id, at: Date(), event: .allowed, agent: "claude", provider: "keyreeve", kind: "sort"))
        #expect(try propose(bridge, [["path": "a.txt", "kind": "internal"]]).text.hasPrefix("1 changes"))
    }

    @Test func aProposalNamingAFileNotListedOrShapedWrongIsRefusedWhole() throws {
        let world = World()
        let bridge = bridge(world)
        #expect(try propose(bridge, [["path": "a.txt"], ["path": "../etc/passwd"]]).error)
        #expect(try propose(bridge, ["a.txt"]).error)
        #expect(try propose(bridge, [[String: Any]]()).error)
        #expect(try propose(bridge, Array(repeating: ["path": "a.txt"], count: AgentSorting.maxChanges + 1)).error)
        #expect(world.entries.isEmpty && world.saved.isEmpty)
    }

    @Test func aNoIsKept() throws {
        let world = World()
        world.answer = .deny
        #expect(try propose(bridge(world), [["path": "a.txt", "kind": "public"]]).error)
        #expect(world.entries.map(\.event) == [.asked, .declined])
    }

    @Test func onlyKeyreevesOwnProposalNamesAreRead() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("sorting-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        try AgentSorting.save(Data("[]".utf8), id: "r-abc", home: home)
        #expect(AgentSorting.load(id: "r-abc", home: home) == Data("[]".utf8))
        #expect(AgentSorting.load(id: "../r-abc", home: home) == nil)
        #expect(AgentSorting.load(id: "abc", home: home) == nil)
    }
}
