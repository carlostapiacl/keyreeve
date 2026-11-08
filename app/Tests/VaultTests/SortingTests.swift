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

    static let list = Data(#"""
        {"keys":[
         {"path":"done.txt","provider":"github","result":"works","sealed":true,"level":"ask","fields":[]},
         {"path":"loose.txt","result":"never_checked","sealed":false,"level":"ask","fields":[]},
         {"path":"pay.env","provider":"stripe","result":"never_checked","sealed":true,"level":"never","fields":["KEY"]},
         {"path":"panel.txt","provider":"coolify","result":"never_checked","sealed":false,"level":"ask","needs_host":true,"fields":[]},
         {"path":"old.txt","archived":true,"level":"ask","result":"rejected","sealed":false,"fields":[]}],
         "providers":[{"id":"github","name":"GitHub"},{"id":"stripe","name":"Stripe"},{"id":"coolify","name":"Coolify"}]}
        """#.utf8)

    func paths(_ data: Data?) throws -> [String] {
        let page = try #require(data)
        let object = try #require(try JSONSerialization.jsonObject(with: page) as? [String: Any])
        return (object["keys"] as? [[String: Any]] ?? []).compactMap { $0["path"] as? String }
    }

    @Test func theInventoryShowsWhatIsPendingInPages() throws {
        #expect(try paths(AgentSorting.page(Self.list, pending: true, matching: nil, offset: 0, limit: 60)) == ["loose.txt", "pay.env", "panel.txt"])
        #expect(try paths(AgentSorting.page(Self.list, pending: false, matching: nil, offset: 0, limit: 60)).count == 5)
        #expect(try paths(AgentSorting.page(Self.list, pending: false, matching: "PAN", offset: 0, limit: 60)) == ["panel.txt"])
        let first = try #require(AgentSorting.page(Self.list, pending: true, matching: nil, offset: 0, limit: 2))
        let object = try #require(try JSONSerialization.jsonObject(with: first) as? [String: Any])
        #expect(object["next_offset"] as? Int == 2 && object["matching"] as? Int == 3 && object["total"] as? Int == 5)
        #expect(try paths(AgentSorting.page(Self.list, pending: true, matching: nil, offset: 2, limit: 2)) == ["panel.txt"])
    }

    @Test func whatWillNotHappenIsSaidAtOnce() {
        let notes = AgentSorting.notes(for: [
            ["path": "pay.env", "check": true],
            ["path": "panel.txt", "check": true],
            ["path": "panel.txt", "check": true, "host": "https://panel.example.com"],
            ["path": "loose.txt", "kind": "provider", "provider": "nobody", "field": "X", "check": true],
            ["path": "done.txt", "host": "http://plain.example.com"],
            ["path": "done.txt", "host": "panel.example.com"],
            ["path": "done.txt", "expires": "next week"],
            ["path": "done.txt", "expires": "2026-12-31"],
        ], inventory: Self.list)
        #expect(notes.contains { $0.hasPrefix("pay.env: set to Only me") })
        #expect(notes.filter { $0.hasPrefix("panel.txt: its provider runs on the person's own server") }.count == 1)
        #expect(notes.contains { $0.hasPrefix("loose.txt: no provider nobody") })
        #expect(notes.contains { $0.hasPrefix("loose.txt: the file has no field X") })
        #expect(notes.filter { $0.hasPrefix("done.txt: host is reached over https only") }.count == 1)
        #expect(notes.filter { $0.hasPrefix("done.txt: expires must be a day") }.count == 1)
    }
}

