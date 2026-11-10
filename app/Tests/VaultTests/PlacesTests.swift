import Foundation
import KeyreeveVault
import Testing

/// Where keys live: agents list and propose places, and the person approves them. No value, and no hash of one,
/// ever reaches an agent.
struct PlacesTests {
    static let canary = "CANARY-sk-live-0123456789"

    final class World: @unchecked Sendable {
        var entries: [AccessRequests.Entry] = []
        var saved: [String: Data] = [:]
        var answer = AgentBridge.Announcement.later
        var opened = 0
        var book = PlaceBook()
        var logged: [String] = []
    }

    static func key(_ id: String) -> KeyIndex.Key { KeyIndex.Key(id: id, source: id + ".env", field: "TOKEN", provider: "openai") }

    func bridge(_ world: World, offered: [String] = ["openai-lh"], folder: URL? = nil) -> AgentBridge {
        var bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { offered },
            open: { _, _ in
                world.opened += 1
                return Data(Self.canary.utf8)
            },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            log: { event, key, detail, reason in world.logged.append([event, key, detail, reason ?? ""].joined(separator: " ")) },
            describe: { Dictionary(uniqueKeysWithValues: offered.map { ($0, Self.key($0)) }) },
            requests: { world.entries }, addRequest: { world.entries.append($0) }, announce: { _ in world.answer },
            saveProposal: { world.saved[$0] = $1 })
        bridge.places = { world.book }
        bridge.proceduresFolder = folder
        return bridge
    }

    func call(_ bridge: AgentBridge, _ name: String, _ arguments: [String: Any]) throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, name, arguments)
    }

    static let place: [String: Any] = [
        "key": "openai-lh", "procedure": "ssh-env",
        "params": ["host": "vps2", "file": "/opt/lh/.env", "variable": "OPENAI_API_KEY"],
        "label": "VPS2 · /opt/lh/.env · OPENAI_API_KEY", "why": "the env file names OPENAI_API_KEY",
    ]

    @Test func aProposalAddsNothingAndWaitsForThePerson() throws {
        let world = World()
        let bridge = bridge(world)
        let answer = try call(bridge, "propose_places", ["reason": "found on the servers", "places": [Self.place]])
        #expect(!answer.error && answer.text.hasPrefix("1 places are waiting"))
        let asked = try #require(world.entries.first)
        #expect(asked.kind == "places" && asked.event == .asked)
        let kept = AgentBridge.proposedPlaces(try #require(world.saved[asked.id]))
        #expect(kept.count == 1 && kept[0].sha256 == nil && kept[0].approved == nil && kept[0].by == "claude")
        // Nothing reached the book, and no key was opened.
        #expect(world.book.places.isEmpty && world.opened == 0)
        // One list at a time.
        #expect(try call(bridge, "propose_places", ["reason": "again", "places": [Self.place]]).text.hasPrefix("Still waiting"))
        #expect(world.entries.count == 1)
    }

    @Test func declinedAtOnceKeepsNothing() throws {
        let world = World()
        world.answer = .deny
        let answer = try call(bridge(world), "propose_places", ["reason": "found", "places": [Self.place]])
        #expect(answer.error)
        #expect(world.entries.map(\.event) == [.asked, .declined])
        #expect(world.book.places.isEmpty && world.opened == 0)
    }

    @Test func aProposalForAKeyNotOfferedOrShapedWrongIsRefusedWhole() throws {
        let world = World()
        let bridge = bridge(world)
        var hidden = Self.place
        hidden["key"] = "not-offered"
        #expect(try call(bridge, "propose_places", ["reason": "r", "places": [Self.place, hidden]]).error)
        for (field, value) in [
            ("procedure", "../evil" as Any), ("procedure", "Ssh"), ("label", ""), ("label", "two\nlines"),
            ("params", ["Host": "x"]), ("params", ["host": "a\nb"]), ("params", ["host": 3]),
        ] {
            var bad = Self.place
            bad[field] = value
            #expect(try call(bridge, "propose_places", ["reason": "r", "places": [bad]]).error, "\(field)")
        }
        #expect(try call(bridge, "propose_places", ["reason": "r", "places": [String]()]).error)
        #expect(world.entries.isEmpty && world.saved.isEmpty)
    }

    @Test func listPlacesHidesThePlacesOfKeysNotOffered() throws {
        let world = World()
        world.book = PlaceBook(places: [
            PlaceBook.Place(
                key: "openai-lh", procedure: "ssh-env", params: ["host": "vps2"], label: "VPS2 · OPENAI_API_KEY",
                sha256: "ab", lastCheck: PlaceBook.Check(at: Date(timeIntervalSince1970: 0), result: .old)),
            PlaceBook.Place(key: "secret-thing", procedure: "github-secret", params: ["repo": "me/hidden-repo"], label: "hidden-label"),
            PlaceBook.Place(key: "secret-thing", procedure: "ssh-env", params: [:], label: "hidden-label-2"),
        ])
        let bridge = bridge(world)
        let all = try call(bridge, "list_places", [:])
        #expect(!all.error)
        #expect(all.text.contains("VPS2 · OPENAI_API_KEY") && all.text.contains("approved") && all.text.contains("earlier value"))
        #expect(!all.text.contains("secret-thing") && !all.text.contains("hidden"))
        #expect(all.text.contains("2 more places belong to keys not offered to agents"))
        // Asked by name, a key not offered answers as one that is not there.
        let hidden = try call(bridge, "list_places", ["key": "secret-thing"])
        #expect(hidden.error && !hidden.text.contains("hidden-label"))
        let one = try call(bridge, "list_places", ["key": "openai-lh"])
        #expect(!one.error && one.text.contains("VPS2"))
    }

    @Test func noValueOrHashReachesAnAgentOrTheLog() throws {
        let world = World()
        let digest = PlaceBook.sha256(Data(Self.canary.utf8))
        world.book = PlaceBook(places: [
            PlaceBook.Place(
                key: "openai-lh", procedure: "ssh-env", params: ["host": "vps2"], label: "VPS2", sha256: "ab",
                lastCheck: PlaceBook.Check(at: Date(), result: .same))
        ])
        let bridge = bridge(world)
        let listed = try call(bridge, "list_places", [:])
        _ = try call(bridge, "propose_places", ["reason": "found", "places": [Self.place]])
        let proposal = String(decoding: world.saved.values.first ?? Data(), as: UTF8.self)
        for text in [listed.text, proposal, world.logged.joined(separator: "\n")] {
            #expect(!text.contains(Self.canary) && !text.contains(digest))
        }
        #expect(world.opened == 0)
        // A check result kept in the book is a word, never the hash.
        let encoded = String(decoding: try JSONEncoder().encode(world.book), as: UTF8.self)
        #expect(!encoded.contains(digest))
    }

    @Test func aProcedureThatIsNotThereIsNamedToTheAgent() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("procedures-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let world = World()
        var mine = Self.place
        mine["procedure"] = "my-deploy"
        let answer = try call(bridge(world, folder: folder), "propose_places", ["reason": "r", "places": [mine]])
        #expect(!answer.error && answer.text.contains("my-deploy is not a procedure yet"))
    }

    @Test func approvingPinsEachPlaceAndAChangedProcedureNeedsApprovalAgain() throws {
        var book = PlaceBook()
        let proposed = [
            PlaceBook.Place(key: "a", procedure: "ssh-env", params: ["host": "vps2"], label: "one", by: "claude"),
            PlaceBook.Place(key: "b", procedure: "unknown", params: [:], label: "two", by: "claude"),
        ]
        #expect(book.approve(proposed, pins: ["ssh-env": "aa"], at: Date()) == 1)
        #expect(book.places.count == 1 && book.places[0].sha256 == "aa")
        #expect(PlaceBook.status(of: book.places[0], currentPin: "aa") == .approved)
        #expect(PlaceBook.status(of: book.places[0], currentPin: "bb") == .changed)
        #expect(PlaceBook.status(of: book.places[0], currentPin: nil) == .missing)
        #expect(PlaceBook.status(of: proposed[1], currentPin: "aa") == .waiting)
        // The same place again is approved again, not added twice.
        #expect(book.approve([proposed[0]], pins: ["ssh-env": "bb"], at: Date()) == 1)
        #expect(book.places.count == 1 && book.places[0].sha256 == "bb")
    }

    @Test func aFolderProcedureIsHashedAndCannotTakeABuiltinName() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("procedures-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try Data("#!/bin/sh\necho absent\n".utf8).write(to: folder.appendingPathComponent("mine.sh"))
        try Data("#!/bin/sh\n".utf8).write(to: folder.appendingPathComponent("ssh-env.sh"))
        #expect(PlaceBook.folderProcedure("mine", in: folder) != nil)
        #expect(PlaceBook.folderProcedure("ssh-env", in: folder) == nil)
        #expect(PlaceBook.folderProcedure("../mine", in: folder) == nil)
        #expect(PlaceBook.procedureExists("ssh-env", in: folder) && !PlaceBook.procedureExists("nope", in: folder))
    }

    /// The names the app knows ship as files in the repository's `procedures` folder.
    @Test func theBuiltinNamesAreTheFilesThatShip() throws {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let files = try FileManager.default.contentsOfDirectory(atPath: repository.appendingPathComponent("procedures").path)
        #expect(files.filter { $0.hasSuffix(".sh") }.map { String($0.dropLast(3)) }.sorted() == PlaceBook.builtinProcedures.sorted())
    }

    @Test func digestsTellTheValueNowFromAnEarlierOne() {
        var digests = ValueDigests()
        digests.learn(key: "k", revision: "r1", value: "CANARY-one")
        let one = PlaceBook.sha256(Data("CANARY-one".utf8))
        let two = PlaceBook.sha256(Data("CANARY-two".utf8))
        #expect(digests.compare(one, key: "k", revision: "r1") == .same)
        #expect(digests.compare(two, key: "k", revision: "r1") == .different)
        // After a rotation the value now was never opened: no fingerprint, no guess.
        #expect(digests.compare(one, key: "k", revision: "r2") == .notCompared)
        digests.learn(key: "k", revision: "r2", value: "CANARY-two")
        #expect(digests.compare(one, key: "k", revision: "r2") == .old)
        #expect(digests.compare(two.uppercased(), key: "k", revision: "r2") == .same)
        #expect(digests.compare(one, key: "other", revision: "r1") == .notCompared)
    }

    @Test func aDamagedBookIsNeverWrittenOver() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("places-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let file = PlaceBook.file(home: home)
        try PlaceBook.update(at: file) { $0.places.append(PlaceBook.Place(key: "a", procedure: "ssh-env", params: [:], label: "x")) }
        #expect(PlaceBook.load(from: file).places.count == 1)
        let damaged = Data("{ not json".utf8)
        try damaged.write(to: file)
        #expect(throws: VaultError.self) { try PlaceBook.update(at: file) { $0.places.removeAll() } }
        #expect(try Data(contentsOf: file) == damaged)
        #expect(PlaceBook.load(from: file).places.isEmpty)
    }
}
