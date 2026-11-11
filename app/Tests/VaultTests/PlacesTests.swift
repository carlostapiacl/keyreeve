import CryptoKit
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

    static func digestKey() throws -> DigestKey {
        let chip = SoftwareRecipient()
        return try DigestKey.derive(from: chip, tag: Age.TagRecipient(publicKey: chip.publicKey).string)
    }

    @Test func digestsTellTheValueNowFromAnEarlierOne() throws {
        let key = try Self.digestKey()
        var digests = ValueDigests()
        digests.learn(name: "lh.env", revision: "r1", value: Data("OPENAI_API_KEY=CANARY-one\nOTHER=x\n".utf8), key: key)
        let one = PlaceBook.sha256(Data("CANARY-one".utf8))
        let two = PlaceBook.sha256(Data("CANARY-two".utf8))
        let compare = { (hash: String, revision: String) in
            digests.compare(hash, name: "lh.env", field: "OPENAI_API_KEY", revision: revision, key: key)
        }
        #expect(compare(one, "r1") == .same)
        #expect(compare(two, "r1") == .different)
        // Each field is its own value: OTHER holds another.
        #expect(digests.compare(one, name: "lh.env", field: "OTHER", revision: "r1", key: key) == .different)
        // After a rotation the value now was never seen: no guess.
        #expect(compare(one, "r2") == .notCompared)
        digests.learn(name: "lh.env", revision: "r2", value: Data("OPENAI_API_KEY=CANARY-two\n".utf8), key: key)
        #expect(compare(one, "r2") == .old)
        #expect(compare(two.uppercased(), "r2") == .same)
        // A one-line file is its whole value.
        digests.learn(name: "plain.txt", revision: "p", value: Data("CANARY-one\n".utf8), key: key)
        #expect(digests.compare(one, name: "plain.txt", field: nil, revision: "p", key: key) == .same)
    }

    /// A value that holds `=` is never taken apart into a field whose name is part of the value: a base64 key with its
    /// padding, a private key, JSON. The file would hold the value in the clear.
    @Test func noPartOfAValueBecomesAFieldName() throws {
        let key = try Self.digestKey()
        let base64 = "CANARYbase64KeyOfFortyThreeCharactersLong00"
        let values = [
            "\(base64)=\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA=\nCANARY=x\n-----END OPENSSH PRIVATE KEY-----\n",
            "{\n  \"private_key\": \"CANARY-pem==\",\n  \"client_email\": \"a@b.c\"\n}\n",
            "a+b/c=CANARY\n",
        ]
        for value in values {
            let made = ValueDigests.digests(of: Data(value.utf8), key: key)
            #expect(made.keys.allSatisfy { $0.isEmpty }, "\(made.keys.sorted())")
        }
        // A file of NAME=value lines keeps its fields.
        #expect(Set(ValueDigests.digests(of: Data("API_KEY=CANARY\nmgmt_token=x\n".utf8), key: key).keys) == ["API_KEY", "mgmt_token"])
        #expect(ValueDigests.isFieldName("TELEGRAM_BOT_TOKEN") && !ValueDigests.isFieldName(base64) && !ValueDigests.isFieldName("a b"))
    }

    /// A file an earlier version wrote with such names is written again without them, the next time it is touched.
    @Test func anOlderFileLosesTheNamesThatAreNotNames() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("digests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let file = home.appendingPathComponent(ValueDigests.fileName)
        let leaked = "CANARYbase64KeyOfFortyThreeCharactersLong00"
        try "{\"entries\":{\"k\":{\"r\":{\"\":\"aa\",\"API\":\"bb\",\"\(leaked)\":\"cc\"}}},\"schema\":2}"
            .write(to: file, atomically: true, encoding: .utf8)
        #expect(ValueDigests.load(from: file).entries["k"]?["r"] == ["": "aa", "API": "bb"])
        try ValueDigests.update(at: file) { _ in }
        let text = try String(contentsOf: file, encoding: .utf8)
        #expect(!text.contains(leaked) && text.contains("API"))
    }

    @Test func theDigestsFileHoldsNoPlainHashAndIsUselessWithoutTheChipKey() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("digests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let file = home.appendingPathComponent(ValueDigests.fileName)
        let key = try Self.digestKey()
        let chip = SoftwareRecipient()
        var vault = VaultFile(enclave: chip.publicKey, recovery: Age.X25519Identity().recipient)
        let value = Data("OPENAI_API_KEY=\(Self.canary)\n".utf8)
        try vault.add(name: "lh.env", value: value)
        let revision = try #require(vault.entries["lh.env"]?.revision)
        let record = VaultEvents.recorder(store: VaultStore(directory: home.appendingPathComponent("vault")), file: file, key: { _ in key })
        record(vault, "lh.env", revision, value)
        let text = try String(contentsOf: file, encoding: .utf8)
        let plain = PlaceBook.sha256(Data(Self.canary.utf8))
        #expect(!text.contains(plain) && !text.contains(PlaceBook.sha256(value)) && !text.contains(Self.canary))
        let digests = ValueDigests.load(from: file)
        #expect(digests.compare(plain, name: "lh.env", field: "OPENAI_API_KEY", revision: revision, key: key) == .same)
        // Without the chip key there is nothing to compare with: not compared, never an error or a guess.
        #expect(digests.compare(plain, name: "lh.env", field: "OPENAI_API_KEY", revision: revision, key: nil) == .notCompared)
        // Another Mac's key makes other digests.
        #expect(digests.compare(plain, name: "lh.env", field: "OPENAI_API_KEY", revision: revision, key: try Self.digestKey()) == .different)
        // With no chip key, the recorder writes nothing.
        let other = home.appendingPathComponent("other.json")
        VaultEvents.recorder(store: VaultStore(directory: home.appendingPathComponent("vault")), file: other)(vault, "lh.env", revision, value)
        #expect(!FileManager.default.fileExists(atPath: other.path))
        // A file of plain hashes from before is dropped, never trusted.
        try Data(#"{"keys":{"lh.env":{"r":"\#(plain)"}}}"#.utf8).write(to: other)
        #expect(ValueDigests.load(from: other).entries.isEmpty)
    }

    @Test func theVaultLeavesADigestWhenItSealsAndWhenItOpens() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("digests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let file = home.appendingPathComponent(ValueDigests.fileName)
        let key = try Self.digestKey()
        let chip = SoftwareRecipient()
        var vault = VaultFile(enclave: chip.publicKey, recovery: Age.X25519Identity().recipient)
        let old = Data("CANARY-old-value\n".utf8)
        try vault.add(name: "before.txt", value: old)
        VaultEvents.observe(VaultEvents.recorder(store: VaultStore(directory: home), file: file, key: { _ in key }))
        defer { VaultEvents.observe(nil) }
        try vault.add(name: "sealed.txt", value: Data("CANARY-sealed\n".utf8))
        try vault.replace(name: "sealed.txt", value: Data("CANARY-put\n".utf8))
        var digests = ValueDigests.load(from: file)
        let put = try #require(vault.entries["sealed.txt"]?.revision)
        #expect(digests.compare(PlaceBook.sha256(Data("CANARY-put".utf8)), name: "sealed.txt", field: nil, revision: put, key: key) == .same)
        #expect(digests.compare(PlaceBook.sha256(Data("CANARY-sealed".utf8)), name: "sealed.txt", field: nil, revision: put, key: key) == .old)
        // Sealed before the recorder, it is filled in the first time it is opened.
        let before = try #require(vault.entries["before.txt"]?.revision)
        #expect(!digests.knows(name: "before.txt", revision: before))
        _ = try vault.open(name: "before.txt", with: chip)
        digests = ValueDigests.load(from: file)
        #expect(digests.compare(PlaceBook.sha256(Data("CANARY-old-value".utf8)), name: "before.txt", field: nil, revision: before, key: key) == .same)

        // One way in: an added key leaves its digest, a put over it waits under #pending with none, and the value
        // accepted leaves its own, with the one before as earlier. Batch use opens through the same open.
        let store = VaultStore(directory: home.appendingPathComponent("vault"))
        try store.create(VaultFile(enclave: chip.publicKey, recovery: Age.X25519Identity().recipient), blob: Data("blob".utf8))
        let index = home.appendingPathComponent(KeyIndex.fileName)
        let journal = home.appendingPathComponent("rotations.jsonl")
        _ = try KeyArrival.add(Data("CANARY-added\n".utf8), as: "added/mail", addedBy: "claude", store: store, index: index)
        let added = try #require(try store.load().entries["added/mail"]?.revision)
        digests = ValueDigests.load(from: file)
        #expect(digests.compare(PlaceBook.sha256(Data("CANARY-added".utf8)), name: "added/mail", field: nil, revision: added, key: key) == .same)
        let outcome = try KeyArrival.put(
            Data("CANARY-waiting\n".utf8), as: "added/mail", addedBy: "codex", byEngine: false, journal: journal, store: store, index: index)
        #expect(outcome == .waiting)
        #expect(ValueDigests.load(from: file).entries["added/mail#pending"] == nil, "a value that waits is not in force")
        try KeyArrival.accept("added/mail", with: chip, journal: journal, store: store)
        let accepted = try #require(try store.load().entries["added/mail"]?.revision)
        digests = ValueDigests.load(from: file)
        let waiting = PlaceBook.sha256(Data("CANARY-waiting".utf8))
        #expect(digests.compare(waiting, name: "added/mail", field: nil, revision: accepted, key: key) == .same)
        #expect(digests.compare(PlaceBook.sha256(Data("CANARY-added".utf8)), name: "added/mail", field: nil, revision: accepted, key: key) == .old)
    }

    /// On a Mac with a chip, the key is made from the chip key that needs no fingerprint, with no prompt, and is
    /// the same each time.
    @Test func theDigestKeyComesFromTheChipWithNoPrompt() throws {
        guard SecureEnclave.isAvailable else { return }
        guard let made = try? EnclaveRecipient.createUnattended() else { return }
        let tag = Age.TagRecipient(publicKey: made.recipient.publicKey).string
        let first = try DigestKey.derive(from: try EnclaveRecipient.loadUnattended(blob: made.blob), tag: tag)
        let second = try DigestKey.derive(from: try EnclaveRecipient.loadUnattended(blob: made.blob), tag: tag)
        let hash = PlaceBook.sha256(Data("CANARY".utf8))
        #expect(first.digest(ofHex: hash) == second.digest(ofHex: hash))
        #expect(first.digest(ofHex: hash) != (try Self.digestKey()).digest(ofHex: hash))
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
