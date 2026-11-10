import Foundation
import Testing

@testable import KeyreeveVault

/// One way in: every key that goes into the vault leaves a record no agent sees, and a new value for a key that
/// is there waits for the person.
struct ArrivalTests {
    let chip = SoftwareRecipient()
    let recovery = Age.X25519Identity()
    let canary = Data("CANARY-arrival-value".utf8)
    let newer = Data("CANARY-newer-value".utf8)

    /// A home of its own for each test, with a vault sealed to a key in memory.
    func home() throws -> (home: URL, store: VaultStore, index: URL, journal: URL) {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("arrival-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let store = VaultStore(directory: home.appendingPathComponent("vault"))
        try store.create(VaultFile(enclave: chip.publicKey, recovery: recovery.recipient), blob: Data("blob".utf8))
        return (home, store, home.appendingPathComponent(KeyIndex.fileName), home.appendingPathComponent("rotations.jsonl"))
    }

    @Test func anAddedKeyGetsARecordNoAgentSees() throws {
        let (home, store, index, _) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        let key = try KeyArrival.add(
            canary, as: "added/OpenAI prod", addedBy: "claude", description: "OpenAI, production", tags: ["work", " "],
            store: store, index: index)
        #expect(key.id == "openai-prod")
        let read = try KeyIndex.load(from: index)
        #expect(read.keys.isEmpty)
        let record = try #require(read.unoffered.first)
        #expect(record.source == "added/OpenAI prod")
        #expect(record.more.addedBy == "claude")
        #expect(record.more.addedAt != nil)
        #expect(record.more.reviewed == false)
        #expect(record.description == "OpenAI, production")
        #expect(record.more.tags == ["work"])
        let sealed = Set(try store.load().entries.keys)
        #expect(read.agentNames(sealed: sealed).isEmpty, "list_keys does not see it")
        #expect(read.agentDescriptions.isEmpty)
        #expect(!read.isOffered(key.id))
        #expect(try store.load().open(name: "added/OpenAI prod", with: chip) == canary)
        // Nothing written beside the vault holds the value.
        #expect(!(try String(contentsOf: index, encoding: .utf8)).contains("CANARY"))
    }

    @Test func aTakenIdentifierGetsANumber() throws {
        let (home, store, index, _) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        _ = try KeyArrival.add(canary, as: "added/stripe", addedBy: "claude", store: store, index: index)
        let second = try KeyArrival.add(canary, as: "stripe", addedBy: "claude", store: store, index: index)
        #expect(second.id == "stripe-2")
        #expect(throws: VaultError.self) { try KeyArrival.add(canary, as: "stripe", addedBy: "claude", store: store, index: index) }
        #expect(throws: VaultError.self) { try KeyArrival.add(canary, as: "stripe#pending", addedBy: "claude", store: store, index: index) }
    }

    @Test func aKeysTomlThatCannotBeReadStopsTheAdd() throws {
        let (home, store, index, _) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        try "not toml at all".write(to: index, atomically: true, encoding: .utf8)
        #expect(throws: VaultError.self) { try KeyArrival.add(canary, as: "added/x", addedBy: "claude", store: store, index: index) }
        #expect(try store.load().entries["added/x"] == nil, "no key is left in the vault with no record")
    }

    @Test func putOverARealKeyWaitsForThePerson() throws {
        let (home, store, index, journal) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        _ = try KeyArrival.add(canary, as: "added/mail", addedBy: "claude", store: store, index: index)
        let outcome = try KeyArrival.put(newer, as: "added/mail", addedBy: "codex", byEngine: false, journal: journal, store: store, index: index)
        #expect(outcome == .waiting)
        var vault = try store.load()
        #expect(try vault.open(name: "added/mail", with: chip) == canary, "the current value stays in force")
        #expect(vault.replaced == nil)
        #expect(vault.entries["added/mail#pending"]?.from == "codex")
        #expect(KeyArrival.waiting(in: vault, journal: journal).map(\.name) == ["added/mail"])
        // Even a program that says it is the engine waits when no rotation is open.
        #expect(try KeyArrival.put(newer, as: "added/mail", addedBy: "x", byEngine: true, journal: journal, store: store, index: index) == .waiting)

        try KeyArrival.accept("added/mail", with: chip, journal: journal, store: store)
        vault = try store.load()
        #expect(try vault.open(name: "added/mail", with: chip) == newer)
        #expect(try vault.openReplaced(name: "added/mail", index: 0, with: chip) == canary, "the old value stays as history")
        #expect(vault.entries["added/mail#pending"] == nil)
        #expect(KeyArrival.waiting(in: vault, journal: journal).isEmpty)
    }

    @Test func aWaitingValueCanBeDiscarded() throws {
        let (home, store, index, journal) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        _ = try KeyArrival.add(canary, as: "added/mail", addedBy: "claude", store: store, index: index)
        _ = try KeyArrival.put(newer, as: "added/mail", addedBy: "codex", byEngine: false, journal: journal, store: store, index: index)
        try KeyArrival.discard("added/mail", journal: journal, store: store)
        let vault = try store.load()
        #expect(try vault.open(name: "added/mail", with: chip) == canary)
        #expect(vault.entries["added/mail#pending"] == nil)
        #expect(throws: VaultError.self) { try KeyArrival.discard("added/mail", journal: journal, store: store) }
    }

    @Test func putOfANewNameIsAnAdd() throws {
        let (home, store, index, journal) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        let outcome = try KeyArrival.put(canary, as: "added/fresh", addedBy: "claude", byEngine: false, journal: journal, store: store, index: index)
        guard case .added(let key) = outcome else { Issue.record("not added: \(outcome)"); return }
        #expect(key.id == "fresh")
        #expect(try KeyIndex.load(from: index).unoffered.map(\.id) == ["fresh"])
    }

    /// The engine's own writes during a rotation work as they did: temporary copies, then the key itself.
    @Test func aRotationStillReplacesItsKey() throws {
        let (home, store, index, journal) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        _ = try KeyArrival.add(canary, as: "resend.txt", addedBy: "claude", store: store, index: index)
        try #"{"rotation":1,"key":"resend.txt","at":1,"event":"started","old_id":null}"#.appending("\n")
            .write(to: journal, atomically: true, encoding: .utf8)
        // Temporary copies: replaced with no history, as before.
        #expect(try KeyArrival.put(canary, as: "resend.txt#previous", addedBy: "keyreeve-cli", byEngine: true, journal: journal, store: store, index: index) == .temporary)
        #expect(try KeyArrival.put(newer, as: "resend.txt#pending", addedBy: "keyreeve-cli", byEngine: true, journal: journal, store: store, index: index) == .temporary)
        #expect(try KeyArrival.put(newer, as: "resend.txt#pending", addedBy: "keyreeve-cli", byEngine: true, journal: journal, store: store, index: index) == .temporary)
        var vault = try store.load()
        #expect(vault.replaced == nil)
        #expect(KeyArrival.waiting(in: vault, journal: journal).isEmpty, "a rotation's copy is not a waiting value")
        // Someone else cannot ride on the open rotation, and its copy is not overwritten.
        #expect(throws: VaultError.self) {
            try KeyArrival.put(Data("other".utf8), as: "resend.txt", addedBy: "zsh", byEngine: false, journal: journal, store: store, index: index)
        }
        #expect(try store.load().open(name: "resend.txt#pending", with: chip) == newer)
        // The engine promotes the new key.
        #expect(try KeyArrival.put(newer, as: "resend.txt", addedBy: "keyreeve-cli", byEngine: true, journal: journal, store: store, index: index) == .replacedByRotation)
        vault = try store.load()
        #expect(try vault.open(name: "resend.txt", with: chip) == newer)
        #expect(vault.replaced?["resend.txt"]?.count == 1)
        // And the rotation closes: the next new value waits again.
        let closed = #"{"rotation":1,"key":"resend.txt","at":2,"event":"completed"}"#
        try (String(contentsOf: journal, encoding: .utf8) + closed + "\n").write(to: journal, atomically: true, encoding: .utf8)
        try store.update { $0.entries["resend.txt#pending"] = nil; $0.entries["resend.txt#previous"] = nil }
        #expect(try KeyArrival.put(canary, as: "resend.txt", addedBy: "keyreeve-cli", byEngine: true, journal: journal, store: store, index: index) == .waiting)
    }

    @Test func theJournalIsReadAsTheEngineReadsIt() throws {
        let (home, _, _, journal) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        let lines = [
            #"{"rotation":1,"key":"a","at":1,"event":"started","old_id":null}"#,
            #"{"rotation":1,"key":"a","at":2,"event":"rolled_back","reason":"x"}"#,
            #"{"rotation":1,"key":"b","at":1,"event":"started","old_id":null}"#,
            #"{"rotation":1,"key":"b","at":2,"event":"sink_updated","sink":"x"}"#,
            #"{"rotation":1,"key":"c","at":1,"event":"started","old_id":null}"#,
            #"{"rotation":1,"key":"c","at":2,"event":"completed"}"#,
            #"{"rotation":2,"key":"c","at":3,"event":"started","old_id":null}"#,
            #"{"rotation":2,"key":"c","at":4,"event":"rollback_started","reason":"x"}"#,
        ]
        try lines.joined(separator: "\n").write(to: journal, atomically: true, encoding: .utf8)
        #expect(KeyArrival.openRotations(journal: journal) == ["b", "c"])
        #expect(KeyArrival.openRotations(journal: home.appendingPathComponent("none.jsonl")).isEmpty)
    }

    @Test func anOrphanIsFoundAndGivenAnUnofferedRecord() throws {
        let (home, store, index, _) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        // As an older version left it: in the vault, and nothing in keys.toml.
        try store.update {
            try $0.add(name: "added/old-agent-key", value: canary)
            try $0.add(name: "notes/folder.env", value: canary, source: "/keys")
            try $0.add(name: "x#pending", value: canary)
        }
        var vault = try store.load()
        // A first-version book: a folder's file has its own line in the list, and is not called an orphan.
        #expect(KeyArrival.orphans(in: vault, index: try KeyIndex.load(from: index)) == ["added/old-agent-key"])
        var book = KeyIndex()
        book.schema = 2
        #expect(KeyArrival.orphans(in: vault, index: book) == ["added/old-agent-key", "notes/folder.env"])

        let made = try KeyArrival.giveRecords(to: ["added/old-agent-key"], addedBy: nil, reviewed: true, index: index)
        #expect(made.map(\.id) == ["old-agent-key"])
        let read = try KeyIndex.load(from: index)
        #expect(read.keys.isEmpty)
        #expect(read.unoffered.map(\.id) == ["old-agent-key"])
        vault = try store.load()
        #expect(KeyArrival.orphans(in: vault, index: read).isEmpty)
        #expect(read.agentNames(sealed: Set(vault.entries.keys)).isEmpty)
        // Twice changes nothing.
        #expect(try KeyArrival.giveRecords(to: ["added/old-agent-key"], addedBy: nil, reviewed: true, index: index).isEmpty)
    }

    @Test func whoAddedItIsNamedAsOtherEventsNameIt() {
        let claude = AuditLog.Observed(pid: 1, program: "/x/keyreeve-vault", chain: ["keyreeve-vault", "zsh", "node", "claude"])
        #expect(KeyArrival.addedBy(observed: claude, declared: nil) == "claude")
        #expect(KeyArrival.agent(observed: claude, declared: nil) == "claude")
        #expect(KeyArrival.addedBy(observed: claude, declared: "sales") == "claude/sales")
        let shell = AuditLog.Observed(pid: 1, program: "/x/keyreeve-vault", chain: ["keyreeve-vault", "bash", "python3", "zsh", "Terminal", "launchd"])
        #expect(KeyArrival.addedBy(observed: shell, declared: nil) == "bash < python3 < zsh < Terminal")
        #expect(KeyArrival.agent(observed: shell, declared: nil) == nil)
        #expect(KeyArrival.addedBy(observed: AuditLog.Observed(pid: 1, program: "x", chain: ["keyreeve-vault"]), declared: nil) == "a program")
    }

    @Test func theRecordSurvivesWritingAndReading() throws {
        var index = KeyIndex()
        var key = KeyIndex.Key(id: "a", source: "added/a")
        key.more.addedBy = "claude \"quoted\""
        key.more.addedAt = "2026-11-09T23:00:00Z"
        key.more.reviewed = false
        try index.addUnoffered(key)
        let read = try KeyIndex.parse(index.toml)
        #expect(read == index)
        #expect(index.toml.contains("reviewed = false"))
        // A file written before these fields reads as reviewed.
        #expect(try KeyIndex.parse("[[key]]\nid = \"b\"\nsource = \"b\"\n").keys.first?.more.reviewed == true)
    }
}
