import CryptoKit
import Foundation
import KeyreeveCatalog
import KeyreeveVault
import Testing

@testable import KeyreeveUI

/// What the window would show, read from real files.
@MainActor
struct SnapshotTests {
    func home() throws -> (root: URL, files: KeyreeveFiles, store: VaultStore) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-snap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let files = KeyreeveFiles(directory: root)
        try "path,level,tags,format,modified,mode,reviewed\na.txt,ask,,text,2026-01-01,600,true\n"
            .write(to: files.catalog, atomically: true, encoding: .utf8)
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        let chip = SoftwareRecipient()
        try store.save(VaultFile(enclave: chip.publicKey, recovery: Age.X25519Identity().recipient))
        return (root, files, store)
    }

    @Test func testACopyFromAnotherFolderIsNotUsedForTheFileWithItsName() throws {
        let (root, files, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = root.appendingPathComponent("first")
        let second = root.appendingPathComponent("second")
        for folder in [first, second] {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try "value".write(to: folder.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        }
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: first, store: store, now: Date().addingTimeInterval(60))
        let read = { (folder: URL) in
            Snapshot(reading: .init(files: files, store: store, binary: nil, keysFolder: folder)).items[0].vault
        }
        #expect(read(first) == .sealed)
        #expect(read(second) == .otherFolder)
    }

    /// A pasted key whose name cannot be written is not left sealed with no name, and trying again works.
    @Test func aPastedKeyIsSavedWholeOrNotAtAll() throws {
        let (root, _, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        var index = KeyIndex()
        try index.add(KeyIndex.Key(id: "mail", source: "added/mail"))
        struct Full: Error {}
        #expect(throws: VaultError.self) {
            try AppModel.savePasted(Data("CANARY".utf8), as: "added/mail", index: index, store: store) { _ in throw Full() }
        }
        #expect(try store.load().entries["added/mail"] == nil)
        var written: Data?
        try AppModel.savePasted(Data("CANARY".utf8), as: "added/mail", index: index, store: store) { written = $0 }
        #expect(try store.load().entries["added/mail"] != nil)
        #expect(written.map { String(decoding: $0, as: UTF8.self).contains("added/mail") } == true)
    }

    /// The agents a key can be opened to: those the log has seen, cleaned, once each, with Claude and Codex.
    @Test func theAgentsToChooseFromAreTheOnesSeen() {
        let names = AppModel.agentNames(["nightly-bot", "Claude", " nightly-bot ", "motor_1", "a b", "<x>", "", String(repeating: "z", count: 50), "claude/sales", "a/b/c", "claude/"])
        #expect(names == ["claude", "claude/sales", "codex", "motor_1", "nightly-bot"])
    }

    /// An agent seen once is remembered, cleaned, after it leaves the recent lines of the log.
    @Test func anAgentSeenOnceIsRemembered() throws {
        let defaults = try #require(UserDefaults(suiteName: "agents-\(UUID().uuidString)"))
        AppModel.rememberAgents(["nightly-bot", "<bad>"], defaults)
        #expect(AppModel.rememberedAgents(defaults) == ["claude", "codex", "nightly-bot"])
        AppModel.rememberAgents(AppModel.rememberedAgents(defaults) + ["sales"], defaults)
        #expect(AppModel.rememberedAgents(defaults).contains("nightly-bot"))
    }

    /// The window knows which keys have a copy that opens with no fingerprint, so a marked one without it is said.
    @Test func theWindowKnowsWhichKeysHaveANoFingerprintCopy() throws {
        let (root, files, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        try store.update { vault in
            try vault.add(name: "marked.txt", value: Data("CANARY".utf8))
            try vault.add(name: "plain.txt", value: Data("CANARY".utf8))
            vault.unattended = Age.TagRecipient(publicKey: SoftwareRecipient().publicKey).string
            try vault.sealUnattended(name: "marked.txt", value: Data("CANARY".utf8))
        }
        let snapshot = Snapshot(reading: .init(files: files, store: store, binary: nil, keysFolder: nil))
        #expect(snapshot.unattendedSources == ["marked.txt"])
    }

    /// A key put in the vault from a script, with no file and no catalog line, is listed so it can be checked.
    @Test func aKeyAddedFromAScriptIsListed() throws {
        let (root, files, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        try store.update { vault in
            try vault.add(name: "from-a-script.txt", value: Data("CANARY".utf8))
            try vault.add(name: "from-elsewhere.txt", value: Data("CANARY".utf8), source: "/some/other/folder")
        }
        let paths = Snapshot(reading: .init(files: files, store: store, binary: nil, keysFolder: nil)).items.map(\.path)
        #expect(paths.contains("from-a-script.txt"))
        // One sealed from a folder of files belongs to that folder's list, not here.
        #expect(!paths.contains("from-elsewhere.txt"))
    }

    /// A revocation counts only once the service says so; with no service running, none can be in force.
    @Test func aRevocationIsDoneOnlyWhenTheServiceSaysSo() throws {
        let socket = FileManager.default.temporaryDirectory.appendingPathComponent("svc-\(UUID().uuidString).sock").path
        #expect(AppModel.revokeConfirmed(key: "k", grant: nil, socket: socket))
        FileManager.default.createFile(atPath: socket, contents: Data())
        defer { try? FileManager.default.removeItem(atPath: socket) }
        let yes: (KeyService.Request) throws -> KeyService.Response? = { _ in KeyService.Response(ok: true) }
        let no: (KeyService.Request) throws -> KeyService.Response? = { _ in KeyService.Response(ok: false) }
        let saidYes = AppModel.revokeConfirmed(key: "k", grant: nil, socket: socket, send: yes)
        let saidNo = AppModel.revokeConfirmed(key: "k", grant: nil, socket: socket, tries: 2, send: no)
        // A socket that is there and does not answer is not a yes.
        let silent = AppModel.revokeConfirmed(key: "k", grant: nil, socket: socket, tries: 1)
        #expect(saidYes)
        #expect(!saidNo)
        #expect(!silent)
    }

    /// A file that is there and cannot be read is said to be so, never shown as an empty one.
    @Test func damagedFilesAreNamedAndNotShownAsEmpty() throws {
        let (root, files, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let read = { Snapshot(reading: .init(files: files, store: store, binary: nil, keysFolder: nil)) }
        #expect(read().problems.isEmpty)
        try "path,level,tags,format,modified,mode,reviewed\na.txt,ask,,text,2026-01-01,600,true\nb.txt,ask\n"
            .write(to: files.catalog, atomically: true, encoding: .utf8)
        try "[[agents".write(to: files.agents, atomically: true, encoding: .utf8)
        try "{not json".write(to: store.directory.appendingPathComponent("vault.json"), atomically: true, encoding: .utf8)
        let snapshot = read()
        #expect(snapshot.hasVault)
        #expect(snapshot.items.map(\.path) == ["a.txt"])
        #expect(snapshot.problems.count == 3)
        // In whichever language the tests run.
        #expect(snapshot.problems.contains { $0.hasPrefix("1 ") })
        #expect(snapshot.problems.contains { $0.contains("vault is there") || $0.contains("bóveda está") })
        #expect(snapshot.problems.contains { $0.contains("agents") && $0.contains("damaged") })
    }

    @Test func testAFinishedLoadCannotRefillALockedWindow() async throws {
        let (root, files, _) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let model = AppModel(files: files, binary: nil)
        var finished = false
        model.load { finished = true }
        try await Task.sleep(for: .milliseconds(100))
        #expect(!finished)
        #expect(model.items.isEmpty)
    }

    @Test func testReadingClosesTheProgramsFolder() throws {
        let (root, files, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let providers = root.appendingPathComponent("providers")
        try FileManager.default.createDirectory(at: providers, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        _ = Snapshot(reading: .init(files: files, store: store, binary: nil, keysFolder: nil))
        let mode = try FileManager.default.attributesOfItem(atPath: providers.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o700)
    }
}
