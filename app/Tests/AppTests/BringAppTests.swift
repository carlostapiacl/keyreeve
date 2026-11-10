import CryptoKit
import Foundation
@testable import KeyreeveCatalog
import KeyreeveVault
import Testing

@testable import KeyreeveUI

/// Bring in seals the chosen keys at once, gives each an identifier no agent sees, and leaves the files as
/// they were.
@MainActor
struct BringAppTests {
    func home() throws -> (root: URL, store: VaultStore) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("bring-app-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        try store.save(VaultFile(enclave: SoftwareRecipient().publicKey, recovery: Age.X25519Identity().recipient))
        return (root, store)
    }

    func candidate(_ id: Int, _ file: URL, value: String, name: String, provider: String?, area: String = "folder",
                   group: BringCandidate.Group = .works, server: String? = nil) throws -> BringCandidate {
        let text = try String(contentsOf: file, encoding: .utf8)
        let range = try #require(text.range(of: value))
        let from = text.utf8.distance(from: text.startIndex, to: range.lowerBound)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        let origin = BringCandidate.Origin(
            path: file.path, area: area, bytes: (attributes[.size] as! NSNumber).uint64Value,
            modified: UInt64((attributes[.modificationDate] as! Date).timeIntervalSince1970.rounded(.down)),
            parts: [.init(name: name, section: nil, line: 1, span: [from, from + value.utf8.count], json: nil, whole: false)])
        return BringCandidate(
            id: id, group: group, kind: "key", why: "", provider: provider, evidence: provider.map { _ in "prefix" }, guessed: [],
            check: nil, unchecked: nil, server: server, origins: [origin], duplicate: false, from_project: area == "project",
            suggested: group == .works ? "seal" : "decide")
    }

    @Test func chosenKeysAreSealedWithIdentifiersNoAgentSees() throws {
        let (root, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let env = root.appendingPathComponent("app.env")
        try "OPENAI_API_KEY=CANARYopenai\nR2_ID=CANARYr2\n".write(to: env, atomically: true, encoding: .utf8)
        let before = try Data(contentsOf: env)
        let openai = try candidate(1, env, value: "CANARYopenai", name: "OPENAI_API_KEY", provider: "openai", area: "project")
        let r2 = try candidate(2, env, value: "CANARYr2", name: "R2_ID", provider: "r2", server: "x.r2.cloudflarestorage.com")
        var written: Data?
        let result = try AppModel.sealBrought(
            [openai, r2], index: KeyIndex(), store: store, selfHosted: ["r2"], variables: ["openai": "OPENAI_API_KEY"]
        ) { written = $0 }
        #expect(result.sealed.map(\.id) == ["openai", "r2"])
        #expect(result.sealed.map(\.fromProject) == [true, false])
        #expect(result.failed.isEmpty)
        #expect(result.index.keys.isEmpty, "no key is offered to agents")
        #expect(result.index.unoffered.map(\.source) == ["added/openai", "added/r2"])
        #expect(result.index.unoffered[0].variable == "OPENAI_API_KEY")
        #expect(result.index.unoffered[1].more.host == "x.r2.cloudflarestorage.com")
        let vault = try store.load()
        #expect(vault.entries["added/openai"]?.source == env.path, "where it came from is kept")
        #expect(written.map { String(decoding: $0, as: UTF8.self).contains("added/r2") } == true)
        #expect(!(written.map { String(decoding: $0, as: UTF8.self) } ?? "").contains("CANARY"))
        #expect(try Data(contentsOf: env) == before, "the file is not changed")
    }

    /// A provider only guessed from a name is not saved with the key, so no later check sends it there.
    @Test func aGuessIsNotSavedAsTheProvider() throws {
        let (root, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let env = root.appendingPathComponent("telegram.env")
        try "MY_TELEGRAM_THING=CANARYguess\n".write(to: env, atomically: true, encoding: .utf8)
        var key = try candidate(1, env, value: "CANARYguess", name: "MY_TELEGRAM_THING", provider: nil, group: .doubtful)
        key.guessed = ["telegram"]
        key.unchecked = "only its name suggests a provider"
        let result = try AppModel.sealBrought([key], index: KeyIndex(), store: store, variables: ["telegram": "TELEGRAM_BOT_TOKEN"]) { _ in }
        let saved = try #require(result.index.unoffered.first)
        #expect(saved.provider == nil)
        #expect(saved.variable == "MY_TELEGRAM_THING")
        #expect(saved.id == "telegram", "the file's name still names it")
    }

    @Test func nothingIsLeftWhenKeysTomlCannotBeWritten() throws {
        let (root, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let env = root.appendingPathComponent(".env")
        try "TOKEN=CANARYtoken\n".write(to: env, atomically: true, encoding: .utf8)
        let key = try candidate(1, env, value: "CANARYtoken", name: "TOKEN", provider: nil)
        struct Full: Error {}
        #expect(throws: VaultError.self) {
            try AppModel.sealBrought([key], index: KeyIndex(), store: store) { _ in throw Full() }
        }
        #expect(try store.load().entries.isEmpty)
    }

    @Test func aFileThatChangedIsLeftOutAndSaid() throws {
        let (root, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        let env = root.appendingPathComponent(".env")
        try "TOKEN=CANARYtoken\n".write(to: env, atomically: true, encoding: .utf8)
        let key = try candidate(1, env, value: "CANARYtoken", name: "TOKEN", provider: nil)
        try "TOKEN=CANARYlonger\n".write(to: env, atomically: true, encoding: .utf8)
        let result = try AppModel.sealBrought([key], index: KeyIndex(), store: store) { _ in }
        #expect(result.sealed.isEmpty)
        #expect(result.failed.count == 1)
        #expect(try store.load().entries.isEmpty)
    }

    @Test func onlyTheDoubtfulWaitForThePerson() throws {
        let (root, store) = try home()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = store
        let env = root.appendingPathComponent(".env")
        try "A=CANARYa\nB=CANARYb\n".write(to: env, atomically: true, encoding: .utf8)
        var dead = try candidate(3, env, value: "CANARYb", name: "B", provider: "x", group: .dead)
        dead.suggested = "skip"
        let report = BringReport(
            schema: 1, scope: "folder", roots: [], suggested_projects: [], files: 1, checked: true,
            skipped: .init(), summary: .init(),
            candidates: [
                try candidate(1, env, value: "CANARYa", name: "A", provider: "x"),
                try candidate(2, env, value: "CANARYb", name: "B", provider: nil, group: .doubtful), dead,
            ])
        var state = BringState()
        state.report = report
        state.decisions = AppModel.firstDecisions(report)
        #expect(state.undecided == 1)
        #expect(state.chosen.map(\.id) == [1])
        state.decisions[2] = true
        #expect(state.undecided == 0)
        #expect(state.chosen.map(\.id) == [1, 2])
        // Usual places search only the project folders the person turned on.
        var places = BringState(projects: [URL(fileURLWithPath: "/a"), URL(fileURLWithPath: "/b")])
        places.projects[1].on = true
        #expect(places.scope == .places(projects: [URL(fileURLWithPath: "/b")]))
        places.usualPlaces = false
        #expect(places.scope == nil)
    }

    @Test func offeringTheOnesScriptsUseOffersOnlyThose() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("bring-offer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        model.unlocked = true
        var index = KeyIndex()
        try index.addUnoffered(.init(id: "openai", source: "added/openai"))
        try index.addUnoffered(.init(id: "netrc", source: "added/netrc"))
        model.keyIndex = index
        var state = BringState()
        state.sealed = [("openai", true), ("netrc", false)]
        model.bringing = state
        model.offerBroughtFromProjects()
        let read = try KeyIndex.load(from: model.files.keyIndex)
        #expect(read.keys.map(\.id) == ["openai"])
        #expect(read.unoffered.map(\.id) == ["netrc"])
        #expect(model.bringing == nil)
    }
}
