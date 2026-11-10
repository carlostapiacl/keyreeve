import Foundation
import KeyreeveCatalog
@testable import KeyreeveUI
import KeyreeveVault
import Testing

/// The window's copy of keys.toml can be older than the file: an agent may have added a key since. An edit in the
/// app writes only its own change, so nothing the agent added is lost.
@MainActor
struct StaleIndexTests {
    let chip = SoftwareRecipient()
    let recovery = Age.X25519Identity()

    func model(_ prefix: String) throws -> (AppModel, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("\(prefix)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        try model.vaultStore.create(VaultFile(enclave: chip.publicKey, recovery: recovery.recipient), blob: Data("blob".utf8))
        model.unlocked = true
        return (model, root)
    }

    @Test func anAgentsAddSurvivesAnEditFromAnOlderCopy() throws {
        let (model, root) = try model("stale")
        defer { try? FileManager.default.removeItem(at: root) }
        var bank = CatalogItem(path: "bank.txt", recipes: ["bank"], labels: [])
        bank.vault = .sealed
        model.items = [bank]
        model.assignIdentifiers()
        let bankID = try #require(model.keyIndex.allKeys(forSource: "bank.txt").first?.id)
        let stale = model.keyIndex

        // An agent adds a key while the window holds the copy above.
        let added = try KeyArrival.add(
            Data("CANARY-agent".utf8), as: "added/agent-key", addedBy: "claude", store: model.vaultStore, index: model.files.keyIndex)
        #expect(model.keyIndex == stale, "the window has not read it yet")

        // The person gives the other key a level, which offers it and writes keys.toml.
        model.setAgentLevel(.ask, for: bankID)

        let disk = try KeyIndex.load(from: model.files.keyIndex)
        #expect(disk.isOffered(bankID), "the person's change is there")
        #expect(model.agentPolicy.levels[bankID] == .ask)
        let agentRecord = try #require(disk.unoffered.first { $0.id == added.id }, "the agent's record is still there")
        #expect(agentRecord.more.addedBy == "claude")
        #expect(agentRecord.more.reviewed == false)
        #expect(model.keyIndex == disk, "the window now holds what is on disk")

        // A second edit from the window, after another add, keeps both again.
        let second = try KeyArrival.add(
            Data("CANARY-agent-2".utf8), as: "added/agent-key-two", addedBy: "codex", store: model.vaultStore, index: model.files.keyIndex)
        model.setAccount("me@example.com", of: bankID)
        let again = try KeyIndex.load(from: model.files.keyIndex)
        #expect(again.unoffered.contains { $0.id == second.id })
        #expect(again.unoffered.contains { $0.id == added.id })
        #expect(again.key(bankID)?.account == "me@example.com")
        #expect(!(try String(contentsOf: model.files.keyIndex, encoding: .utf8)).contains("CANARY"))
    }

    @Test func aChangeOnDiskIsNoticed() throws {
        let (model, root) = try model("stamp")
        defer { try? FileManager.default.removeItem(at: root) }
        model.indexStamp = AppModel.indexStamp(of: model.files)
        let before = model.indexStamp
        model.reloadIfIndexChanged()
        #expect(model.indexStamp == before, "nothing changed, nothing is read")
        _ = try KeyArrival.add(Data("CANARY-x".utf8), as: "added/x", addedBy: "claude", store: model.vaultStore, index: model.files.keyIndex)
        model.reloadIfIndexChanged()
        #expect(model.indexStamp != before, "the add is seen, and the list is read again")
        // A mark the key service writes in key-state.json changes the stamp too, with keys.toml untouched.
        let added = AppModel.indexStamp(of: model.files)
        try KeyStates.mark(id: "x", active: false, in: AppModel.keyStates(of: model.files))
        #expect(AppModel.indexStamp(of: model.files) != added, "a key its provider stopped accepting is flagged without a restart")
    }
}
