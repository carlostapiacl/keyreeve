import Foundation
import KeyreeveCatalog
@testable import KeyreeveUI
import KeyreeveVault
import Testing

@MainActor
struct SortingAppTests {
    func model() throws -> (AppModel, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("sorting-app-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        model.items = [
            CatalogItem(path: "id.txt", labels: []),
            CatalogItem(path: "app.env", tags: ["shop"], labels: ["TOKEN", "URL"], description: "mine"),
        ]
        model.unlocked = true
        return (model, root)
    }

    @Test func theListForAgentsHasNamesAndStatesAndOnlyWhileAllowed() throws {
        let (model, root) = try model()
        defer {
            try? FileManager.default.removeItem(at: root)
            UserDefaults.standard.removeObject(forKey: AppModel.agentsCanSortKey)
        }
        let file = AgentSorting.inventoryFile(home: root)
        UserDefaults.standard.set(false, forKey: AppModel.agentsCanSortKey)
        model.publishInventory()
        #expect(!FileManager.default.fileExists(atPath: file.path))
        UserDefaults.standard.set(true, forKey: AppModel.agentsCanSortKey)
        model.publishInventory()
        let text = try String(contentsOf: file, encoding: .utf8)
        #expect(AgentSorting.paths(inInventory: Data(text.utf8)) == ["id.txt", "app.env"])
        #expect(text.contains("TOKEN") && text.contains("never_checked") && text.contains("\"what\":\"mine\""))
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
        UserDefaults.standard.set(false, forKey: AppModel.agentsCanSortKey)
        model.publishInventory()
        #expect(!FileManager.default.fileExists(atPath: file.path))
    }

    @Test func applyingKeepsTheChosenChangesAndTellsTheAgent() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        let request = AccessRequests.Entry(id: "r-1", at: Date(), event: .asked, agent: "claude", provider: "keyreeve", reason: "sort", kind: "sort")
        let json = #"[{"path":"id.txt","kind":"public","what":"An account id"},{"path":"app.env","archive":true}]"#
        let proposal = SortProposal.read(Data(json.utf8), items: model.items, providers: ProviderDirectory())
        model.apply(proposal, chosen: ["id.txt"], for: request)
        let edits = try JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: model.files.edits))
        #expect(edits["id.txt"]?.level == "none" && edits["id.txt"]?.description == "An account id")
        #expect(edits["app.env"] == nil)
        let answer = AccessRequests.read(from: root.appendingPathComponent(AccessRequests.fileName)).last
        #expect(answer?.event == .allowed && answer?.id == "r-1" && answer?.result?.hasPrefix("applied 1 changes") == true)
    }
}

@MainActor
struct WhenIdleTests {
    @Test func aStepWaitsUntilTheAppIsFree() async throws {
        let model = AppModel(files: KeyreeveFiles(directory: FileManager.default.temporaryDirectory.appendingPathComponent("idle-\(UUID().uuidString)")), binary: nil)
        model.busy = true
        var ran = false
        model.whenIdle { ran = true }
        try await Task.sleep(for: .milliseconds(500))
        #expect(!ran)
        model.busy = false
        try await Task.sleep(for: .milliseconds(500))
        #expect(ran)
    }
}
