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
        // Accepted at once; the end is written when the steps after it end, never before.
        #expect(answer?.event == .allowed && answer?.id == "r-1" && answer?.result?.hasPrefix("accepted: 1 changes saved") == true)
    }

    /// Sealing and checking a file that was also split reach its new files, never the original that moved away.
    @Test func aSplitFileIsSealedAndCheckedAsItsNewFiles() {
        let split = ["notes.txt": ["notes-1.txt", "notes-2.txt"]]
        #expect(AppModel.afterSplit(["a.env", "notes.txt"], split: split) == ["a.env", "notes-1.txt", "notes-2.txt"])
        #expect(AppModel.afterSplit(["notes.txt"], split: [:]) == ["notes.txt"])
    }

    /// Splitting is all or nothing: a file in the way, or an original that cannot move, leaves things as they were.
    @Test func splittingLeavesNothingHalfDone() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("split-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("notes.txt")
        try "a\nb\n".write(to: source, atomically: true, encoding: .utf8)
        let outputs = [root.appendingPathComponent("notes-1.txt"), root.appendingPathComponent("notes-2.txt")]
        let originals = root.appendingPathComponent("originals")
        let target = originals.appendingPathComponent("day-split/notes.txt")
        // The second name is taken: the first file is taken out again, and the original stays.
        try "other".write(to: outputs[1], atomically: true, encoding: .utf8)
        #expect(throws: VaultError.self) {
            try AppModel.splitFiles(source: source, keys: ["a", "b"], into: outputs, movingTo: target, originals: originals)
        }
        #expect(!FileManager.default.fileExists(atPath: outputs[0].path))
        #expect(try String(contentsOf: outputs[1], encoding: .utf8) == "other")
        #expect(FileManager.default.fileExists(atPath: source.path))
        try FileManager.default.removeItem(at: outputs[1])
        // Something already where the original would go: the same.
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "older".write(to: target, atomically: true, encoding: .utf8)
        #expect(throws: VaultError.self) {
            try AppModel.splitFiles(source: source, keys: ["a", "b"], into: outputs, movingTo: target, originals: originals)
        }
        #expect(outputs.allSatisfy { !FileManager.default.fileExists(atPath: $0.path) })
        #expect(FileManager.default.fileExists(atPath: source.path))
        try FileManager.default.removeItem(at: target)
        try AppModel.splitFiles(source: source, keys: ["a", "b"], into: outputs, movingTo: target, originals: originals)
        #expect(try String(contentsOf: outputs[1], encoding: .utf8) == "b\n")
        #expect(!FileManager.default.fileExists(atPath: source.path) && FileManager.default.fileExists(atPath: target.path))
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

    /// Past the wait, a step does not run beside what is still going: it is skipped, and that is said.
    @Test func aStepThatWaitedTooLongIsSkippedNotForced() async throws {
        let model = AppModel(files: KeyreeveFiles(directory: FileManager.default.temporaryDirectory.appendingPathComponent("idle-\(UUID().uuidString)")), binary: nil)
        model.busy = true
        var ran = false
        var skipped = false
        model.whenIdle("sealing", skipped: { skipped = true }, wait: 0.3) { ran = true }
        try await Task.sleep(for: .milliseconds(900))
        #expect(!ran && skipped)
        #expect(model.message?.isEmpty == false)
    }

    /// A step after an edit reads the list as the edit left it: a reload still on its way counts as busy, so a
    /// check made after applying a proposal never runs with the fields from before.
    @Test func aStepWaitsForTheListBeingReadAgain() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("idle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        model.unlocked = true
        model.items = [CatalogItem(path: "stale.env")]
        model.load()
        var seen: [String]?
        model.whenIdle { seen = model.items.map(\.path) }
        try await Task.sleep(for: .milliseconds(800))
        #expect(seen == [])
    }
}

/// Identifying never ends in silence, and checking many keys also asks whose they are.
@MainActor
struct IdentifyTests {
    @Test func identifyingSaysWhyWhenItCannotStart() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("identify-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: URL(fileURLWithPath: "/usr/bin/true"))
        try model.files.saveKeysFolder(root.appendingPathComponent("keys"))
        model.message = nil
        model.identify([CatalogItem(path: "a.txt", level: "ask", recipes: ["nobody"])])
        #expect(model.message == T("None of these keys can be identified: their provider cannot say whose they are, or they cannot be checked from here"))
        model.message = nil
        model.busy = true
        model.identify([CatalogItem(path: "a.txt", level: "ask", recipes: ["nobody"])])
        #expect(model.message == T("Keyreeve is busy. Try again when it finishes."))
        let bare = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        bare.identify([])
        #expect(bare.message == T("This app was built without its command"))
    }

    @Test func checkingSeveralKeysAlsoAsksWhoseTheyAre() {
        let providers = ProviderDirectory([
            ProviderInfo(id: "cloudflare", name: "Cloudflare", can_identify: true),
            ProviderInfo(id: "pexels", name: "Pexels"),
        ])
        let cf = CatalogItem(path: "cf.txt", level: "ask", recipes: ["cloudflare"])
        let px = CatalogItem(path: "px.txt", level: "ask", recipes: ["pexels"])
        #expect(AppModel.alsoIdentify([cf, px], providers: providers).map(\.path) == ["cf.txt"])
        #expect(AppModel.alsoIdentify([cf], providers: providers).isEmpty)
    }
}
