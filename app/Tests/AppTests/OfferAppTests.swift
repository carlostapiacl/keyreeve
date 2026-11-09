import Foundation
import KeyreeveCatalog
@testable import KeyreeveUI
import KeyreeveVault
import Testing

/// "Give them identifiers" names every sealed key for the person, and offers none of them to agents.
@MainActor
struct OfferAppTests {
    func model() throws -> (AppModel, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("offer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        var bank = CatalogItem(path: "bank.txt", recipes: ["bank"], labels: [])
        bank.vault = .sealed
        var root2 = CatalogItem(path: "root.txt", labels: [])
        root2.vault = .outdated
        let loose = CatalogItem(path: "loose.txt", labels: [])
        model.items = [bank, root2, loose]
        model.unlocked = true
        return (model, root)
    }

    var sealed: Set<String> { ["bank.txt", "root.txt"] }

    @Test func identifiersGivenInBulkAreWrittenNotOffered() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        model.assignIdentifiers()
        let read = try KeyIndex.load(from: model.files.keyIndex)
        #expect(read.keys.isEmpty)
        #expect(Set(read.unoffered.map(\.source)) == sealed)
        #expect(read.agentNames(sealed: sealed).isEmpty, "agents see none of them")
        #expect(read == model.keyIndex)
        #expect(model.sealedWithoutIdentifier == 0)
        #expect(model.sealedNotOffered == 2)
        // A second click gives no key a second identifier.
        model.assignIdentifiers()
        #expect(try KeyIndex.load(from: model.files.keyIndex).unoffered.count == 2)
    }

    @Test func aPersonOffersOneAndTakesItBack() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        model.assignIdentifiers()
        let id = try #require(model.keyIndex.allKeys(forSource: "bank.txt").first?.id)
        model.setOffered(true, id: id)
        #expect(try KeyIndex.load(from: model.files.keyIndex).agentNames(sealed: sealed) == [id])
        #expect(model.sealedNotOffered == 1)
        model.setAgentLevel(.ask, for: id)
        #expect(model.agentPolicy.levels[id] == .ask)
        // Taken back, it is out of sight and closed.
        model.setOffered(false, id: id)
        #expect(try KeyIndex.load(from: model.files.keyIndex).agentNames(sealed: sealed).isEmpty)
        #expect(model.agentPolicy.levels[id] == nil)
    }

    @Test func givingALevelOffersTheKey() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        model.assignIdentifiers()
        let id = try #require(model.keyIndex.allKeys(forSource: "root.txt").first?.id)
        model.setAgentLevel(.ask, for: id)
        #expect(try KeyIndex.load(from: model.files.keyIndex).agentNames(sealed: sealed) == [id])
    }
}
