import Foundation
import KeyreeveCatalog
@testable import KeyreeveUI
import KeyreeveVault
import Testing

/// What the window shows of keys that came in without the person, and what reviewing them does.
@MainActor
struct ArrivalAppTests {
    let chip = SoftwareRecipient()
    let recovery = Age.X25519Identity()

    /// A folder of its own, with a vault, 21 keys an agent added, one sealed with no record and one value waiting.
    func model() throws -> (AppModel, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("arrival-app-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        try model.vaultStore.create(VaultFile(enclave: chip.publicKey, recovery: recovery.recipient), blob: Data("blob".utf8))
        for number in 1...21 {
            _ = try KeyArrival.add(
                Data("CANARY-\(number)".utf8), as: "added/server-key-\(number)", addedBy: "claude", store: model.vaultStore,
                index: model.files.keyIndex)
        }
        try model.vaultStore.update { try $0.add(name: "added/older", value: Data("CANARY-old".utf8)) }
        _ = try KeyArrival.put(
            Data("CANARY-new".utf8), as: "added/server-key-1", addedBy: "codex", byEngine: false, journal: model.files.rotations,
            store: model.vaultStore, index: model.files.keyIndex)
        model.keyIndex = try KeyIndex.load(from: model.files.keyIndex)
        model.items = try items(model)
        model.unlocked = true
        return (model, root)
    }

    /// The list as the window builds it for keys with no file.
    func items(_ model: AppModel) throws -> [CatalogItem] {
        let vault = try model.vaultStore.load()
        var items = vault.entries.keys.filter { !VaultFile.isTemporary($0) }.sorted().map { name in
            var item = CatalogItem(path: name)
            item.vault = .sealed
            return item
        }
        AppModel.markArrivals(&items, vault: vault, index: try KeyIndex.load(from: model.files.keyIndex), journal: model.files.rotations)
        return items
    }

    @Test func newKeysAreMarkedAndCounted() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        let news = ArrivalNews.read(files: model.files, store: model.vaultStore)
        #expect(news.added == [ArrivalNews.Added(who: "claude", count: 21)])
        #expect(news.waiting == [ArrivalNews.Waiting(key: "server-key-1", from: "codex")])
        #expect(news.withoutRecord == 1)
        #expect(news.lines.first == T("%@ added %d keys", "claude", 21))
        #expect(ArrivalNews.make(items: model.items, index: model.keyIndex) == news)
        #expect(filter(model.items, by: .unreviewed, search: "").count == 22)
        #expect(CatalogSummary(items: model.items).count(.unreviewed) == 22)
        let first = try #require(model.items.first { $0.path == "added/server-key-1" })
        #expect(first.waitingFrom == "codex")
        #expect(first.attention == T("A new value is waiting, from %@", "codex"))
        let older = try #require(model.items.first { $0.path == "added/older" })
        #expect(older.withoutRecord)
        #expect(older.attention == T("Sealed without a record"))
        let plain = try #require(model.items.first { $0.path == "added/server-key-2" })
        #expect(plain.attention == T("New, not reviewed: added by %@", "claude"))
        for line in news.lines { #expect(!line.contains("CANARY")) }
    }

    @Test func reviewingOffersNothing() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        let chosen = model.items.filter { $0.newFrom != nil }
        model.markReviewed(chosen)
        let index = try KeyIndex.load(from: model.files.keyIndex)
        #expect(index.keys.isEmpty, "nothing is offered by reviewing")
        #expect(index.unoffered.allSatisfy { $0.more.reviewed })
        #expect(index.unoffered.allSatisfy { $0.more.addedBy == "claude" }, "who added it stays")
        #expect(ArrivalNews.read(files: model.files, store: model.vaultStore).added.isEmpty)
        let reviewed = try AuditLog(url: model.files.audit).entries().filter { $0.event == "reviewed" }
        #expect(reviewed.count == 21)
    }

    @Test func anOrphanGetsAnUnofferedIdentifier() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        let older = try #require(model.items.first { $0.path == "added/older" })
        model.giveRecord(to: older)
        let index = try KeyIndex.load(from: model.files.keyIndex)
        let record = try #require(index.unoffered.first { $0.source == "added/older" })
        #expect(record.id == "older")
        #expect(!index.isOffered("older"))
        #expect(KeyArrival.orphans(in: try model.vaultStore.load(), index: index).isEmpty)
    }

    @Test func aWaitingValueIsDiscardedAndTheKeyKeepsItsValue() throws {
        let (model, root) = try model()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try #require(model.items.first { $0.path == "added/server-key-1" })
        model.discardWaiting(first)
        let vault = try model.vaultStore.load()
        #expect(vault.entries["added/server-key-1#pending"] == nil)
        #expect(try vault.open(name: "added/server-key-1", with: chip) == Data("CANARY-1".utf8))
    }
}
