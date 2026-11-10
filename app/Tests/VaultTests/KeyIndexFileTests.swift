import Foundation
import Testing

@testable import KeyreeveVault

/// Every writer of keys.toml reads it under one lock and writes only its change.
struct KeyIndexFileTests {
    func file() throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("keys-file-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent(KeyIndex.fileName)
    }

    @Test func manyWritersAtOnceLoseNothing() throws {
        let url = try file()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        DispatchQueue.concurrentPerform(iterations: 40) { number in
            _ = try? KeyIndex.change(at: url) { index in try index.addUnoffered(KeyIndex.Key(id: "k\(number)", source: "s\(number)")) }
        }
        #expect(try KeyIndex.load(from: url).unoffered.count == 40)
    }

    @Test func anEditFromAnOlderCopyWritesOnlyItsChange() throws {
        let url = try file()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try KeyIndex.change(at: url) { try $0.addUnoffered(KeyIndex.Key(id: "mine", source: "mine.txt")) }
        let base = try KeyIndex.load(from: url)
        try KeyIndex.change(at: url) { try $0.addUnoffered(KeyIndex.Key(id: "theirs", source: "theirs.txt")) }
        var edited = base
        edited.offer(id: "mine")
        let saved = try KeyIndex.save(edited, from: base, at: url)
        #expect(saved.isOffered("mine"))
        #expect(saved.unoffered.map(\.id) == ["theirs"])
        #expect(try KeyIndex.load(from: url) == saved)
        // A removal is only of what this edit removed.
        var removed = saved
        removed.remove(id: "mine")
        #expect(try KeyIndex.save(removed, from: saved, at: url).unoffered.map(\.id) == ["theirs"])
        // A new identifier someone else took meanwhile stops the edit instead of replacing theirs.
        var clash = base
        try clash.addUnoffered(KeyIndex.Key(id: "theirs", source: "other.txt"))
        #expect(throws: VaultError.self) { try KeyIndex.save(clash, from: base, at: url) }
        #expect(try KeyIndex.load(from: url).unoffered.first { $0.id == "theirs" }?.source == "theirs.txt")
    }
}
