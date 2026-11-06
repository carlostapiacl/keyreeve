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
        try store.save(VaultFile(enclave: chip.publicKey, recovery: SoftwareRecipient().publicKey))
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
