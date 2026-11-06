import CryptoKit
import Foundation
import Testing

@testable import KeyreeveVault

struct VaultTests {
    let chip = SoftwareRecipient()
    let recovery = SoftwareRecipient()
    let value = Data("CANARY-value".utf8)

    func vault() throws -> VaultFile {
        var file = VaultFile(enclave: chip.publicKey, recovery: recovery.publicKey)
        try file.add(name: "a/key.txt", value: value)
        return file
    }

    @Test func testBothKeysOpenAValue() throws {
        let file = try vault()
        XCTAssertEqual(try file.open(name: "a/key.txt", with: chip), value)
        XCTAssertEqual(try file.open(name: "a/key.txt", with: recovery), value)
    }

    @Test func testAStrangerCannotOpenIt() throws {
        XCTAssertThrowsError(try vault().open(name: "a/key.txt", with: SoftwareRecipient()))
    }

    @Test func testTheFileHoldsNoValue() throws {
        let encoded = try JSONEncoder().encode(try vault())
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("CANARY"))
        XCTAssertNil(encoded.range(of: value))
    }

    @Test func testAChangedFileDoesNotOpen() throws {
        var file = try vault()
        file.entries["a/key.txt"]!.sealedValue[20] ^= 1
        XCTAssertThrowsError(try file.open(name: "a/key.txt", with: chip))

        file = try vault()
        file.entries["a/key.txt"]!.enclaveWrap.sealedKey[20] ^= 1
        XCTAssertThrowsError(try file.open(name: "a/key.txt", with: chip))
    }

    @Test func testAValueCannotBeSwappedUnderAnotherName() throws {
        var file = try vault()
        try file.add(name: "other", value: Data("other".utf8))
        file.entries["other"] = file.entries["a/key.txt"]
        XCTAssertThrowsError(try file.open(name: "other", with: chip))
    }

    @Test func testAddingNeverOverwrites() throws {
        var file = try vault()
        XCTAssertThrowsError(try file.add(name: "a/key.txt", value: Data("new".utf8)))
        XCTAssertEqual(try file.open(name: "a/key.txt", with: chip), value)
    }

    @Test func testBadNamesAreRefused() throws {
        for name in ["", "a\nb", "a\tb", String(repeating: "a", count: 201)] {
            XCTAssertThrowsError(try VaultFile.check(name: name), name)
        }
        for name in ["a b (2).txt", "contraseña.txt", "dir/key.env"] {
            try VaultFile.check(name: name)
        }
    }

    @Test func testRecoveryMovesTheVaultToANewChip() throws {
        var file = try vault()
        let newChip = SoftwareRecipient()
        try file.moveToNewEnclave(newChip.publicKey, recovery: recovery)
        XCTAssertEqual(try file.open(name: "a/key.txt", with: newChip), value)
        XCTAssertEqual(try file.open(name: "a/key.txt", with: recovery), value)
        XCTAssertThrowsError(try file.open(name: "a/key.txt", with: chip))
    }

    @Test func testTheWrongKeyCannotMoveTheVault() throws {
        var file = try vault()
        XCTAssertThrowsError(
            try file.moveToNewEnclave(SoftwareRecipient().publicKey, recovery: SoftwareRecipient()))
        XCTAssertEqual(try file.open(name: "a/key.txt", with: chip), value)
    }

    @Test func testTheRecoveryKeyRoundTripsAndCatchesATypo() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let text = RecoveryKey.encode(key)
        XCTAssertEqual(try RecoveryKey.decode(text).rawRepresentation, key.rawRepresentation)
        XCTAssertEqual(
            try RecoveryKey.decode(text.lowercased().replacingOccurrences(of: "-", with: " ")).rawRepresentation,
            key.rawRepresentation)
        var chars = Array(text)
        let index = chars.firstIndex { $0 != "-" }!
        chars[index] = chars[index] == "A" ? "B" : "A"
        XCTAssertThrowsError(try RecoveryKey.decode(String(chars)))
        XCTAssertThrowsError(try RecoveryKey.decode("short"))
    }

    @Test func testTheStoreIsPrivateAndRoundTrips() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyreeve-store-\(UUID().uuidString)/vault")
        defer { try? FileManager.default.removeItem(at: dir.deletingLastPathComponent()) }
        let store = VaultStore(directory: dir)
        XCTAssertFalse(store.exists)
        try store.save(try vault())
        try store.saveBlob(Data([1]))
        XCTAssertEqual(try store.load(), try vault().withSameEntries(as: store.load()))
        for (path, mode) in [(dir.path, 0o700), (store.vaultURL.path, 0o600), (store.blobURL.path, 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, mode, path)
        }
    }
}

/// Moving real files, with software keys in place of the chip.
struct KeeperTests {
    let chip = SoftwareRecipient()
    let recovery = SoftwareRecipient()

    func folder() throws -> (root: URL, keys: URL, store: VaultStore) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-keeper-\(UUID().uuidString)")
        let keys = root.appendingPathComponent("keys")
        try FileManager.default.createDirectory(at: keys.appendingPathComponent("sub dir"), withIntermediateDirectories: true)
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        try store.save(VaultFile(enclave: chip.publicKey, recovery: recovery.publicKey))
        return (root, keys, store)
    }

    @Test func testSealingKeepsTheOriginalAndTheValueOpens() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = keys.appendingPathComponent("sub dir/key (2).txt")
        try "CANARY-one\n".write(to: file, atomically: true, encoding: .utf8)
        let report = try VaultKeeper.seal(paths: ["sub dir/key (2).txt"], folder: keys, store: store)
        XCTAssertEqual(report.sealed, ["sub dir/key (2).txt"])
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "CANARY-one\n")
        let opened = try VaultKeeper.open(names: report.sealed, recipient: chip, store: store, by: "check")
        XCTAssertEqual(opened["sub dir/key (2).txt"], "CANARY-one\n")
        let raw = try String(contentsOf: root.appendingPathComponent("vault/vault.json"), encoding: .utf8)
        XCTAssertFalse(raw.contains("CANARY"))
    }

    @Test func testTheUseIsRecordedWithoutTheValue() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try "CANARY-one".write(to: keys.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        _ = try VaultKeeper.open(names: ["a.txt"], recipient: chip, store: store, by: "check")
        let usage = try String(contentsOf: root.appendingPathComponent("usage.jsonl"), encoding: .utf8)
        #expect(usage.contains("a.txt"))
        XCTAssertFalse(usage.contains("CANARY"))
    }

    @Test func testBadFilesAreSkippedAndTheRestGoIn() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let outside = root.appendingPathComponent("outside.txt")
        try "CANARY".write(to: outside, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(at: keys.appendingPathComponent("link.txt"), withDestinationURL: outside)
        try "good".write(to: keys.appendingPathComponent("good.txt"), atomically: true, encoding: .utf8)
        try Data().write(to: keys.appendingPathComponent("empty.txt"))
        try Data([0xFF, 0xFE, 0x00]).write(to: keys.appendingPathComponent("binary.p12"))
        try Data(count: 1024 * 1024 + 1).write(to: keys.appendingPathComponent("big.txt"))
        let report = try VaultKeeper.seal(
            paths: ["good.txt", "empty.txt", "binary.p12", "big.txt", "link.txt", "../outside.txt", "missing.txt"],
            folder: keys, store: store)
        XCTAssertEqual(report.sealed, ["good.txt"])
        XCTAssertEqual(report.skipped["empty.txt"], .empty)
        XCTAssertEqual(report.skipped["binary.p12"], .notText)
        XCTAssertEqual(report.skipped["big.txt"], .tooLarge)
        XCTAssertEqual(report.skipped["link.txt"], .outsideFolder)
        XCTAssertEqual(report.skipped["../outside.txt"], .outsideFolder)
        XCTAssertEqual(report.skipped["missing.txt"], .unreadable)
    }

    @Test func testSealingTwiceChangesNothing() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = keys.appendingPathComponent("a.txt")
        try "first".write(to: file, atomically: true, encoding: .utf8)
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        try "second".write(to: file, atomically: true, encoding: .utf8)
        let report = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        XCTAssertEqual(report.already, ["a.txt"])
        XCTAssertEqual(try VaultKeeper.open(names: ["a.txt"], recipient: chip, store: store, by: "t")["a.txt"], "first")
    }

    @Test func testComparingFindsWhatChanged() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        for name in ["same.txt", "changed.txt", "gone.txt"] {
            try name.write(to: keys.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        let names = ["same.txt", "changed.txt", "gone.txt"]
        _ = try VaultKeeper.seal(paths: names, folder: keys, store: store, now: Date().addingTimeInterval(-60))
        try "new".write(to: keys.appendingPathComponent("changed.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(at: keys.appendingPathComponent("gone.txt"))
        let report = try VaultKeeper.compare(names: names, folder: keys, recipient: chip, store: store)
        XCTAssertEqual(report.same, ["same.txt"])
        XCTAssertEqual(report.different, ["changed.txt"])
        XCTAssertEqual(report.noFile, ["gone.txt"])
        let entry = try XCTUnwrap(store.load().entries["changed.txt"])
        #expect(VaultKeeper.isOutdated(entry, path: "changed.txt", folder: keys))
    }

    @Test func testNothingIsSavedUntilTheRecoveryKeyIsConfirmed() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-draft-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        let draft = VaultDraft(enclave: chip, blob: Data([1]), recovery: P256.KeyAgreement.PrivateKey())
        XCTAssertFalse(store.exists)
        #expect(draft.accepts(" \(draft.lastGroup.lowercased()) "))
        XCTAssertFalse(draft.accepts("nope"))
        XCTAssertFalse(draft.accepts(""))
        try draft.save(to: store)
        #expect(store.exists)
        XCTAssertThrowsError(try draft.save(to: store))
        XCTAssertEqual(try RecoveryKey.decode(draft.recoveryKey).publicKey.rawRepresentation, try store.load().recoveryPublicKey)
    }
}

extension VaultFile {
    /// Sealing is random, so compare what was stored with what came back.
    fileprivate func withSameEntries(as other: VaultFile) -> VaultFile { other }
}
