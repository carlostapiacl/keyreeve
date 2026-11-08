import CryptoKit
import Foundation
import Testing

@testable import KeyreeveVault

struct VaultTests {
    let chip = SoftwareRecipient()
    let recovery = Age.X25519Identity()
    let value = Data("CANARY-value".utf8)

    func vault() throws -> VaultFile {
        var file = VaultFile(enclave: chip.publicKey, recovery: recovery.recipient)
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
        XCTAssertNil(try vault().entries["a/key.txt"]!.sealed.range(of: value))
    }

    @Test func testAChangedFileDoesNotOpen() throws {
        var file = try vault()
        let last = file.entries["a/key.txt"]!.sealed.count - 1
        file.entries["a/key.txt"]!.sealed[last] ^= 1
        XCTAssertThrowsError(try file.open(name: "a/key.txt", with: chip))

        file = try vault()
        file.entries["a/key.txt"]!.sealed[40] ^= 1
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

    /// A key marked to need no fingerprint has a second copy, sealed only to the key that needs none. That key
    /// opens nothing else, a rotation keeps the mark, taking it off removes the copy, and a new chip drops it.
    @Test func aKeyMarkedForNoFingerprintOpensOnlyThroughItsOwnCopy() throws {
        var file = try vault()
        try file.add(name: "b/other.txt", value: Data("OTHER".utf8))
        let unattended = SoftwareRecipient()
        #expect(throws: VaultError.self) { try file.sealUnattended(name: "a/key.txt", value: value) }
        file.unattended = Age.TagRecipient(publicKey: unattended.publicKey).string
        try file.sealUnattended(name: "a/key.txt", value: value)
        #expect(try file.openUnattended(name: "a/key.txt", with: unattended) == value)
        // It opens neither the main copy nor a key that was not marked.
        #expect(throws: (any Error).self) { try file.open(name: "a/key.txt", with: unattended) }
        #expect(throws: VaultError.self) { try file.openUnattended(name: "b/other.txt", with: unattended) }
        // The main key does not open the copy either: it is sealed to the other key alone.
        #expect(throws: (any Error).self) { try file.openUnattended(name: "a/key.txt", with: chip) }
        // A rotation keeps the mark, with the new value.
        try file.replace(name: "a/key.txt", value: Data("NEW".utf8))
        #expect(try file.openUnattended(name: "a/key.txt", with: unattended) == Data("NEW".utf8))
        file.dropUnattended(name: "a/key.txt")
        #expect(throws: VaultError.self) { try file.openUnattended(name: "a/key.txt", with: unattended) }
        try file.sealUnattended(name: "a/key.txt", value: Data("NEW".utf8))
        try file.moveToNewEnclave(SoftwareRecipient().publicKey, recovery: recovery)
        #expect(file.unattended == nil && file.entries["a/key.txt"]?.unattendedSealed == nil)
    }

    /// A backup is proven by opening every key in it with the recovery key, not by matching a few characters.
    @Test func aBackupIsProvenByOpeningEveryKey() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("backup-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let store = VaultStore(directory: folder.appendingPathComponent("vault"))
        var file = try vault()
        try file.replace(name: "a/key.txt", value: Data("NEWER".utf8))
        try store.save(file)
        let backup = try store.backup(to: folder)
        let read = try VaultStore.read(backup)
        #expect(try read.openAll(with: recovery) == 1)
        #expect(throws: VaultError.self) { try read.openAll(with: Age.X25519Identity()) }
        // A damaged copy inside is named, so a backup that cannot bring the keys back is known before it is needed.
        var damaged = read
        damaged.entries["a/key.txt"]?.sealed = try Age.encrypt(Data("x".utf8), to: [Age.X25519Identity().recipient])
        #expect(throws: VaultError("a/key.txt does not open with the recovery key")) { try damaged.openAll(with: recovery) }
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
            try file.moveToNewEnclave(SoftwareRecipient().publicKey, recovery: Age.X25519Identity()))
        XCTAssertEqual(try file.open(name: "a/key.txt", with: chip), value)
    }

    @Test func testTheRecoveryKeyRoundTripsAndCatchesATypo() throws {
        let key = Age.X25519Identity()
        XCTAssertEqual(try Age.X25519Identity(string: key.string).recipient, key.recipient)
        var chars = Array(key.string)
        chars[chars.count - 3] = chars[chars.count - 3] == "Q" ? "P" : "Q"
        XCTAssertThrowsError(try Age.X25519Identity(string: String(chars)))
        XCTAssertThrowsError(try Age.X25519Identity(string: "short"))
    }

    @Test func testTheStoreIsPrivateAndRoundTrips() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyreeve-store-\(UUID().uuidString)/vault")
        defer { try? FileManager.default.removeItem(at: dir.deletingLastPathComponent()) }
        let store = VaultStore(directory: dir)
        XCTAssertFalse(store.exists)
        try store.save(try vault())
        try store.saveBlob(Data([1]), for: Age.TagRecipient(publicKey: chip.publicKey).string)
        XCTAssertEqual(try store.load(), try vault().withSameEntries(as: store.load()))
        for (path, mode) in [(dir.path, 0o700), (store.vaultURL.path, 0o600), (store.blobURL(for: Age.TagRecipient(publicKey: chip.publicKey).string).path, 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, mode, path)
        }
    }
}

/// Moving real files, with software keys in place of the chip.
struct KeeperTests {
    let chip = SoftwareRecipient()
    let recovery = Age.X25519Identity()

    func folder() throws -> (root: URL, keys: URL, store: VaultStore) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-keeper-\(UUID().uuidString)")
        let keys = root.appendingPathComponent("keys")
        try FileManager.default.createDirectory(at: keys.appendingPathComponent("sub dir"), withIntermediateDirectories: true)
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        try store.save(VaultFile(enclave: chip.publicKey, recovery: recovery.recipient))
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
        XCTAssertEqual(report.sealed, ["good.txt", "binary.p12"])
        XCTAssertEqual(report.skipped["empty.txt"], .empty)
        // A certificate is kept byte for byte, and comes back the same.
        XCTAssertEqual(try store.load().open(name: "binary.p12", with: chip), Data([0xFF, 0xFE, 0x00]))
        XCTAssertEqual(try VaultKeeper.compare(names: ["binary.p12"], folder: keys, recipient: chip, store: store).same, ["binary.p12"])
        // Opening it as text, for a check, says what it is.
        #expect(throws: VaultError.self) { try VaultKeeper.open(names: ["binary.p12"], recipient: chip, store: store, by: "check") }
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

    @Test func testSealingAgainKeepsTheOldCopyAndTheRecoveryMovesIt() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = keys.appendingPathComponent("a.txt")
        try "first".write(to: file, atomically: true, encoding: .utf8)
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        try "second".write(to: file, atomically: true, encoding: .utf8)
        _ = try VaultKeeper.sealAgain(paths: ["a.txt"], folder: keys, store: store)
        var vault = try store.load()
        XCTAssertEqual(try vault.open(name: "a.txt", with: chip), Data("second".utf8))
        XCTAssertEqual(try vault.openReplaced(name: "a.txt", index: 0, with: chip), Data("first".utf8))
        let newChip = SoftwareRecipient()
        try vault.moveToNewEnclave(newChip.publicKey, recovery: recovery)
        XCTAssertEqual(try vault.openReplaced(name: "a.txt", index: 0, with: newChip), Data("first".utf8))
    }

    @Test func testAFileJustBeforeSealingIsNotOutdated() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = keys.appendingPathComponent("a.txt")
        try "first".write(to: file, atomically: true, encoding: .utf8)
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        let entry = try XCTUnwrap(store.load().entries["a.txt"])
        XCTAssertFalse(VaultKeeper.isOutdated(entry, path: "a.txt", folder: keys))
    }

    @Test func testMovingAndPuttingBackOriginals() throws {
        let (root, keys, _) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try "CANARY".write(to: keys.appendingPathComponent("sub dir/a.txt"), atomically: true, encoding: .utf8)
        try "kept".write(to: keys.appendingPathComponent("b.txt"), atomically: true, encoding: .utf8)
        let inventory = root.appendingPathComponent("inventory.json")
        try #"{"schema":1,"items":[{"path":"sub dir/a.txt","modified":1,"mode":"600","format":"text","fields":[],"kinds":[]}]}"#
            .write(to: inventory, atomically: true, encoding: .utf8)
        let ledger = root.appendingPathComponent("moved.json")
        let moved = MovedOriginals(ledger: ledger, destination: root.appendingPathComponent("originals/2026"))
        // A file the inventory does not describe stays, and so does a path out of the folder.
        XCTAssertEqual(try moved.move(["sub dir/a.txt", "b.txt", "../x"], from: keys, inventory: inventory), ["sub dir/a.txt"])
        let target = root.appendingPathComponent("originals/2026/sub dir/a.txt")
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "CANARY")
        XCTAssertFalse(FileManager.default.fileExists(atPath: keys.appendingPathComponent("sub dir/a.txt").path))
        XCTAssertEqual(moved.paths, ["sub dir/a.txt"])
        XCTAssertFalse(try String(contentsOf: ledger, encoding: .utf8).contains("CANARY"))

        // A file that took the old place is not overwritten.
        try "newer".write(to: keys.appendingPathComponent("sub dir/a.txt"), atomically: true, encoding: .utf8)
        XCTAssertEqual(try moved.putBack(["sub dir/a.txt"], to: keys), [])
        XCTAssertEqual(try String(contentsOf: keys.appendingPathComponent("sub dir/a.txt"), encoding: .utf8), "newer")
        try FileManager.default.removeItem(at: keys.appendingPathComponent("sub dir/a.txt"))
        XCTAssertEqual(try moved.putBack(["sub dir/a.txt"], to: keys), ["sub dir/a.txt"])
        XCTAssertEqual(moved.paths, [])
    }

    @Test func testASealedKeyDeletedByHandStaysOnTheList() throws {
        let (root, _, _) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let item = { (path: String) in #"{"path":"\#(path)","modified":1,"mode":"600","format":"text","fields":[],"kinds":[]}"# }
        let before = Data(#"{"schema":1,"items":[\#(item("sealed.txt")),\#(item("plain.txt")),\#(item("still.txt"))]}"#.utf8)
        let inventory = root.appendingPathComponent("inventory.json")
        try #"{"schema":1,"items":[\#(item("still.txt"))]}"#.write(to: inventory, atomically: true, encoding: .utf8)
        let moved = MovedOriginals(ledger: root.appendingPathComponent("moved.json"), destination: root.appendingPathComponent("originals"))
        // Only a sealed key that the scan no longer found is kept. One that is not sealed is gone for good.
        XCTAssertEqual(try moved.keepSealed(["sealed.txt", "still.txt"], before: before, inventory: inventory), ["sealed.txt"])
        XCTAssertEqual(moved.paths, ["sealed.txt"])
        // A second scan adds nothing twice, and there is nothing to put back.
        XCTAssertEqual(try moved.keepSealed(["sealed.txt"], before: before, inventory: inventory), [])
        XCTAssertEqual(try moved.putBack(["sealed.txt"], to: root), [])
    }

    @Test func testABackupIsTheSealedFileAndNeverReplacesAnother() throws {
        let (root, _, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let shelf = root.appendingPathComponent("shelf")
        try FileManager.default.createDirectory(at: shelf, withIntermediateDirectories: true)
        try store.update { try $0.add(name: "a.txt", value: Data("CANARY".utf8)) }
        let day = Date(timeIntervalSince1970: 1_800_000_000)
        let first = try store.backup(to: shelf, now: day)
        let second = try store.backup(to: shelf, now: day)
        #expect(first != second)
        XCTAssertEqual(try Data(contentsOf: first), try Data(contentsOf: store.directory.appendingPathComponent("vault.json")))
        XCTAssertFalse(try String(contentsOf: first, encoding: .utf8).contains("CANARY"))
        let mode = try FileManager.default.attributesOfItem(atPath: first.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
        // The chip's part stays behind: it is of no use on another Mac.
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: shelf.path).count, 2)
        XCTAssertThrowsError(try VaultStore(directory: root.appendingPathComponent("none")).backup(to: shelf))
    }

    @Test func testWritersAtTheSameTimeLoseNothing() throws {
        let (root, _, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        DispatchQueue.concurrentPerform(iterations: 24) { index in
            try? store.update { try $0.add(name: "k\(index)", value: Data("v".utf8)) }
        }
        XCTAssertEqual(try store.load().entries.count, 24)
    }

    @Test func testARotationsNamesCannotHoldARealKey() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try "real".write(to: keys.appendingPathComponent("foo#pending"), atomically: true, encoding: .utf8)
        let report = try VaultKeeper.seal(paths: ["foo#pending"], folder: keys, store: store)
        XCTAssertEqual(report.skipped["foo#pending"], .reservedName)
    }

    @Test func testAMovedFileThatChangedStaysPut() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = keys.appendingPathComponent("a.txt")
        try "same".write(to: file, atomically: true, encoding: .utf8)
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        let report = try VaultKeeper.compare(names: ["a.txt"], folder: keys, recipient: chip, store: store)
        XCTAssertEqual(VaultKeeper.stillMatching(report, folder: keys), ["a.txt"])
        try "other".write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(VaultKeeper.stillMatching(report, folder: keys), [])
        XCTAssertNil(String(data: try JSONEncoder().encode(report.digests), encoding: .utf8)?.range(of: "same"))
    }

    @Test func testACopyKnowsItsFolder() throws {
        let (root, keys, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try "one".write(to: keys.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        _ = try VaultKeeper.seal(paths: ["a.txt"], folder: keys, store: store)
        let entry = try XCTUnwrap(store.load().entries["a.txt"])
        XCTAssertFalse(VaultKeeper.isFromAnotherFolder(entry, folder: keys))
        #expect(VaultKeeper.isFromAnotherFolder(entry, folder: root))
        // Sealing again keeps it, so a replaced copy does not lose its folder.
        try "two".write(to: keys.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        _ = try VaultKeeper.sealAgain(paths: ["a.txt"], folder: keys, store: store)
        #expect(VaultKeeper.isFromAnotherFolder(try XCTUnwrap(store.load().entries["a.txt"]), folder: root))
    }

    @Test func testOriginalsEndUpPrivateEvenInAnOpenFolder() throws {
        let (root, keys, _) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = keys.appendingPathComponent("a.txt")
        try "CANARY".write(to: file, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        let inventory = root.appendingPathComponent("inventory.json")
        try #"{"schema":1,"items":[{"path":"a.txt","modified":1,"mode":"644","format":"text","fields":[],"kinds":[]}]}"#
            .write(to: inventory, atomically: true, encoding: .utf8)
        let open = root.appendingPathComponent("originals/2026")
        try FileManager.default.createDirectory(at: open, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        let moved = MovedOriginals(ledger: root.appendingPathComponent("moved.json"), destination: open)
        XCTAssertEqual(try moved.move(["a.txt"], from: keys, inventory: inventory), ["a.txt"])
        let mode = { (path: String) in
            (try? FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue
        }
        XCTAssertEqual(mode(open.path), 0o700)
        XCTAssertEqual(mode(open.appendingPathComponent("a.txt").path), 0o600)
    }

    @Test func testALinkedOriginalsFolderIsRefused() throws {
        let (root, keys, _) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try "CANARY".write(to: keys.appendingPathComponent("a.txt"), atomically: true, encoding: .utf8)
        let inventory = root.appendingPathComponent("inventory.json")
        try #"{"schema":1,"items":[{"path":"a.txt","modified":1,"mode":"600","format":"text","fields":[],"kinds":[]}]}"#
            .write(to: inventory, atomically: true, encoding: .utf8)
        let shared = root.appendingPathComponent("shared")
        try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: true)
        let link = root.appendingPathComponent("originals")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: shared)
        let moved = MovedOriginals(ledger: root.appendingPathComponent("moved.json"), destination: link.appendingPathComponent("2026"))
        XCTAssertThrowsError(try moved.move(["a.txt"], from: keys, inventory: inventory))
        #expect(FileManager.default.fileExists(atPath: keys.appendingPathComponent("a.txt").path))
    }

    @Test func testCreatingNeverOverwritesAVault() throws {
        let (root, _, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try store.update { try $0.add(name: "kept", value: Data("v".utf8)) }
        XCTAssertThrowsError(try store.create(VaultFile(enclave: chip.publicKey, recovery: recovery.recipient), blob: Data([1])))
        XCTAssertEqual(try store.load().entries.count, 1)
    }

    @Test func testACrashDuringRecoveryLeavesTheOldPairWorking() throws {
        let (root, _, store) = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        try store.saveBlob(Data([1]), for: try store.load().enclave)
        // The new blob lands, and the crash comes before the vault switches to it.
        try store.saveBlob(Data([2]), for: Age.TagRecipient(publicKey: SoftwareRecipient().publicKey).string)
        XCTAssertEqual(try store.loadBlob(), Data([1]))
    }

    @Test func testNothingIsSavedUntilTheRecoveryKeyIsConfirmed() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-draft-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        let draft = VaultDraft(enclave: chip, blob: Data([1]))
        XCTAssertFalse(store.exists)
        #expect(draft.accepts(" \(draft.lastGroup.lowercased()) "))
        XCTAssertFalse(draft.accepts("nope"))
        XCTAssertFalse(draft.accepts(""))
        try draft.save(to: store)
        #expect(store.exists)
        XCTAssertThrowsError(try draft.save(to: store))
        XCTAssertEqual(try Age.X25519Identity(string: draft.recoveryKey).recipient.string, try store.load().recovery)
    }
}

extension VaultFile {
    /// Sealing is random, so compare what was stored with what came back.
    fileprivate func withSameEntries(as other: VaultFile) -> VaultFile { other }
}

struct ReservedNameTests {
    @Test func aFileAtAPastedKeysPathIsNeverSealedUnderIt() {
        #expect(VaultFile.isReserved("added/openai"))
        #expect(VaultFile.isReserved("resend#incoming"))
        #expect(!VaultFile.isReserved("lab/added.txt"))
    }
}
