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

    @Test func testBadNamesAreRefused() {
        for name in ["", "a b", "a\nb", "ñ", String(repeating: "a", count: 201)] {
            XCTAssertThrowsError(try VaultFile.check(name: name), name)
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

extension VaultFile {
    /// Sealing is random, so compare what was stored with what came back.
    fileprivate func withSameEntries(as other: VaultFile) -> VaultFile { other }
}
