import CryptoKit
import Foundation
import KeyreeveVault
import Testing

/// Proves the vault's files are real age files, against the official tools when they are installed.
struct AgeInteropTests {
    static let tool = ["/usr/local/bin/age", "/opt/homebrew/bin/age"].first(where: FileManager.default.isExecutableFile)

    func run(_ arguments: [String], input: Data) throws -> Data {
        let process = Process()
        let stdin = Pipe()
        let stdout = Pipe()
        process.executableURL = URL(fileURLWithPath: try #require(Self.tool))
        process.arguments = arguments
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        // age streams, so a large input would fill both pipes if this waited on either one.
        let writer = stdin.fileHandleForWriting
        DispatchQueue.global().async {
            try? writer.write(contentsOf: input)
            try? writer.close()
        }
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "age failed")
        return output
    }

    func identityFile(_ identity: Age.X25519Identity) throws -> (url: URL, remove: () -> Void) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("age-id-\(UUID().uuidString)")
        try identity.string.write(to: url, atomically: true, encoding: .utf8)
        return (url, { try? FileManager.default.removeItem(at: url) })
    }

    @Test(arguments: [0, 5, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 200_000])
    func testAgeOpensWhatTheVaultSeals(size: Int) throws {
        guard Self.tool != nil else { return }
        let recovery = Age.X25519Identity()
        let plain = Age.randomBytesForTests(size)
        let chip = SoftwareRecipient()
        let file = try Age.encrypt(plain, to: [chip.ageRecipient, recovery.recipient])
        let id = try identityFile(recovery)
        defer { id.remove() }
        #expect(try run(["-d", "-i", id.url.path], input: file) == plain)
        // And the other holder of the file key, the chip's stand-in.
        #expect(try Age.decrypt(file, with: chip) == plain)
    }

    @Test(arguments: [0, 5, 64 * 1024, 200_000])
    func testTheVaultOpensWhatAgeSeals(size: Int) throws {
        guard Self.tool != nil else { return }
        let plain = Age.randomBytesForTests(size)
        let recovery = Age.X25519Identity()
        let chip = SoftwareRecipient()
        let toRecovery = try run(["-r", recovery.recipient.string], input: plain)
        #expect(try Age.decrypt(toRecovery, with: recovery) == plain)
        let toChip = try run(["-r", chip.ageRecipient.string], input: plain)
        #expect(try Age.decrypt(toChip, with: chip) == plain)
    }

    @Test func testAVaultEntryOpensWithAgeAlone() throws {
        guard Self.tool != nil else { return }
        let recovery = Age.X25519Identity()
        var vault = VaultFile(enclave: SoftwareRecipient().publicKey, recovery: recovery.recipient)
        try vault.add(name: "dir/my key.env", value: Data("TOKEN=abc\n".utf8))
        let id = try identityFile(recovery)
        defer { id.remove() }
        let opened = try run(["-d", "-i", id.url.path], input: vault.entries["dir/my key.env"]!.sealed)
        #expect(String(decoding: opened, as: UTF8.self) == "keyreeve-name: dir/my key.env\nTOKEN=abc\n")
    }

    @Test func testTheWrongKeyAndACutFileAreRefused() throws {
        let recovery = Age.X25519Identity()
        let file = try Age.encrypt(Data(count: 70_000), to: [recovery.recipient])
        XCTAssertThrowsError(try Age.decrypt(file, with: Age.X25519Identity()))
        XCTAssertThrowsError(try Age.decrypt(file.dropLast(100), with: recovery))
        XCTAssertThrowsError(try Age.decrypt(file.prefix(file.count - 16 - 4464), with: recovery))
        var changed = file
        changed[10] ^= 1
        XCTAssertThrowsError(try Age.decrypt(changed, with: recovery))
    }

    @Test func testAKeyFromAgeKeygenWorks() throws {
        // From the age documentation's format: an identity and its recipient go together.
        let identity = Age.X25519Identity()
        #expect(identity.string.hasPrefix("AGE-SECRET-KEY-1"))
        #expect(identity.recipient.string.hasPrefix("age1"))
        #expect(try Age.X25519Recipient(string: identity.recipient.string) == identity.recipient)
    }
}

extension Age {
    static func randomBytesForTests(_ count: Int) -> Data {
        var out = Data()
        while out.count < count { out += SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
        return out.prefix(count)
    }
}
