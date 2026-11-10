import Foundation
import Testing

@testable import KeyreeveVault

/// `keyreeve-vault add`, `put` and `orphans` as an agent runs them: a folder of their own, a value on stdin, and a
/// time limit on every run.
struct VaultCommandTests {
    let chip = SoftwareRecipient()
    let recovery = Age.X25519Identity()
    let first = "CANARY-first-value-7f3a"
    let second = "CANARY-second-value-9c1d"

    /// The tool the package builds beside these tests.
    static let tool = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent(".build/debug/keyreeve-vault")

    struct Run {
        var status: Int32
        var out: String
        var err: String
    }

    func run(_ arguments: [String], stdin: String = "", home: URL) throws -> Run {
        let process = Process()
        process.executableURL = Self.tool
        process.arguments = arguments
        process.environment = [
            "KEYREEVE_HOME": home.path, "KEYREEVE_VAULT": home.appendingPathComponent("vault").path, "HOME": home.path,
            "PATH": "/usr/bin:/bin", "KEYREEVE_AGENT": "tester",
        ]
        let input = Pipe()
        let output = Pipe()
        let error = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = error
        try process.run()
        input.fileHandleForWriting.write(Data(stdin.utf8))
        try input.fileHandleForWriting.close()
        let deadline = Date().addingTimeInterval(30)
        while process.isRunning && Date() < deadline { usleep(20_000) }
        if process.isRunning {
            process.terminate()
            Issue.record("keyreeve-vault \(arguments.first ?? "") did not finish in 30 seconds")
        }
        process.waitUntilExit()
        return Run(
            status: process.terminationStatus,
            out: String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            err: String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }

    func home() throws -> (URL, VaultStore) {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("vault-cli-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let store = VaultStore(directory: home.appendingPathComponent("vault"))
        try store.create(VaultFile(enclave: chip.publicKey, recovery: recovery.recipient), blob: Data("blob".utf8))
        return (home, store)
    }

    func lastAudit(_ home: URL) throws -> AuditLog.Entry {
        try #require(try AuditLog(url: home.appendingPathComponent("audit.jsonl")).entries().last)
    }

    @Test func addPutAndOrphansFromATerminal() throws {
        try #require(FileManager.default.isExecutableFile(atPath: Self.tool.path), "build the package first")
        let (home, store) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        var outputs: [String] = []

        // add: sealed, with a record no agent sees, and a usage line that says who.
        let added = try run(["add", "added/openai-prod", "--description", "OpenAI production", "--tags", "work,ai"], stdin: first, home: home)
        outputs += [added.out, added.err]
        #expect(added.status == 0, "\(added.err)")
        let index = try KeyIndex.load(from: home.appendingPathComponent(KeyIndex.fileName))
        let record = try #require(index.unoffered.first)
        #expect(index.keys.isEmpty)
        #expect(record.id == "openai-prod")
        #expect(record.description == "OpenAI production")
        #expect(record.more.tags == ["work", "ai"])
        #expect(record.more.reviewed == false)
        #expect(record.more.addedBy?.hasSuffix("/tester") == true)
        let sealedLine = try lastAudit(home)
        #expect(sealedLine.event == "sealed")
        #expect(sealedLine.key == "openai-prod")
        #expect(sealedLine.observed?.program.isEmpty == false)
        #expect((sealedLine.observed?.chain.count ?? 0) >= 2)
        #expect(sealedLine.declared?.agent == record.more.addedBy)
        let listed = try run(["list"], home: home)
        outputs += [listed.out, listed.err]
        #expect(!listed.out.contains("openai-prod"), "agents and list do not see it")

        // put over it: the value waits, and the current one stays in force.
        let put = try run(["put", "added/openai-prod"], stdin: second, home: home)
        outputs += [put.out, put.err]
        #expect(put.status == 0, "\(put.err)")
        #expect(put.out.contains("waiting"))
        let vault = try store.load()
        #expect(try vault.open(name: "added/openai-prod", with: chip) == Data(first.utf8))
        #expect(try vault.open(name: "added/openai-prod#pending", with: chip) == Data(second.utf8))
        #expect(vault.replaced == nil)
        let waitingLine = try lastAudit(home)
        #expect(waitingLine.key == "openai-prod")
        #expect(waitingLine.observed != nil)
        #expect(waitingLine.detail?.contains("waits") == true)

        // An entry an older version sealed with no record shows up, by name.
        try store.update { try $0.add(name: "added/from-before", value: Data(first.utf8)) }
        let orphans = try run(["orphans"], home: home)
        outputs += [orphans.out, orphans.err]
        #expect(orphans.out == "added/from-before\n")

        // No value anywhere: not in what was printed, not in keys.toml, not in the log.
        let files = try [KeyIndex.fileName, "audit.jsonl"].map { try String(contentsOf: home.appendingPathComponent($0), encoding: .utf8) }
        for text in outputs + files { #expect(!text.contains("CANARY"), "\(text)") }
    }

    @Test func addRefusesARotationsNameAndAMissingValue() throws {
        try #require(FileManager.default.isExecutableFile(atPath: Self.tool.path), "build the package first")
        let (home, store) = try home()
        defer { try? FileManager.default.removeItem(at: home) }
        #expect(try run(["add", "x#pending"], stdin: first, home: home).status != 0)
        #expect(try run(["add", "x"], stdin: "", home: home).status != 0)
        #expect(try run(["add", "x", "--colour", "red"], stdin: first, home: home).status != 0)
        #expect(try store.load().entries.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent(KeyIndex.fileName).path))
    }
}
