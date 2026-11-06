import Foundation
import KeyreeveVault
import Testing

struct KeyIndexTests {
    @Test func testTheFileRoundTrips() throws {
        var index = KeyIndex()
        try index.add(.init(id: "mail-restoiq", source: "dir/a b.env", field: "API_KEY", provider: "resend", project: "restoiq", account: "hola@restoiq.cl", description: "Say \"hi\"", variable: "RESEND_API_KEY"))
        try index.add(.init(id: "netlify", source: "netlify-pat.txt"))
        #expect(try KeyIndex.parse(index.toml) == index)
    }

    @Test func testAccountsTellApartKeysOfOneProviderAndProject() throws {
        var index = KeyIndex()
        #expect(index.suggestion(provider: "instagram", project: "redes", account: "cuenta.uno", source: "a") == "instagram")
        try index.add(.init(id: "instagram", source: "a"))
        #expect(index.suggestion(provider: "instagram", project: "redes", account: "cuenta.uno", source: "b") == "instagram-redes")
        try index.add(.init(id: "instagram-redes", source: "b"))
        #expect(index.suggestion(provider: "instagram", project: "redes", account: "cuenta.dos", source: "c") == "instagram-cuenta-dos")
        try index.add(.init(id: "instagram-cuenta-dos", source: "c"))
        #expect(index.suggestion(provider: "instagram", project: "redes", account: "cuenta.dos@correo.cl", source: "d") == "instagram-cuenta-dos-2")
    }

    @Test func testBadIdentifiersAndFilesAreRefused() throws {
        for id in ["", "Upper", "a b", "-a", "a-", "ñ", "a/b", "a.b", String(repeating: "a", count: 65)] {
            #expect(!KeyIndex.isValid(id: id), "\(id)")
        }
        #expect(KeyIndex.isValid(id: "mail-restoiq-2"))
        var index = KeyIndex()
        try index.add(.init(id: "a", source: "x"))
        XCTAssertThrowsError(try index.add(.init(id: "a", source: "y")))
        for text in [
            "id = \"a\"", "[[key]]\nid = \"a\"", "[[key]]\nsource = \"x\"", "[[key]]\nid = \"a\"\nsource = \"x\"\nother = \"y\"",
            "[[key]]\nid = \"BAD\"\nsource = \"x\"", "[[key]]\nid = \"a\"\nid = \"b\"\nsource = \"x\"",
            "[[key]]\nid = \"a\"\nsource = \"x\"\n[[key]]\nid = \"a\"\nsource = \"y\"",
        ] {
            XCTAssertThrowsError(try KeyIndex.parse(text), text)
        }
    }

    @Test func testSuggestionsReadWellAndNeverCollide() throws {
        var index = KeyIndex()
        #expect(index.suggestion(provider: "netlify", project: "infra", source: "netlify-pat.txt") == "netlify")
        try index.add(.init(id: "netlify", source: "a"))
        #expect(index.suggestion(provider: "netlify", project: "Hernán Zurita", source: "b") == "netlify-hernan-zurita")
        try index.add(.init(id: "netlify-hernan-zurita", source: "b"))
        #expect(index.suggestion(provider: "netlify", project: "Hernán Zurita", source: "c") == "netlify-hernan-zurita-2")
        #expect(index.suggestion(provider: nil, project: nil, source: "dir/My Secret.env.bak") == "my-secret")
        #expect(KeyIndex.isValid(id: index.suggestion(provider: nil, project: nil, source: "...")))
    }
}

struct AuditLogTests {
    func log() -> (AuditLog, URL) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("audit-\(UUID().uuidString).jsonl")
        return (AuditLog(url: url), url)
    }

    @Test func testAnEditShowsWhereItHappened() throws {
        let (log, url) = log()
        defer { try? FileManager.default.removeItem(at: url) }
        for index in 0..<4 { try log.append(event: "used", key: "k\(index)") }
        #expect(log.firstBrokenLine() == nil)
        #expect(try log.entries().map(\.key) == ["k0", "k1", "k2", "k3"])
        var text = try String(contentsOf: url, encoding: .utf8)
        text = text.replacingOccurrences(of: "\"key\":\"k2\"", with: "\"key\":\"zz\"")
        try text.write(to: url, atomically: true, encoding: .utf8)
        #expect(log.firstBrokenLine() == 3)
    }

    @Test func testRemovingALineShows() throws {
        let (log, url) = log()
        defer { try? FileManager.default.removeItem(at: url) }
        for index in 0..<3 { try log.append(event: "used", key: "k\(index)") }
        let lines = try String(contentsOf: url, encoding: .utf8).split(separator: "\n")
        try (lines[0] + "\n" + lines[2] + "\n").write(to: url, atomically: true, encoding: .utf8)
        #expect(log.firstBrokenLine() == 2)
    }

    @Test func testWritersAtTheSameTimeKeepTheChain() throws {
        let (log, url) = log()
        defer { try? FileManager.default.removeItem(at: url) }
        DispatchQueue.concurrentPerform(iterations: 40) { index in try? log.append(event: "used", key: "k\(index)") }
        #expect(try log.entries().count == 40)
        #expect(log.firstBrokenLine() == nil)
    }

    @Test func testTheFileIsPrivate() throws {
        let (log, url) = log()
        defer { try? FileManager.default.removeItem(at: url) }
        try log.append(event: "used", key: "k")
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
    }
}

/// The service, with a counter in place of the finger and a clock the test moves.
final class Fixture: @unchecked Sendable {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("svc-\(UUID().uuidString)")
    var prompts: [String] = []
    var refuse = false
    var now = Date(timeIntervalSince1970: 1_800_000_000)
    lazy var log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"))
    lazy var service: KeyService = {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return KeyService(
            index: { try KeyIndex.parse("[[key]]\nid = \"netlify\"\nsource = \"n.txt\"\naccount = \"mi-cuenta\"\nvariable = \"NETLIFY_AUTH_TOKEN\"\n\n[[key]]\nid = \"mail\"\nsource = \"m.env\"\nfield = \"API\"\n") },
            open: { source, prompt in
                if self.refuse { throw VaultError("the fingerprint was not accepted") }
                self.prompts.append(prompt)
                return Data((source == "m.env" ? "OTHER=x\nAPI=CANARY-mail\n" : "CANARY-netlify\n").utf8)
            },
            log: log, now: { self.now })
    }()
    let caller = AuditLog.Observed(pid: 42, program: "/bin/zsh", chain: ["zsh", "claude"])

    func use(_ key: String, _ program: String = "/usr/local/bin/netlify", seconds: Int? = nil) -> KeyService.Response {
        service.handle(
            .init(op: "use", key: key, seconds: seconds, program: program, arguments: 2, agent: "claude", reason: "deploy", cwd: "/w"),
            caller: caller)
    }

    deinit { try? FileManager.default.removeItem(at: folder) }
}

struct KeyServiceTests {
    @Test func testOneFingerCoversAKeyAndProgramUntilItEnds() throws {
        let f = Fixture()
        #expect(f.use("netlify").value == "CANARY-netlify")
        #expect(f.use("netlify").variable == "NETLIFY_AUTH_TOKEN")
        #expect(f.prompts.count == 1)
        f.now.addTimeInterval(TimeInterval(KeyService.defaultSeconds + 1))
        #expect(f.use("netlify").ok)
        #expect(f.prompts.count == 2)
    }

    @Test func testThePromptNamesTheAccount() throws {
        let f = Fixture()
        _ = f.use("netlify")
        _ = f.use("mail")
        #expect(f.prompts == ["run netlify with the key netlify (mi-cuenta)", "run netlify with the key mail"])
    }

    @Test func testAPermissionForOneProgramDoesNotCoverAnother() throws {
        let f = Fixture()
        _ = f.use("netlify")
        _ = f.use("netlify", "/usr/bin/printenv")
        #expect(f.prompts.count == 2)
    }

    @Test func testAFieldIsWhatComesBack() throws {
        #expect(Fixture().use("mail").value == "CANARY-mail")
    }

    @Test func testARefusedFingerGivesNothingAndIsLogged() throws {
        let f = Fixture()
        f.refuse = true
        let answer = f.use("netlify")
        #expect(!answer.ok)
        #expect(answer.value == nil)
        #expect(try f.log.entries().map(\.event) == ["denied"])
    }

    @Test func testAnUnknownKeyIsRefusedBeforeTheFingerAndLogged() throws {
        let f = Fixture()
        #expect(!f.use("nope").ok)
        #expect(f.prompts.isEmpty)
        #expect(try f.log.entries().map(\.event) == ["refused"])
    }

    @Test func testTheLogSaysWhoAndHoldsNoValue() throws {
        let f = Fixture()
        _ = f.use("netlify")
        _ = f.use("netlify")
        let entries = try f.log.entries()
        #expect(entries.map(\.event) == ["granted", "used", "used"])
        #expect(entries[0].observed?.chain == ["zsh", "claude"])
        #expect(entries[0].declared?.agent == "claude")
        #expect(entries[0].declared?.command == "netlify (2 arguments)")
        let raw = try String(contentsOf: f.log.url, encoding: .utf8)
        #expect(!raw.contains("CANARY"))
        #expect(f.log.firstBrokenLine() == nil)
    }

    @Test func testRevokingEndsPermissionsNow() throws {
        let f = Fixture()
        _ = f.use("netlify")
        _ = f.use("mail")
        #expect(f.service.handle(.init(op: "grants"), caller: nil).grants?.count == 2)
        _ = f.service.handle(.init(op: "revoke", key: "mail"), caller: f.caller)
        #expect(f.service.handle(.init(op: "grants"), caller: nil).grants?.map(\.key) == ["netlify"])
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        #expect(f.service.isIdle)
        #expect(f.service.handle(.init(op: "grants"), caller: nil).grants?.first?.key == nil)
    }

    @Test func testALongPermissionIsCapped() throws {
        let f = Fixture()
        _ = f.use("netlify", seconds: 999_999_999)
        let grant = try #require(f.service.handle(.init(op: "grants"), caller: nil).grants?.first)
        #expect(grant.expires.timeIntervalSince(f.now) == TimeInterval(KeyService.maxSeconds))
    }

    @Test func testOverARealSocketTheCallerIsTakenFromTheSystem() throws {
        let f = Fixture()
        let path = "/tmp/kr-\(UUID().uuidString.prefix(8)).sock"
        defer { unlink(path) }
        let descriptor = try KeySocket.listen(path: path)
        let stop = Flag()
        let service = f.service
        Thread.detachNewThread { KeySocket.serve(descriptor: descriptor, service: service) { stop.value } }
        defer { stop.value = true }
        let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
        let answer = try KeySocket.send(.init(op: "use", key: "netlify", program: "/bin/ls", arguments: 0), path: path, timeout: 5)
        #expect(answer.value == "CANARY-netlify")
        let entry = try #require(try f.log.entries().first)
        #expect(entry.observed?.pid == getpid())
        let chain = entry.observed?.chain ?? []
        #expect(chain.count > 0)
    }

    @Test func testAProgramNamedByItsVersionShowsItsFolderInstead() {
        #expect(CallerIdentity.label(path: "/Users/a/.local/share/claude/versions/2.1.319", name: "2.1.319") == "claude")
        #expect(CallerIdentity.label(path: "/bin/zsh", name: "zsh") == "zsh")
        #expect(CallerIdentity.label(path: nil, name: "zsh") == "zsh")
    }

    final class Flag: @unchecked Sendable { var value = false }
}
