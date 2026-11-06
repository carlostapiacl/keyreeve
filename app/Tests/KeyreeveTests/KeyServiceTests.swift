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

final class FakeProxy: KeyProxy, @unchecked Sendable {
    var added: [(grant: String, provider: String, text: String, field: String?)] = []
    var removed: [String] = []
    var refuses = false
    func add(grant: String, key: String, provider: String, text: String, field: String?, expires: Date) throws -> String {
        if refuses { throw VaultError("this provider cannot use a stand-in") }
        added.append((grant, provider, text, field))
        return "STAND-IN"
    }
    func remove(grant: String) { removed.append(grant) }
    var endpoint: KeyService.ProxyEndpoint { KeyService.ProxyEndpoint(port: 9, ca: "/ca", bundle: "/bundle") }
}

final class FakeDoor: SSHDoorHandle {
    let socket = "/tmp/fake.sock"
    let identity: String? = "/tmp/fake.pub"
    var closed = false
    func close() { closed = true }
}

final class FakeAgents: SSHKeyAgents, @unchecked Sendable {
    let door = FakeDoor()
    var keys: [String] = []
    var check: SSHDoor.ServerCheck?
    func open(
        grant: String, name: String, key: String, seconds: Int, check: @escaping SSHDoor.ServerCheck,
        signed: @escaping SSHDoor.SignatureLog, refused: @escaping SSHDoor.RefusalLog
    ) throws -> SSHDoorHandle {
        keys.append(key)
        self.check = check
        return door
    }
}

/// The service, with a counter in place of the finger and a clock the test moves.
final class Fixture: @unchecked Sendable {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("svc-\(UUID().uuidString)")
    var prompts: [String] = []
    var refuse = false
    var now = Date(timeIntervalSince1970: 1_800_000_000)
    let proxy = FakeProxy()
    let agents = FakeAgents()
    var confirmations: [String] = []
    var confirmAnswer = true
    lazy var log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"))
    lazy var service: KeyService = {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return KeyService(
            index: { try KeyIndex.parse("[[key]]\nid = \"netlify\"\nsource = \"n.txt\"\nprovider = \"netlify\"\naccount = \"mi-cuenta\"\nvariable = \"NETLIFY_AUTH_TOKEN\"\n\n[[key]]\nid = \"mail\"\nsource = \"m.env\"\nfield = \"API\"\nprovider = \"resend\"\n\n[[key]]\nid = \"loose\"\nsource = \"l.txt\"\n\n[[key]]\nid = \"vps\"\nsource = \"vps-key\"\nprovider = \"ssh\"\naccount = \"root\"\n\n[[key]]\nid = \"not-ssh\"\nsource = \"n.txt\"\nprovider = \"ssh\"\n\n[[key]]\nid = \"pinned\"\nsource = \"vps-key\"\nprovider = \"ssh\"\nservers = \"SHA256:one SHA256:two\"\n") },
            open: { source, prompt in
                if self.refuse { throw VaultError("the fingerprint was not accepted") }
                self.prompts.append(prompt)
                if source == "vps-key" { return Data("-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY\n-----END OPENSSH PRIVATE KEY-----\n".utf8) }
                return Data((source == "m.env" ? "OTHER=x\nAPI=CANARY-mail\n" : "CANARY-netlify\n").utf8)
            },
            proxy: proxy, agents: agents,
            confirm: { prompt in
                self.confirmations.append(prompt)
                return self.confirmAnswer
            },
            log: log, now: { self.now })
    }()
    let caller = AuditLog.Observed(pid: 42, program: "/bin/zsh", chain: ["zsh", "claude"])

    func use(_ key: String, _ program: String = "/usr/local/bin/netlify", seconds: Int? = nil, real: Bool? = nil) -> KeyService.Response {
        service.handle(
            .init(op: "use", key: key, seconds: seconds, program: program, arguments: 2, agent: "claude", reason: "deploy", cwd: "/w", real: real),
            caller: caller)
    }

    deinit { try? FileManager.default.removeItem(at: folder) }
}

struct KeyServiceTests {
    @Test func testOneFingerCoversAKeyAndProgramUntilItEnds() throws {
        let f = Fixture()
        #expect(f.use("netlify").standIn == "STAND-IN")
        #expect(f.use("netlify").variable == "NETLIFY_AUTH_TOKEN")
        #expect(f.prompts.count == 1)
        #expect(f.proxy.added.count == 1)
        f.now.addTimeInterval(TimeInterval(KeyService.defaultSeconds + 1))
        #expect(f.use("netlify").ok)
        #expect(f.prompts.count == 2)
    }

    @Test func testAnSSHKeyGoesToAnAgentAndNeverComesBack() throws {
        let f = Fixture()
        let answer = f.use("vps", "/usr/bin/ssh")
        #expect(answer.sshSocket == "/tmp/fake.sock")
        #expect(answer.sshIdentity == "/tmp/fake.pub")
        #expect(answer.value == nil)
        #expect(answer.standIn == nil)
        #expect(f.agents.keys.first?.contains("CANARY") == true)
        #expect(f.proxy.added.isEmpty)
        let encoded = String(decoding: try JSONEncoder().encode(answer), as: UTF8.self)
        #expect(!encoded.contains("CANARY"))
        #expect(!(try String(contentsOf: f.log.url, encoding: .utf8)).contains("CANARY"))
    }

    @Test func testAKeyCalledSSHThatIsNotOneGoesNowhere() throws {
        let f = Fixture()
        let answer = f.use("not-ssh", "/usr/bin/ssh")
        #expect(!answer.ok)
        #expect(f.agents.keys.isEmpty)
        #expect(f.proxy.added.isEmpty)
        #expect(f.service.isIdle)
    }

    @Test func testOneSSHPermissionCoversEveryProgram() throws {
        let f = Fixture()
        #expect(f.use("vps", "/usr/bin/ssh").ok)
        #expect(f.use("vps", "/usr/bin/git").ok)
        #expect(f.use("vps", "/usr/bin/rsync").ok)
        #expect(f.prompts.count == 1)
    }

    @Test func testTheFirstServerIsCoveredAndEachOtherAsks() throws {
        let f = Fixture()
        _ = f.use("vps", "/usr/bin/ssh")
        let check = try #require(f.agents.check)
        #expect(check("SHA256:one"))
        #expect(check("SHA256:one"))
        #expect(f.confirmations.isEmpty)
        #expect(check("SHA256:two"))
        #expect(f.confirmations.count == 1)
        #expect(f.confirmations.first?.contains("SHA256:two") == true)
        #expect(f.confirmations.first?.contains("root") == true)
        #expect(check("SHA256:two"))
        #expect(f.confirmations.count == 1)
        f.confirmAnswer = false
        #expect(!check("SHA256:three"))
        #expect(!check("SHA256:three"))
        #expect(f.confirmations.count == 3, "a no is not remembered as a yes")
    }

    @Test func testAKeyThatNamesItsServersGivesNoFreeFirstOne() throws {
        let f = Fixture()
        _ = f.use("pinned", "/usr/bin/ssh")
        let check = try #require(f.agents.check)
        f.confirmAnswer = false
        #expect(!check("SHA256:invented"))
        #expect(f.confirmations.count == 1)
        #expect(check("SHA256:one"))
        #expect(check("SHA256:two"))
        #expect(f.confirmations.count == 1)
    }

    @Test func testServersMustBeFingerprintsAndSurviveSaving() throws {
        #expect(throws: VaultError.self) {
            try KeyIndex.parse("[[key]]\nid = \"a\"\nsource = \"s\"\nservers = \"my-server\"\n")
        }
        let index = try KeyIndex.parse("[[key]]\nid = \"a\"\nsource = \"s\"\nservers = \"SHA256:x SHA256:y\"\n")
        #expect(index.key("a")?.servers == ["SHA256:x", "SHA256:y"])
        #expect(try KeyIndex.parse(index.toml) == index)
    }

    @Test func testEndingAnSSHPermissionClosesItsDoor() throws {
        let f = Fixture()
        _ = f.use("vps", "/usr/bin/ssh")
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        #expect(f.agents.door.closed)
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

    @Test func testTheFieldGoesToTheProxyAndTheValueNeverComesBack() throws {
        let f = Fixture()
        let answer = f.use("mail")
        #expect(f.proxy.added.first?.text.contains("CANARY-mail") == true)
        #expect(f.proxy.added.first?.field == "API")
        #expect(f.proxy.added.first?.provider == "resend")
        #expect(answer.value == nil)
        let encoded = String(decoding: try JSONEncoder().encode(answer), as: UTF8.self)
        #expect(!encoded.contains("CANARY"))
        #expect(answer.proxy?.port == 9)
    }

    @Test func testTheRealKeyAsksEveryTimeAndIsLoggedApart() throws {
        let f = Fixture()
        #expect(f.use("netlify", real: true).value == "CANARY-netlify")
        #expect(f.use("netlify", real: true).value == "CANARY-netlify")
        #expect(f.prompts.count == 2)
        #expect(f.prompts[0].hasPrefix("give the real key netlify"))
        #expect(f.proxy.added.isEmpty)
        #expect(try f.log.entries().map(\.event) == ["handed", "handed"])
        #expect(f.service.isIdle)
    }

    @Test func testAKeyWithNoProviderHasNowhereToGo() throws {
        let f = Fixture()
        let answer = f.use("loose")
        #expect(!answer.ok)
        #expect(f.prompts.isEmpty)
        #expect(answer.error?.contains("--real") == true)
        #expect(f.use("loose", real: true).ok)
    }

    @Test func testAProviderThatCannotStandInLeavesNoPermission() throws {
        let f = Fixture()
        f.proxy.refuses = true
        #expect(!f.use("netlify").ok)
        #expect(f.service.isIdle)
    }

    @Test func testEndingAPermissionReachesTheProxy() throws {
        let f = Fixture()
        _ = f.use("netlify")
        let grant = f.proxy.added[0].grant
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        #expect(f.proxy.removed == [grant])
        _ = f.use("netlify")
        f.now.addTimeInterval(TimeInterval(KeyService.defaultSeconds + 1))
        #expect(f.service.isIdle)
        #expect(f.proxy.removed.count == 2)
    }

    @Test func testARequestGoesInTheLog() throws {
        let f = Fixture()
        f.service.record(grant: "g", key: "netlify", detail: "GET api.netlify.com/x 200")
        let entry = try #require(try f.log.entries().first)
        #expect(entry.event == "request")
        #expect(entry.detail == "GET api.netlify.com/x 200")
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
        #expect(answer.standIn == "STAND-IN")
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
