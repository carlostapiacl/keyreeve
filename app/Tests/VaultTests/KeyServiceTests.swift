import Foundation
import KeyreeveVault
import Testing

struct KeyIndexTests {
    @Test func testTheFileRoundTrips() throws {
        var index = KeyIndex()
        try index.add(.init(id: "mail-shop", source: "dir/a b.env", field: "API_KEY", provider: "resend", project: "shop", account: "hello@shop.example", description: "Say \"hi\"", variable: "RESEND_API_KEY"))
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

    @Test func aLargeIndexIsReadInOnePassAndStillRefusesATwin() throws {
        let many = (0..<5000).reversed().map { "[[key]]\nid = \"k-\($0)\"\nsource = \"s\($0)\"\n" }.joined(separator: "\n")
        let started = Date()
        let index = try KeyIndex.parse(many)
        #expect(Date().timeIntervalSince(started) < 2)
        #expect(index.keys.count == 5000 && index.keys.first?.id == "k-0" && index.keys.map(\.id) == index.keys.map(\.id).sorted())
        #expect(throws: VaultError.self) { try KeyIndex.parse(many + "\n[[key]]\nid = \"k-7\"\nsource = \"x\"\n") }
    }

    @Test func testBadIdentifiersAndFilesAreRefused() throws {
        for id in ["", "Upper", "a b", "-a", "a-", "ñ", "a/b", "a.b", String(repeating: "a", count: 65)] {
            #expect(!KeyIndex.isValid(id: id), "\(id)")
        }
        #expect(KeyIndex.isValid(id: "mail-shop-2"))
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

    @Test func aNameInYourOwnWordsGetsAValidFreeIdentifier() throws {
        var index = KeyIndex()
        #expect(index.identifier(for: "Mi clave de correo") == "mi-clave-de-correo")
        #expect(index.identifier(for: "Clave Andrés · QA") == "clave-andres-qa")
        #expect(index.identifier(for: "¿?") == "key")
        try index.add(.init(id: "pagos", source: "a"))
        #expect(index.identifier(for: "Pagos") == "pagos-2")
        let long = index.identifier(for: String(repeating: "palabra ", count: 20))
        #expect(KeyIndex.isValid(id: long) && long.count <= 43)
    }

    @Test func testSuggestionsReadWellAndNeverCollide() throws {
        var index = KeyIndex()
        #expect(index.suggestion(provider: "netlify", project: "infra", source: "netlify-pat.txt") == "netlify")
        try index.add(.init(id: "netlify", source: "a"))
        #expect(index.suggestion(provider: "netlify", project: "Ramón Ortiz", source: "b") == "netlify-ramon-ortiz")
        try index.add(.init(id: "netlify-ramon-ortiz", source: "b"))
        #expect(index.suggestion(provider: "netlify", project: "Ramón Ortiz", source: "c") == "netlify-ramon-ortiz-2")
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

    @Test func theRecentEntriesAndTheChainComeFromOneReading() throws {
        let (log, url) = log()
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(log.recent(2).entries.isEmpty && log.recent(2).brokenLine == nil)
        for index in 0..<7 { try log.append(event: "used", key: "k\(index)") }
        #expect(log.recent(3).entries.map(\.key) == ["k4", "k5", "k6"])
        #expect(log.recent(3).brokenLine == nil)
        #expect(log.recent(50).entries.count == 7)
        var text = try String(contentsOf: url, encoding: .utf8)
        text = text.replacingOccurrences(of: "\"key\":\"k2\"", with: "\"key\":\"zz\"")
        try text.write(to: url, atomically: true, encoding: .utf8)
        #expect(log.recent(3).brokenLine == 3)
        #expect(log.recent(3).entries.map(\.key) == ["k4", "k5", "k6"])
    }

    /// A full log is set aside and the next goes on from it: nothing is lost, the chain holds across files,
    /// writers at the same time all land, and an edit or a missing file in the middle shows.
    @Test func aFullLogIsSetAsideAndTheChainGoesOn() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("segments-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"), segmentLimit: 600)
        var clock = Date(timeIntervalSince1970: 1_800_000_000)
        for index in 0..<12 {
            clock.addTimeInterval(1)
            try log.append(event: "used", key: "k\(index)", now: clock)
        }
        DispatchQueue.concurrentPerform(iterations: 30) { index in
            try? log.append(event: "used", key: "c\(index)", now: Date(timeIntervalSince1970: 1_900_000_000 + Double(index)))
        }
        #expect(log.segments().count > 2)
        #expect(try log.entries().count == 42)
        #expect(log.firstBreak() == nil)
        #expect(log.recent(3).brokenLine == nil && log.recent(3).entries.count <= 3)
        // An edit in a file set aside shows, with its name.
        let middle = log.segments()[1]
        let text = try String(contentsOf: middle, encoding: .utf8)
        let edited = text.replacingOccurrences(of: "\"event\":\"used\"", with: "\"event\":\"usex\"")
        try edited.write(to: middle, atomically: true, encoding: .utf8)
        #expect(log.firstBreak()?.file == middle.lastPathComponent)
        try text.write(to: middle, atomically: true, encoding: .utf8)
        #expect(log.firstBreak() == nil)
        // A file set aside that goes missing breaks the link to the next.
        try FileManager.default.removeItem(at: middle)
        #expect(log.firstBreak() != nil)
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

    @Test func aLogThatCannotBeReadIsNotCalledWhole() throws {
        let (log, url) = log()
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            try? FileManager.default.removeItem(at: url)
        }
        #expect(log.firstBrokenLine() == nil)
        try log.append(event: "used", key: "k")
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: url.path)
        #expect(log.firstBrokenLine() == 0)
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
    var paused = false
    /// Turns the pause on while the finger is on the sensor.
    var pauseDuringFinger = false
    /// How long the person takes at the sensor, on the test's clock.
    var fingerTakes: TimeInterval = 0
    /// Which sealing the vault holds now.
    var sealing: String? = "r1"
    /// Run while the finger is on the sensor.
    var duringFinger: () -> Void = {}
    /// Changes keys.toml: the netlify key's account, as an edit made elsewhere would.
    var account = "mi-cuenta"
    /// Whether the person's files mark a key "always, no fingerprint": what the service itself reads.
    var markedAlways: Set<String> = []
    lazy var log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"))
    lazy var service: KeyService = {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return KeyService(
            index: { try KeyIndex.parse("[[key]]\nid = \"netlify\"\nsource = \"n.txt\"\nprovider = \"netlify\"\naccount = \"\(self.account)\"\nvariable = \"NETLIFY_AUTH_TOKEN\"\n\n[[key]]\nid = \"mail\"\nsource = \"m.env\"\nfield = \"API\"\nprovider = \"resend\"\n\n[[key]]\nid = \"loose\"\nsource = \"l.txt\"\n\n[[key]]\nid = \"vps\"\nsource = \"vps-key\"\nprovider = \"ssh\"\naccount = \"root\"\n\n[[key]]\nid = \"not-ssh\"\nsource = \"n.txt\"\nprovider = \"ssh\"\n\n[[key]]\nid = \"pinned\"\nsource = \"vps-key\"\nprovider = \"ssh\"\nservers = \"SHA256:one SHA256:two\"\n") },
            open: { source, prompt in
                if self.refuse { throw VaultError("the fingerprint was not accepted") }
                self.prompts.append(prompt)
                if self.pauseDuringFinger { self.paused = true }
                self.duringFinger()
                self.now.addTimeInterval(self.fingerTakes)
                if source == "vps-key" { return Data("-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY\n-----END OPENSSH PRIVATE KEY-----\n".utf8) }
                return Data((source == "m.env" ? "OTHER=x\nAPI=CANARY-mail\n" : "CANARY-netlify\n").utf8)
            },
            proxy: proxy, agents: agents,
            confirm: { prompt in
                self.confirmations.append(prompt)
                return self.confirmAnswer
            },
            log: log, now: { self.now }, paused: { self.paused }, revision: { _ in self.sealing },
            openUnattended: { key, _, source in
                self.markedAlways.contains(key) ? Data((source == "m.env" ? "API=CANARY-mail\n" : "CANARY-netlify\n").utf8) : nil
            })
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

    /// `revoke` must get through while your finger is being waited for, and must also stop what comes of it.
    @Test func testRevokingDoesNotWaitForAPromptAndEndsWhatItOpens() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("svc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let touching = DispatchSemaphore(value: 0)
        let touched = DispatchSemaphore(value: 0)
        let proxy = FakeProxy()
        let service = KeyService(
            index: { try KeyIndex.parse("[[key]]\nid = \"n\"\nsource = \"s\"\nprovider = \"netlify\"\n") },
            open: { _, _ in
                touching.signal()
                touched.wait()
                return Data("CANARY\n".utf8)
            },
            proxy: proxy, log: AuditLog(url: folder.appendingPathComponent("a.jsonl")))
        let using = Task.detached { service.handle(.init(op: "use", key: "n", program: "/bin/x"), caller: nil) }
        touching.wait()
        let started = Date()
        #expect(service.handle(.init(op: "revoke"), caller: nil).ok)
        #expect(service.handle(.init(op: "grants"), caller: nil).grants?.isEmpty == true)
        // Waiting for the prompt would take until the signal below, so any short bound shows it.
        #expect(Date().timeIntervalSince(started) < 5)
        touched.signal()
        let answer = await using.value
        #expect(!answer.ok)
        #expect(answer.standIn == nil)
        #expect(service.isIdle)
    }

    /// A key the person marked "always" opens with no prompt; a caller that only claims it is asked as usual.
    @Test func onlyAKeyMarkedByThePersonOpensWithNoFingerprint() throws {
        let f = Fixture()
        var request = KeyService.Request(op: "use", key: "netlify", program: "/usr/bin/curl", agent: "motor", reason: "stats")
        request.unattended = true
        request.anyProgram = true
        // Claimed, not marked: the finger is asked.
        #expect(f.service.handle(request, caller: f.caller).ok)
        #expect(f.prompts.count == 1)
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        f.markedAlways = ["netlify"]
        let answer = f.service.handle(request, caller: f.caller)
        #expect(answer.ok && answer.standIn == "STAND-IN" && answer.value == nil)
        #expect(f.prompts.count == 1)
        #expect(try f.log.entries().contains { $0.event == "granted" && $0.detail?.hasSuffix("no fingerprint") == true })
        // The real key always asks, marked or not.
        _ = f.use("netlify", real: true)
        #expect(f.prompts.count == 2)
    }

    /// A key replaced in the vault ends the permission for the old value: the next use asks for the new one.
    @Test func aReplacedKeyEndsThePermissionForTheOldValue() throws {
        let f = Fixture()
        #expect(f.use("netlify").ok)
        #expect(f.use("netlify").ok)
        #expect(f.prompts.count == 1)
        f.sealing = "r2"
        #expect(f.use("netlify").ok)
        #expect(f.prompts.count == 2)
        #expect(f.proxy.removed.count == 1)
        #expect(try f.log.entries().contains { $0.event == "closed" && $0.detail == "replaced in the vault" })
    }

    /// The yes was for the key as keys.toml had it when asked; changed meanwhile, nothing opens.
    @Test func aKeyChangedInTheIndexDuringTheFingerOpensNothing() throws {
        let f = Fixture()
        f.duringFinger = { f.account = "otra-cuenta" }
        let answer = f.use("netlify")
        #expect(!answer.ok && answer.error?.contains("changed in keys.toml") == true)
        #expect(f.proxy.added.isEmpty && f.service.isIdle)
        f.duringFinger = {}
        let real = f.use("netlify", real: true)
        #expect(real.ok)
        f.duringFinger = { f.account = "tercera" }
        #expect(!f.use("netlify", real: true).ok)
    }

    /// A use stuck behind someone else's prompt says which prompt, before the client gives up in silence.
    @Test func aUseBehindAnotherPromptSaysWhatItWaitsFor() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("svc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let touching = DispatchSemaphore(value: 0)
        let touched = DispatchSemaphore(value: 0)
        let log = AuditLog(url: folder.appendingPathComponent("a.jsonl"))
        let service = KeyService(
            index: { try KeyIndex.parse("[[key]]\nid = \"n\"\nsource = \"s\"\nprovider = \"netlify\"\n\n[[key]]\nid = \"m\"\nsource = \"t\"\nprovider = \"netlify\"\n") },
            open: { _, _ in
                touching.signal()
                touched.wait()
                return Data("CANARY\n".utf8)
            },
            proxy: FakeProxy(), log: log, promptWait: 0.2)
        let first = Task.detached { service.handle(.init(op: "use", key: "n", program: "/bin/x", agent: "motor"), caller: nil) }
        touching.wait()
        let second = service.handle(.init(op: "use", key: "m", program: "/bin/y", agent: "claude"), caller: nil)
        #expect(!second.ok)
        #expect(second.error?.contains("waiting for the person's fingerprint for n, asked by motor") == true)
        #expect(try log.entries().contains { $0.event == "refused" && $0.key == "m" && $0.detail == "another fingerprint is pending" })
        touched.signal()
        #expect(await first.value.ok)
        // The turn is free again once the prompt ahead is answered.
        let third = Task.detached { service.handle(.init(op: "use", key: "m", program: "/bin/y", agent: "claude"), caller: nil) }
        touching.wait()
        touched.signal()
        #expect(await third.value.ok)
    }

    @Test func aSilentServiceIsBlamedOnTheFingerprintOnlyForAUse() {
        #expect(KeySocket.silence(for: "use").contains("fingerprint"))
        #expect(!KeySocket.silence(for: "grants").contains("fingerprint"))
        // A lost answer is not a no: none of them may say that nothing happened.
        for op in ["use", "revoke", "grants"] { #expect(!KeySocket.silence(for: op).lowercased().contains("nothing changed")) }
    }

    @Test func testAUseThatCannotBeLoggedLeavesNoPermission() throws {
        let f = Fixture()
        _ = f.service
        // A folder where the log goes, so nothing can be written.
        try FileManager.default.createDirectory(at: f.log.url, withIntermediateDirectories: true)
        #expect(!f.use("vps", "/usr/bin/ssh").ok)
        #expect(f.agents.door.closed)
        #expect(f.service.isIdle)
        #expect(!f.use("netlify").ok)
        #expect(f.service.isIdle)
    }

    @Test func testALongDirectoryDoesNotJamTheLog() throws {
        let f = Fixture()
        _ = f.service
        let long = String(repeating: "d", count: 70_000)
        #expect(f.service.handle(.init(op: "use", key: "netlify", program: "/bin/x", cwd: long), caller: nil).ok)
        #expect(f.use("netlify").ok)
        #expect(f.log.firstBrokenLine() == nil)
    }

    @Test func testADurationTooLargeIsRefusedAndNotACrash() {
        #expect(KeyService.seconds(from: "9223372036854775807h") == nil)
        #expect(KeyService.seconds(from: "90s") == 90)
        #expect(KeyService.seconds(from: "5m") == 300)
        #expect(KeyService.seconds(from: "2h") == 7200)
        #expect(KeyService.seconds(from: "5x") == nil)
    }

    @Test func testAKeyIndexSurvivesANewlineInAFileName() throws {
        let index = KeyIndex(keys: [KeyIndex.Key(id: "a", source: "odd\nname\"\\.txt")])
        #expect(try KeyIndex.parse(index.toml) == index)
    }

    @Test func testOnlyOneServiceHoldsTheSocket() throws {
        let folder = URL(fileURLWithPath: "/tmp/kl-\(UUID().uuidString.prefix(8))")
        defer { try? FileManager.default.removeItem(at: folder) }
        let path = folder.appendingPathComponent("k.sock").path
        let first = try KeySocket.listen(path: path)
        defer { close(first) }
        #expect(throws: VaultError.self) { try KeySocket.listen(path: path) }
        #expect(KeySocket.isListening(path: path))
    }

    @Test func testThePromptNamesTheAccount() throws {
        let f = Fixture()
        _ = f.use("netlify")
        _ = f.use("mail")
        #expect(f.prompts == [
            FingerPrompt.use(who: "claude", key: "netlify", account: "mi-cuenta", program: "netlify", reason: "deploy"),
            FingerPrompt.use(who: "claude", key: "mail", program: "netlify", reason: "deploy"),
        ])
        #expect(f.prompts[0].contains("(mi-cuenta)"))
    }

    @Test func testAFreeKeyCoversEveryProgramAndOneGrantEndsAlone() throws {
        let f = Fixture()
        let first = f.service.handle(
            .init(op: "use", key: "netlify", seconds: KeyService.maxSeconds, program: "/usr/bin/curl", agent: "claude", anyProgram: true),
            caller: f.caller)
        #expect(first.ok && first.grant != nil)
        #expect(f.use("netlify", "/usr/local/bin/netlify").grant == first.grant)
        #expect(f.prompts.count == 1)
        let mail = f.use("mail")
        // Ending one permission by its id leaves the others.
        _ = f.service.handle(.init(op: "revoke", key: "netlify", grant: first.grant), caller: f.caller)
        let left = f.service.handle(.init(op: "grants"), caller: f.caller).grants ?? []
        #expect(left.map(\.id) == [mail.grant].compactMap { $0 })
    }

    @Test func testTheKeysClosingCutsAPermissionAlreadyInForce() throws {
        let f = Fixture()
        let first = f.use("netlify", seconds: 3600)
        #expect(first.ok)
        let closing = f.now.addingTimeInterval(600)
        let again = f.service.handle(
            .init(op: "use", key: "netlify", program: "/usr/local/bin/netlify", agent: "codex", notAfter: closing), caller: f.caller)
        #expect(again.grant == first.grant && f.prompts.count == 1)
        #expect(f.service.handle(.init(op: "grants"), caller: f.caller).grants?.first?.expires == closing)
        // The service's own clock ends it at the closing, and the proxy hears it.
        f.now = closing.addingTimeInterval(1)
        #expect(f.service.isIdle)
        #expect(f.proxy.removed == [first.grant].compactMap { $0 })
    }

    @Test func aNewPermissionNeverOutlastsTheClosingCountedAfterTheFinger() throws {
        let f = Fixture()
        let closing = f.now.addingTimeInterval(60)
        let answer = f.service.handle(
            .init(op: "use", key: "netlify", seconds: 3600, program: "/usr/bin/curl", notAfter: closing), caller: f.caller)
        #expect(answer.ok)
        #expect(f.service.handle(.init(op: "grants"), caller: f.caller).grants?.first?.expires == closing)
    }

    @Test func thePauseStopsAUseBeforeAndWhileTheFingerIsAsked() throws {
        let f = Fixture()
        f.paused = true
        #expect(!f.use("netlify").ok)
        #expect(f.prompts.isEmpty)
        // Stopped while the person's finger was on its way: nothing is left open.
        f.paused = false
        f.pauseDuringFinger = true
        let answer = f.use("netlify")
        #expect(!answer.ok && f.prompts.count == 1)
        #expect(f.service.handle(.init(op: "grants"), caller: f.caller).grants?.isEmpty == true)
        #expect(f.proxy.added.count == f.proxy.removed.count)
    }

    @Test func thePauseWhileTheFingerIsAskedStopsTheRealKey() throws {
        let f = Fixture()
        f.pauseDuringFinger = true
        let answer = f.use("netlify", real: true)
        #expect(!answer.ok && answer.value == nil)
        #expect(f.prompts.count == 1)
        #expect(try !f.log.entries().contains { $0.event == "handed" })
    }

    @Test func aKeyThatClosesWhileTheFingerIsAskedGivesNothing() throws {
        let f = Fixture()
        f.fingerTakes = 120
        let answer = f.service.handle(
            .init(op: "use", key: "netlify", seconds: 3600, program: "/usr/bin/curl", notAfter: f.now.addingTimeInterval(60)),
            caller: f.caller)
        #expect(!answer.ok)
        #expect(f.proxy.added.isEmpty)
        #expect(f.service.handle(.init(op: "grants"), caller: f.caller).grants?.isEmpty == true)
    }

    @Test func thePauseStopsTheRealKeyToo() throws {
        let f = Fixture()
        f.paused = true
        #expect(!f.use("netlify", real: true).ok)
        #expect(f.prompts.isEmpty)
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
        #expect(f.prompts[0] == FingerPrompt.real(who: "netlify", key: "netlify", account: "mi-cuenta", reason: "deploy"))
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
