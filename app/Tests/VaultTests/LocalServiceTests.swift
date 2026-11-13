import Foundation
import KeyreeveVault
import Testing

/// A key for a service of the person's own on this Mac: declared in keys.toml, approved with the fingerprint, and
/// sent through the proxy to that one loopback address and port.
final class LocalFixture: @unchecked Sendable {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("local-\(UUID().uuidString)")
    let proxy = FakeProxy()
    var prompts: [String] = []
    var approvals = LocalServices()
    /// Run while the finger is on the sensor.
    var duringFinger: () -> Void = {}
    var keys = """
        [[key]]
        id = "mesa-token"
        source = "mesa.env"
        field = "MESA_TOKEN"
        variable = "MESA_TOKEN"
        local = "127.0.0.1:8790"

        [[key]]
        id = "loose"
        source = "l.txt"

        [[key]]
        id = "mail"
        source = "m.env"
        field = "API"
        provider = "resend"
        """
    lazy var log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"))
    lazy var service: KeyService = {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return KeyService(
            index: { try KeyIndex.parse(self.keys) },
            open: { _, prompt in
                self.prompts.append(prompt)
                self.duringFinger()
                return Data("MESA_TOKEN=CANARY-Zq8rT2vX9kLm4NpQ7sWy3BcD6fGh1JkA\nAPI=CANARY-mail\n".utf8)
            },
            proxy: proxy, log: log, localServices: { self.approvals })
    }()

    func use(_ key: String, program: String = "/usr/bin/python3") -> KeyService.Response {
        service.handle(
            .init(op: "use", key: key, program: program, arguments: 3, agent: "claude", reason: "eventos", cwd: "/w"),
            caller: AuditLog.Observed(pid: 42, program: "/bin/zsh", chain: ["zsh", "claude"]))
    }

    deinit { try? FileManager.default.removeItem(at: folder) }
}

struct LocalServiceTests {
    @Test func anAddressIsLoopbackAndAPortAndNothingElse() {
        #expect(LocalServices.address("127.0.0.1:8790") == "127.0.0.1:8790")
        #expect(LocalServices.address(" localhost:8787 ") == "localhost:8787")
        #expect(LocalServices.address("LOCALHOST:8787") == "localhost:8787")
        #expect(LocalServices.address("[::1]:9000") == "[::1]:9000")
        for refused in [
            "127.0.0.1", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:+80", "127.0.0.2:8790", "0.0.0.0:8790",
            "::1:8790", "10.0.0.5:8790", "192.168.1.10:8790", "169.254.169.254:80", "example.com:8790",
            "http://127.0.0.1:8790", "127.0.0.1:８７９０", "",
        ] {
            #expect(LocalServices.address(refused) == nil, "\(refused)")
        }
    }

    @Test func anApprovedKeyGoesToItsServiceWithAStandIn() throws {
        let f = LocalFixture()
        f.approvals = LocalServices(approved: ["mesa-token": "127.0.0.1:8790"])
        let answer = f.use("mesa-token")
        #expect(answer.ok, "\(answer.error ?? "")")
        #expect(answer.standIn == "STAND-IN")
        #expect(answer.local == "127.0.0.1:8790")
        #expect(answer.value == nil)
        #expect(f.proxy.locals == ["127.0.0.1:8790"])
        #expect(f.proxy.added.first?.field == "MESA_TOKEN")
        // The person sees where it goes before giving the finger.
        #expect(f.prompts.count == 1 && f.prompts[0].contains("127.0.0.1:8790"))
        let logged = try String(contentsOf: f.log.url, encoding: .utf8)
        #expect(logged.contains("to 127.0.0.1:8790"))
        #expect(!logged.contains("CANARY"))
        // A second use rides on the same permission, still for that service.
        #expect(f.use("mesa-token").local == "127.0.0.1:8790")
        #expect(f.prompts.count == 1)
    }

    @Test func aServiceTheKeyNamesButThePersonDidNotApproveGetsNothing() throws {
        let f = LocalFixture()
        for approvals in [
            LocalServices(),
            // Approved for another port, or for another key: neither is this one.
            LocalServices(approved: ["mesa-token": "127.0.0.1:8791"]),
            LocalServices(approved: ["loose": "127.0.0.1:8790"]),
        ] {
            f.approvals = approvals
            let answer = f.use("mesa-token")
            #expect(!answer.ok)
            #expect(answer.error?.contains("has not approved") == true, "\(answer.error ?? "")")
        }
        // No finger is spent, and nothing reaches the proxy.
        #expect(f.prompts.isEmpty)
        #expect(f.proxy.added.isEmpty)
        #expect(try String(contentsOf: f.log.url, encoding: .utf8).contains("local service not approved"))
    }

    @Test func aKeyThatNamesSomewhereElseIsRefusedEvenIfApproved() {
        let f = LocalFixture()
        f.keys = f.keys.replacingOccurrences(of: "127.0.0.1:8790", with: "10.0.0.5:8790")
        f.approvals = LocalServices(approved: ["mesa-token": "10.0.0.5:8790"])
        let answer = f.use("mesa-token")
        #expect(!answer.ok)
        #expect(answer.error?.contains("not 127.0.0.1") == true, "\(answer.error ?? "")")
        #expect(f.prompts.isEmpty)
    }

    @Test func aKeyWithNoProviderAndNoServiceStillSaysWhatToDo() {
        let f = LocalFixture()
        let answer = f.use("loose")
        #expect(answer.error?.contains("has no provider") == true)
        #expect(answer.error?.contains("local") == true)
    }

    @Test func anApprovalWithdrawnDuringTheFingerOpensNothing() {
        let f = LocalFixture()
        f.approvals = LocalServices(approved: ["mesa-token": "127.0.0.1:8790"])
        f.duringFinger = { f.approvals = LocalServices() }
        let answer = f.use("mesa-token")
        #expect(!answer.ok)
        #expect(f.proxy.added.isEmpty)
    }

    @Test func severalKeysAtOnceGoEachWhereItWasApproved() {
        let f = LocalFixture()
        f.approvals = LocalServices(approved: ["mesa-token": "127.0.0.1:8790"])
        let answer = f.service.handle(
            .init(op: "use-many", program: "/usr/bin/python3", arguments: 1, agent: "claude", cwd: "/w", keys: ["mesa-token", "mail"]),
            caller: nil)
        let many = answer.many ?? []
        #expect(many.count == 2)
        #expect(many.first { $0.key == "mesa-token" }?.local == "127.0.0.1:8790")
        #expect(many.first { $0.key == "mail" }?.local == nil)
        #expect(f.proxy.locals.sorted { ($0 ?? "") < ($1 ?? "") } == [nil, "127.0.0.1:8790"])
    }

    @Test func applyingNamesTheKeyAndApprovesItOrWritesNothing() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("local-apply-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: folder) }
        let keys = folder.appendingPathComponent("keys.toml")
        let approvals = folder.appendingPathComponent(LocalServices.fileName)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try Data("[[key]]\nid = \"mesa-token\"\nsource = \"m.env\"\n\n[[key]]\nid = \"vps\"\nsource = \"k\"\nprovider = \"ssh\"\n".utf8)
            .write(to: keys)
        #expect(throws: VaultError.self) {
            try LocalServices.apply(["mesa-token": "127.0.0.1:8790", "nobody": "127.0.0.1:1"], keys: keys, approvals: approvals)
        }
        #expect(throws: VaultError.self) { try LocalServices.apply(["vps": "127.0.0.1:22"], keys: keys, approvals: approvals) }
        #expect(throws: VaultError.self) { try LocalServices.apply(["mesa-token": "192.168.0.2:8790"], keys: keys, approvals: approvals) }
        #expect(try KeyIndex.load(from: keys).key("mesa-token")?.local == nil)
        #expect(LocalServices.load(from: approvals).approved.isEmpty)

        try LocalServices.apply(["mesa-token": "LOCALHOST:8790"], keys: keys, approvals: approvals)
        let key = try #require(try KeyIndex.load(from: keys).key("mesa-token"))
        #expect(key.local == "localhost:8790")
        #expect(try LocalServices.load(from: approvals).destination(of: key) == "localhost:8790")
        let mode = try FileManager.default.attributesOfItem(atPath: approvals.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)

        try LocalServices.remove("mesa-token", keys: keys, approvals: approvals)
        #expect(try KeyIndex.load(from: keys).key("mesa-token")?.local == nil)
        #expect(LocalServices.load(from: approvals).approved.isEmpty)
    }

    @Test func keysTomlKeepsTheLocalService() throws {
        let index = try KeyIndex.parse("[[key]]\nid = \"m\"\nsource = \"m.env\"\nlocal = \"127.0.0.1:8790\"\n")
        #expect(index.key("m")?.local == "127.0.0.1:8790")
        #expect(try KeyIndex.parse(index.toml) == index)
        #expect(index.toml.contains("local = \"127.0.0.1:8790\""))
    }

    @Test func onlyALocalKeySendsPlainHTTPThroughTheProxy() throws {
        let endpoint = KeyService.ProxyEndpoint(port: 7777, ca: "/ca", bundle: "/bundle")
        let local = try UseEnvironment(
            answer: KeyService.Response(ok: true, standIn: "S", proxy: endpoint, local: "127.0.0.1:8790"), command: ["python3"],
            variable: "MESA_TOKEN")
        #expect(local.set["HTTP_PROXY"] == "http://127.0.0.1:7777")
        #expect(local.set["http_proxy"] == "http://127.0.0.1:7777")
        #expect(local.set["MESA_TOKEN"] == "S")
        #expect(local.unset.contains("NO_PROXY") && local.unset.contains("no_proxy"))
        let remote = try UseEnvironment(
            answer: KeyService.Response(ok: true, standIn: "S", proxy: endpoint), command: ["curl"], variable: "X")
        #expect(remote.set["HTTP_PROXY"] == nil && remote.set["http_proxy"] == nil)
        #expect(remote.set["HTTPS_PROXY"] == "http://127.0.0.1:7777")
    }

    @Test func aServerGetsTheHashOfARandomTokenAndNothingForAShortOne() throws {
        let token = "Zq8rT2vX9kLm4NpQ7sWy3BcD6fGh1JkAbCdEfGh"
        let verifier = try ServerVerifier.verifier(of: token)
        #expect(verifier.hasPrefix("sha256:") && verifier.count == 7 + 64)
        #expect(!verifier.contains(token))
        // The same SHA-256 any server computes.
        #expect(try ServerVerifier.verifier(of: "a" + String(repeating: "b", count: 30)) == "sha256:" + sha256Hex("a" + String(repeating: "b", count: 30)))
        for weak in ["hunter2", "correct-horse", String(repeating: "7", count: 30), "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_"] {
            #expect(throws: VaultError.self, "\(weak)") { try ServerVerifier.verifier(of: weak) }
        }
    }

    @Test func thePromptSaysWhereTheKeyGoes() {
        let one = FingerPrompt.local([("mesa-token", "127.0.0.1:8790")])
        #expect(one.contains("mesa-token") && one.contains("127.0.0.1:8790"))
        let use = FingerPrompt.use(who: "claude", key: "mesa-token", program: "python3", to: "127.0.0.1:8790")
        #expect(use.contains("127.0.0.1:8790"))
    }
}

private func sha256Hex(_ text: String) -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
    process.arguments = ["-a", "256"]
    let input = Pipe()
    let output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    try? process.run()
    input.fileHandleForWriting.write(Data(text.utf8))
    try? input.fileHandleForWriting.close()
    process.waitUntilExit()
    let line = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    return String(line.split(separator: " ").first ?? "")
}
