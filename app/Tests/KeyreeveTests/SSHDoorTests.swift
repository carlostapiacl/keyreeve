import Foundation
import Testing

@testable import KeyreeveVault

/// Against the real tools: `ssh-agent`, `ssh-add`, `ssh-keygen`, `sshd` and `ssh`, with throwaway keys.
final class SSHLab: @unchecked Sendable {
    let folder = URL(fileURLWithPath: "/tmp/kr-\(UUID().uuidString.prefix(8))")
    var signatures: [SSHDoor.Signature] = []
    var refusals: [String] = []
    var callers: [AuditLog.Observed?] = []
    var allowed: (String) -> Bool = { _ in true }
    var checked: [String] = []
    let lock = NSLock()
    private var servers: [Process] = []
    var door: SSHDoor!

    @discardableResult
    func run(_ tool: String, _ arguments: [String], environment: [String: String] = [:], input: String? = nil) throws -> (status: Int32, output: String) {
        let process = Process()
        let out = Pipe()
        let stdin = Pipe()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin", "HOME": folder.path].merging(environment) { $1 }
        process.standardOutput = out
        process.standardError = out
        process.standardInput = input == nil ? FileHandle.nullDevice : stdin
        try process.run()
        if let input {
            try stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8))
            try stdin.fileHandleForWriting.close()
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    func path(_ name: String) -> String { folder.appendingPathComponent(name).path }

    init() throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path("key")])
        let key = try String(contentsOf: URL(fileURLWithPath: path("key")), encoding: .utf8)
        door = try SSHDoor.open(
            grant: "t", key: key, seconds: 60, folder: folder,
            check: { [unowned self] fingerprint in
                lock.lock()
                defer { lock.unlock() }
                checked.append(fingerprint)
                return allowed(fingerprint)
            },
            signed: { [unowned self] signature, caller in
                lock.lock()
                defer { lock.unlock() }
                signatures.append(signature)
                callers.append(caller)
            },
            refused: { [unowned self] why, _ in
                lock.lock()
                defer { lock.unlock() }
                refusals.append(why)
            })
    }

    /// A real server for this user, trusting the throwaway key. Returns its port and host key's fingerprint.
    func server(_ name: String) throws -> (port: Int, fingerprint: String) {
        let hostKey = path("host-\(name)")
        try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", hostKey])
        let authorized = path("authorized-\(name)")
        try FileManager.default.copyItem(atPath: path("key.pub"), toPath: authorized)
        let port = Int.random(in: 42000...48000)
        let config = """
            Port \(port)
            ListenAddress 127.0.0.1
            HostKey \(hostKey)
            AuthorizedKeysFile \(authorized)
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PubkeyAuthentication yes
            StrictModes no
            UsePAM no
            PidFile \(path("pid-\(name)"))
            """
        try config.write(toFile: path("sshd-\(name)"), atomically: true, encoding: .utf8)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
        process.arguments = ["-D", "-e", "-f", path("sshd-\(name)")]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        servers.append(process)
        usleep(500_000)
        let shown = try run("/usr/bin/ssh-keygen", ["-l", "-f", hostKey + ".pub"]).output
        return (port, shown.split(separator: " ")[1].description)
    }

    /// A real `ssh`, whose only way in is the door. It reads no key file and no config.
    func ssh(port: Int, command: String = "echo logged-in", socket: String? = nil) throws -> (status: Int32, output: String) {
        try run(
            "/usr/bin/ssh",
            [
                "-F", "/dev/null", "-p", String(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=\(path("known"))", "-o", "IdentityFile=/dev/null", "-o", "ConnectTimeout=8",
                "\(NSUserName())@127.0.0.1", command,
            ],
            environment: ["SSH_AUTH_SOCK": socket ?? door.socket])
    }

    deinit {
        door?.close()
        for server in servers { server.terminate() }
        try? FileManager.default.removeItem(at: folder)
    }
}

@Suite(.serialized)
struct SSHDoorTests {
    @Test func testARealLoginGoesThroughAndIsRecorded() throws {
        let lab = try SSHLab()
        let server = try lab.server("a")
        let result = try lab.ssh(port: server.port)
        #expect(result.output.contains("logged-in"), "\(result.output)")
        #expect(lab.signatures.count == 1)
        #expect(lab.signatures.first?.user == NSUserName())
        #expect(lab.signatures.first?.server == server.fingerprint)
        #expect(lab.callers.first??.chain.first == "ssh")
    }

    @Test func testAServerThatIsNotAllowedGetsNoSignature() throws {
        let lab = try SSHLab()
        let server = try lab.server("a")
        lab.allowed = { _ in false }
        let result = try lab.ssh(port: server.port)
        #expect(!result.output.contains("logged-in"))
        #expect(lab.signatures.isEmpty)
        #expect(lab.refusals.contains { $0.contains(server.fingerprint) })
    }

    @Test func testTwoServersAreToldApart() throws {
        let lab = try SSHLab()
        let one = try lab.server("a")
        let two = try lab.server("b")
        #expect(try lab.ssh(port: one.port).output.contains("logged-in"))
        #expect(try lab.ssh(port: two.port).output.contains("logged-in"))
        #expect(lab.signatures.map(\.server) == [one.fingerprint, two.fingerprint])
    }

    @Test func testTheKeyCannotBeTakenOrChangedThroughTheDoor() throws {
        let lab = try SSHLab()
        let environment = ["SSH_AUTH_SOCK": lab.door.socket]
        // Listing public keys works, since ssh needs that.
        #expect(try lab.run("/usr/bin/ssh-add", ["-L"], environment: environment).status == 0)
        // Removing, adding and locking do not.
        #expect(try lab.run("/usr/bin/ssh-add", ["-D"], environment: environment).status != 0)
        try lab.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", lab.path("other")])
        #expect(try lab.run("/usr/bin/ssh-add", [lab.path("other")], environment: environment).status != 0)
        #expect(try lab.run("/usr/bin/ssh-add", ["-L"], environment: environment).output.split(separator: "\n").count == 1)
    }

    @Test func testSigningAFileIsNotALogin() throws {
        let lab = try SSHLab()
        try "hello".write(toFile: lab.path("file"), atomically: true, encoding: .utf8)
        let result = try lab.run(
            "/usr/bin/ssh-keygen", ["-Y", "sign", "-n", "file", "-U", "-f", lab.path("key.pub"), lab.path("file")],
            environment: ["SSH_AUTH_SOCK": lab.door.socket])
        #expect(result.status != 0)
        #expect(lab.signatures.isEmpty)
        #expect(lab.refusals.contains("no server named"))
    }

    @Test func testClosingTheDoorEndsAccess() throws {
        let lab = try SSHLab()
        let server = try lab.server("a")
        lab.door.close()
        #expect(!(try lab.ssh(port: server.port).output.contains("logged-in")))
        #expect(!FileManager.default.fileExists(atPath: lab.door.socket))
    }

    /// A config that points `ssh` elsewhere, as a person's may. The options win over it.
    @Test func testTheCommandReachesTheDoorWhateverTheConfigSays() throws {
        let lab = try SSHLab()
        let server = try lab.server("a")
        let identity = try #require(lab.door.identity)
        #expect(try String(contentsOfFile: identity, encoding: .utf8).hasPrefix("ssh-ed25519 "))
        try "IdentityAgent none\n".write(toFile: lab.path("config"), atomically: true, encoding: .utf8)
        let base = [
            "ssh", "-F", lab.path("config"), "-p", String(server.port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=\(lab.path("known"))", "\(NSUserName())@127.0.0.1", "echo logged-in",
        ]
        let without = try lab.run("/usr/bin/ssh", Array(base.dropFirst()))
        #expect(!without.output.contains("logged-in"), "this config alone cannot get in")
        let command = SSHCommand.arguments(for: base, socket: lab.door.socket, identity: identity)
        let with = try lab.run("/usr/bin/ssh", Array(command.dropFirst()))
        #expect(with.output.contains("logged-in"), "\(with.output)")
        #expect(lab.signatures.count == 1)
        lab.door.close()
        #expect(!FileManager.default.fileExists(atPath: identity))
    }

    @Test func testGitAndRsyncGetTheSameOptionsAndOtherProgramsAreLeftAlone() {
        let variables = SSHCommand.variables(socket: "/run/it's.sock", identity: "/run/k.pub")
        #expect(variables["GIT_SSH_COMMAND"]?.contains("'IdentityAgent=/run/it'\\''s.sock'") == true)
        #expect(variables["RSYNC_RSH"] == variables["GIT_SSH_COMMAND"])
        #expect(SSHCommand.arguments(for: ["git", "push"], socket: "s", identity: "i") == ["git", "push"])
        #expect(SSHCommand.arguments(for: ["/usr/bin/scp", "a", "b"], socket: "s", identity: "i").count == 9)
    }

    private func passphraseLab(_ script: String) throws -> (folder: URL, key: String, askpass: String) {
        let folder = URL(fileURLWithPath: "/tmp/kr-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let path = folder.appendingPathComponent("k").path
        let make = Process()
        make.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        make.arguments = ["-q", "-t", "ed25519", "-N", "secreto", "-f", path]
        make.standardOutput = FileHandle.nullDevice
        try make.run()
        make.waitUntilExit()
        let askpass = folder.appendingPathComponent("ask").path
        try script.write(toFile: askpass, atomically: true, encoding: .utf8)
        chmod(askpass, 0o700)
        return (folder, try String(contentsOfFile: path, encoding: .utf8), askpass)
    }

    @Test func testAKeyWithAPassphraseOpensWhenItIsGiven() throws {
        let lab = try passphraseLab("#!/bin/sh\nprintf '%s\\n' \"$KEYREEVE_ASKPASS\" > \"$0.name\"\necho secreto\n")
        defer { try? FileManager.default.removeItem(at: lab.folder) }
        let door = try SSHDoor.open(
            grant: "p", name: "vps", key: lab.key, seconds: 60, folder: lab.folder, askpass: lab.askpass,
            check: { _ in true }, signed: { _, _ in }, refused: { _, _ in })
        defer { door.close() }
        #expect(door.identity != nil)
        #expect(try String(contentsOfFile: lab.askpass + ".name", encoding: .utf8) == "vps\n")
    }

    @Test func testAWrongPassphraseEndsWhenThePersonStops() throws {
        let lab = try passphraseLab("#!/bin/sh\nif [ -e \"$0.seen\" ]; then exit 1; fi\ntouch \"$0.seen\"\necho equivocada\n")
        defer { try? FileManager.default.removeItem(at: lab.folder) }
        XCTAssertThrowsError(
            try SSHDoor.open(
                grant: "p", name: "vps", key: lab.key, seconds: 60, folder: lab.folder, askpass: lab.askpass,
                check: { _ in true }, signed: { _, _ in }, refused: { _, _ in }))
        #expect(FileManager.default.fileExists(atPath: lab.askpass + ".seen"))
    }

    @Test func testAnAgentWithNoDoorDoesNotStayWithTheKey() throws {
        let lab = try SSHLab()
        let key = try String(contentsOf: URL(fileURLWithPath: lab.path("key")), encoding: .utf8)
        let run = lab.folder.appendingPathComponent("broken")
        try FileManager.default.createDirectory(at: run, withIntermediateDirectories: true)
        // A folder where the door's socket goes, so opening it fails after the key is loaded.
        try FileManager.default.createDirectory(atPath: run.appendingPathComponent("s-x.sock").path, withIntermediateDirectories: true)
        XCTAssertThrowsError(
            try SSHDoor.open(grant: "x", key: key, seconds: 60, folder: run, check: { _ in true }, signed: { _, _ in }, refused: { _, _ in }))
        usleep(300_000)
        #expect(try lab.run("/usr/bin/pgrep", ["-f", run.appendingPathComponent("a-x.sock").path]).status != 0)
    }

    @Test func testAKeyWithAPassphraseIsRefusedPlainly() throws {
        let folder = URL(fileURLWithPath: "/tmp/kr-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let key = folder.appendingPathComponent("k").path
        let make = Process()
        make.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        make.arguments = ["-q", "-t", "ed25519", "-N", "secreto", "-f", key]
        make.standardOutput = FileHandle.nullDevice
        try make.run()
        make.waitUntilExit()
        XCTAssertThrowsError(
            try SSHDoor.open(
                grant: "p", key: try String(contentsOfFile: key, encoding: .utf8), seconds: 60, folder: folder,
                check: { _ in true }, signed: { _, _ in }, refused: { _, _ in }))
    }

    /// The whole way: the service opens the key, starts the agent, logs, and revoking ends it.
    @Test func testTheServiceGivesARealLoginAndTakesItBack() throws {
        let lab = try SSHLab()
        let server = try lab.server("a")
        let other = try lab.server("b")
        let key = try Data(contentsOf: URL(fileURLWithPath: lab.path("key")))
        let run = lab.folder.appendingPathComponent("run")
        let log = AuditLog(url: lab.folder.appendingPathComponent("audit.jsonl"))
        let service = KeyService(
            index: { try KeyIndex.parse("[[key]]\nid = \"vps\"\nsource = \"k\"\nprovider = \"ssh\"\n") },
            open: { _, _ in key }, proxy: nil, agents: SystemSSHAgents(folder: run), confirm: { _ in false }, log: log)
        let answer = service.handle(.init(op: "use", key: "vps", program: "/usr/bin/ssh"), caller: nil)
        let socket = try #require(answer.sshSocket)
        #expect(try lab.ssh(port: server.port, socket: socket).output.contains("logged-in"))
        #expect(!(try lab.ssh(port: other.port, socket: socket).output.contains("logged-in")), "the finger said no")
        let entries = try log.entries()
        #expect(entries.contains { $0.event == "signed" && $0.detail?.contains(server.fingerprint) == true })
        #expect(entries.contains { $0.event == "denied" && $0.detail?.contains(other.fingerprint) == true })
        #expect(!(try String(contentsOf: log.url, encoding: .utf8)).contains("PRIVATE"))
        _ = service.handle(.init(op: "revoke"), caller: nil)
        #expect(!(try lab.ssh(port: server.port, socket: socket).output.contains("logged-in")))
        #expect(!FileManager.default.fileExists(atPath: socket))
    }

    @Test func testAnAgentLeftByAKilledServiceIsCleared() throws {
        let lab = try SSHLab()
        let key = try String(contentsOf: URL(fileURLWithPath: lab.path("key")), encoding: .utf8)
        let run = lab.folder.appendingPathComponent("run")
        // Never closed, as when the service is killed.
        let left = try SSHDoor.open(
            grant: "old", key: key, seconds: 60, folder: run, check: { _ in true }, signed: { _, _ in }, refused: { _, _ in })
        let agentSocket = run.appendingPathComponent("a-old.sock").path
        #expect(try lab.run("/usr/bin/ssh-add", ["-l"], environment: ["SSH_AUTH_SOCK": agentSocket]).status == 0)
        _ = SystemSSHAgents(folder: run)
        #expect(try lab.run("/usr/bin/ssh-add", ["-l"], environment: ["SSH_AUTH_SOCK": agentSocket]).status != 0)
        #expect(!FileManager.default.fileExists(atPath: agentSocket))
        // Removing the socket is not enough: the process holds the key, so it has to be gone.
        usleep(300_000)
        #expect(try lab.run("/usr/bin/pgrep", ["-f", agentSocket]).status != 0)
        withExtendedLifetime(left) {}
    }

    @Test func testParsingTakesNothingOnFaith() {
        #expect(SSHDoor.sessionBind(Data([27])) == nil)
        #expect(SSHDoor.sessionBind(Data([27, 0, 0, 0, 99, 1])) == nil)
        #expect(SSHDoor.login(inSignRequest: Data([13])) == nil)
        #expect(SSHDoor.login(inSignRequest: Data([13, 0, 0, 0, 1, 7, 0, 0, 0, 0])) == nil)
    }
}

/// What a real `ssh` never sends, so only a client written for the purpose can test it.
final class DoorProbe: @unchecked Sendable {
    let folder = URL(fileURLWithPath: "/tmp/kp-\(UUID().uuidString.prefix(8))")
    var bindAccepted = true
    var signAccepted = true
    var received: [UInt8] = []
    var signatures: [SSHDoor.Signature] = []
    var refusals: [String] = []
    var door: SSHDoor!
    let lock = NSLock()

    init() throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let agentSocket = folder.appendingPathComponent("agent").path
        let listener = try KeySocket.bound(path: agentSocket)
        Thread.detachNewThread { [self] in
            while true {
                let client = accept(listener, nil, nil)
                guard client >= 0 else { return }
                Thread.detachNewThread { [self] in
                    while let frame = SSHDoor.readFrame(client), let kind = frame.first {
                        lock.lock()
                        received.append(kind)
                        let accepted = bindAccepted
                        let signs = signAccepted
                        lock.unlock()
                        let reply: [UInt8] = kind == 27 ? [accepted ? 6 : 5] : kind == 13 ? (signs ? [14, 0, 0, 0, 1, 9] : [5]) : [12, 0, 0, 0, 0]
                        _ = SSHDoor.writeFrame(client, Data(reply))
                    }
                    close(client)
                }
            }
        }
        door = try SSHDoor(
            socket: folder.appendingPathComponent("door").path, upstream: agentSocket, agent: nil,
            check: { $0 != SSHDoor.fingerprint(Data("banned".utf8)) },
            signed: { [unowned self] signature, _ in
                lock.lock()
                defer { lock.unlock() }
                signatures.append(signature)
            },
            refused: { [unowned self] why, _ in
                lock.lock()
                defer { lock.unlock() }
                refusals.append(why)
            })
    }

    deinit {
        door.close()
        try? FileManager.default.removeItem(at: folder)
    }

    static func string(_ data: Data) -> Data {
        var out = withUnsafeBytes(of: UInt32(data.count).bigEndian) { Data($0) }
        out.append(data)
        return out
    }

    static func bind(host: String = "host", session: String = "session", forwarding: Bool = false) -> Data {
        var out = Data([27])
        out.append(string(Data("session-bind@openssh.com".utf8)))
        out.append(string(Data(host.utf8)))
        out.append(string(Data(session.utf8)))
        out.append(string(Data("signature".utf8)))
        out.append(forwarding ? 1 : 0)
        return out
    }

    static func sign(
        session: String = "session", service: String = "ssh-connection", kind: UInt8 = 50, method: String = "publickey",
        hostKey: String? = nil, extra: Data = Data(), cutAfterService: Bool = false
    ) -> Data {
        var blob = string(Data(session.utf8))
        blob.append(kind)
        blob.append(string(Data("root".utf8)))
        blob.append(string(Data(service.utf8)))
        if !cutAfterService {
            blob.append(string(Data(method.utf8)))
            blob.append(1)
            blob.append(string(Data("ssh-ed25519".utf8)))
            blob.append(string(Data("public-key".utf8)))
            if let hostKey { blob.append(string(Data(hostKey.utf8))) }
            blob.append(extra)
        }
        var out = Data([13])
        out.append(string(Data("public-key".utf8)))
        out.append(string(blob))
        out.append(contentsOf: [0, 0, 0, 0])
        return out
    }

    /// Sends each frame on one connection, and gives back the first byte of each answer.
    func talk(_ frames: [Data]) throws -> [UInt8] {
        let client = try KeySocket.connected(path: door.socket)
        defer { close(client) }
        return frames.compactMap { frame in
            _ = SSHDoor.writeFrame(client, frame)
            return SSHDoor.readFrame(client)?.first
        }
    }
}

@Suite(.serialized)
struct SSHDoorProtocolTests {
    @Test func testALoginBoundToItsSessionIsSigned() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign()]) == [6, 14])
        #expect(probe.signatures == [.init(user: "root", server: SSHDoor.fingerprint(Data("host".utf8)))])
    }

    @Test func testASignatureWithNoServerNamedIsRefused() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.sign()]) == [5])
        #expect(!probe.received.contains(13))
    }

    @Test func testASignatureForAnotherSessionIsRefused() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(session: "other")]) == [6, 5])
        #expect(!probe.received.contains(13))
    }

    @Test func testWhatIsNotALoginIsRefused() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(kind: 51)]) == [6, 5])
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(service: "something-else")]) == [6, 5])
        #expect(!probe.received.contains(13))
    }

    @Test func testOnlyAWholeLoginIsALogin() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(cutAfterService: true)]) == [6, 5])
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(extra: Data("more".utf8))]) == [6, 5])
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(method: "password")]) == [6, 5])
        #expect(!probe.received.contains(13))
    }

    @Test func testALoginNamingItsServerMustNameTheBoundOne() throws {
        let probe = try DoorProbe()
        let hostbound = "publickey-hostbound-v00@openssh.com"
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(method: hostbound, hostKey: "other")]) == [6, 5])
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(method: hostbound)]) == [6, 5], "that method needs the key")
        #expect(!probe.received.contains(13))
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign(method: hostbound, hostKey: "host")]) == [6, 14])
    }

    @Test func testWhatTheAgentRefusedIsNotWrittenDownAsSigned() throws {
        let probe = try DoorProbe()
        probe.signAccepted = false
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign()]) == [6, 5])
        #expect(probe.signatures.isEmpty)
    }

    @Test func testClosingEndsThoseStillConnected() throws {
        let probe = try DoorProbe()
        let client = try KeySocket.connected(path: probe.door.socket)
        defer { close(client) }
        #expect(SSHDoor.writeFrame(client, Data([11])))
        #expect(SSHDoor.readFrame(client) != nil)
        probe.door.close()
        var patience = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &patience, socklen_t(MemoryLayout<timeval>.size))
        var byte: UInt8 = 0
        #expect(read(client, &byte, 1) == 0, "the door hung up")
    }

    @Test func testAServerTheAgentDidNotAcceptCountsForNothing() throws {
        let probe = try DoorProbe()
        probe.bindAccepted = false
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.sign()]) == [5, 5])
        #expect(!probe.received.contains(13))
    }

    @Test func testAForwardedAgentCannotSign() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.bind(), DoorProbe.bind(forwarding: true), DoorProbe.sign()]) == [6, 5, 5])
        #expect(!probe.received.contains(13))
    }

    @Test func testAServerThatIsNotAllowedGetsNothing() throws {
        let probe = try DoorProbe()
        #expect(try probe.talk([DoorProbe.bind(host: "banned"), DoorProbe.sign()]) == [6, 5])
        #expect(!probe.received.contains(13))
    }

    @Test func testOnlyListingSigningAndBindingReachTheAgent() throws {
        let probe = try DoorProbe()
        let others: [UInt8] = [1, 2, 9, 17, 18, 19, 20, 22, 23, 25, 26, 42, 200]
        #expect(try probe.talk(others.map { Data([$0]) }) == others.map { _ in 5 })
        var query = Data([27])
        query.append(DoorProbe.string(Data("query".utf8)))
        #expect(try probe.talk([query]) == [5])
        #expect(probe.received.isEmpty)
        #expect(try probe.talk([Data([11])]) == [12])
    }
}
