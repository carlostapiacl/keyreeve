import CryptoKit
import Foundation

/// Lets `ssh` sign with a key it never holds. The system's own `ssh-agent` keeps the key and does the
/// math, so no signing code lives here. Commands speak to a door in front of it, which passes only
/// listing and signing, knows which server each connection is for, and writes down every signature.
///
/// OpenSSH tells an agent which server it is talking to (`session-bind@openssh.com`, since 8.9) and the
/// agent checks that server's signature, so a client cannot simply claim a server. A signature with
/// no server named, or for another session, is refused. That also refuses signing for anything but a login.
public final class SSHDoor: @unchecked Sendable {
    public struct Signature: Equatable, Sendable {
        public let user: String
        public let server: String
    }

    /// May this permission sign in to this server? It can ask a person.
    public typealias ServerCheck = @Sendable (_ fingerprint: String) -> Bool
    public typealias SignatureLog = @Sendable (_ signature: Signature, _ caller: AuditLog.Observed?) -> Void
    public typealias RefusalLog = @Sendable (_ why: String, _ caller: AuditLog.Observed?) -> Void

    public let socket: String
    /// The public half, for telling `ssh` which key to offer.
    public let identity: String?
    private let upstream: String
    private let listener: Int32
    private let agent: Process?
    private let check: ServerCheck
    private let signed: SignatureLog
    private let refused: RefusalLog
    private let lock = NSLock()
    private var closed = false
    private var clients: Set<Int32> = []

    private enum Message {
        static let failure: UInt8 = 5
        static let identities: UInt8 = 11
        static let sign: UInt8 = 13
        static let signature: UInt8 = 14
        static let success: UInt8 = 6
        static let extensionRequest: UInt8 = 27
    }

    /// Starts an agent for this one key, with the key added from memory, and opens the door.
    public static func open(
        grant: String, name: String = "", key sealed: String, seconds: Int, folder: URL, askpass: String? = nil,
        check: @escaping ServerCheck, signed: @escaping SignatureLog, refused: @escaping RefusalLog
    ) throws -> SSHDoor {
        let private_ = folder.appendingPathComponent("a-\(grant).sock").path
        let agent = Process()
        agent.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-agent")
        agent.arguments = ["-D", "-a", private_]
        agent.standardInput = FileHandle.nullDevice
        agent.standardOutput = FileHandle.nullDevice
        agent.standardError = FileHandle.nullDevice
        // ssh-agent makes its socket private itself, inside this 0700 folder.
        try PrivateFile.folder(folder)
        unlink(private_)
        do {
            try agent.run()
        } catch {
            throw VaultError("ssh-agent could not start")
        }
        func fail(_ text: String) -> VaultError {
            agent.terminate()
            unlink(private_)
            return VaultError(text)
        }
        var waited = 0
        while !FileManager.default.fileExists(atPath: private_), waited < 50 {
            usleep(100_000)
            waited += 1
        }
        guard FileManager.default.fileExists(atPath: private_) else { throw fail("ssh-agent could not start") }
        // The key goes in on stdin. It also has a limit of its own, in case this process dies.
        let add = Process()
        let input = Pipe()
        _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        add.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
        add.arguments = ["-q", "-t", String(seconds), "-"]
        var environment = ["SSH_AUTH_SOCK": private_, "PATH": "/usr/bin:/bin"]
        if let askpass {
            // Only a key with a passphrase ever calls this.
            environment["SSH_ASKPASS"] = askpass
            environment["SSH_ASKPASS_REQUIRE"] = "force"
            environment[SSHCommand.askpassVariable] = name
        } else {
            environment["SSH_ASKPASS_REQUIRE"] = "never"
        }
        add.environment = environment
        add.standardInput = input
        add.standardOutput = FileHandle.nullDevice
        add.standardError = FileHandle.nullDevice
        do {
            try add.run()
        } catch {
            throw fail("ssh-add could not start")
        }
        signal(SIGPIPE, SIG_IGN)
        try? input.fileHandleForWriting.write(contentsOf: Data((sealed.hasSuffix("\n") ? sealed : sealed + "\n").utf8))
        try? input.fileHandleForWriting.close()
        add.waitUntilExit()
        guard add.terminationStatus == 0 else {
            throw fail("this SSH key could not be loaded, or its passphrase was not given")
        }
        let identity = writePublicKey(agent: private_, to: folder.appendingPathComponent("s-\(grant).pub").path)
        do {
            return try SSHDoor(
                socket: folder.appendingPathComponent("s-\(grant).sock").path, identity: identity, upstream: private_, agent: agent,
                check: check, signed: signed, refused: refused)
        } catch {
            // Nothing will ever close an agent that has no door, and it holds the key.
            agent.terminate()
            unlink(private_)
            if let identity { unlink(identity) }
            throw error
        }
    }

    private static func writePublicKey(agent: String, to path: String) -> String? {
        let list = Process()
        let output = Pipe()
        list.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
        list.arguments = ["-L"]
        list.environment = ["SSH_AUTH_SOCK": agent, "PATH": "/usr/bin:/bin"]
        list.standardInput = FileHandle.nullDevice
        list.standardOutput = output
        list.standardError = FileHandle.nullDevice
        guard (try? list.run()) != nil else { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        list.waitUntilExit()
        guard list.terminationStatus == 0, !data.isEmpty, FileManager.default.createFile(atPath: path, contents: data) else { return nil }
        return path
    }

    /// Opens a door in front of an agent that is already running.
    public init(
        socket: String, identity: String? = nil, upstream: String, agent: Process?,
        check: @escaping ServerCheck, signed: @escaping SignatureLog, refused: @escaping RefusalLog
    ) throws {
        self.socket = socket
        self.identity = identity
        self.upstream = upstream
        self.agent = agent
        self.check = check
        self.signed = signed
        self.refused = refused
        listener = try KeySocket.bound(path: socket)
        Thread.detachNewThread { [self] in acceptLoop() }
    }

    public func close() {
        lock.lock()
        let already = closed
        closed = true
        let open = clients
        lock.unlock()
        guard !already else { return }
        // Those waiting for their next message end now, and take their sockets with them.
        for client in open { shutdown(client, SHUT_RDWR) }
        shutdown(listener, SHUT_RDWR)
        Darwin.close(listener)
        agent?.terminate()
        unlink(socket)
        if let identity { unlink(identity) }
        if agent != nil { unlink(upstream) }
    }

    deinit { close() }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    private func acceptLoop() {
        while !isClosed {
            let client = accept(listener, nil, nil)
            guard client >= 0 else {
                if isClosed { return }
                usleep(10_000)
                continue
            }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            lock.lock()
            let admitted = !closed
            if admitted { clients.insert(client) }
            lock.unlock()
            guard admitted else {
                Darwin.close(client)
                return
            }
            Thread.detachNewThread { [self] in
                defer {
                    lock.lock()
                    clients.remove(client)
                    lock.unlock()
                    Darwin.close(client)
                }
                serve(client)
            }
        }
    }

    /// One client, which is one `ssh`. What it was told about its server lasts for this connection.
    private func serve(_ client: Int32) {
        guard let pid = CallerIdentity.peer(of: client) else { return }
        let caller = CallerIdentity.observe(pid: pid)
        guard let up = try? KeySocket.connected(path: upstream) else { return }
        defer { Darwin.close(up) }
        var server: BoundServer?
        while !isClosed, let frame = Self.readFrame(client), let kind = frame.first {
            let answer: Data?
            switch kind {
            case Message.identities:
                answer = Self.relay(frame, to: up)
            case Message.extensionRequest:
                guard let bind = Self.sessionBind(frame) else {
                    answer = Self.failure
                    break
                }
                // The agent checks the server's signature. Only its yes counts.
                let reply = Self.relay(frame, to: up)
                if reply?.first == Message.success {
                    // A forwarded connection is a server asking, so it is not one to sign for.
                    if bind.forwarding {
                        server = nil
                        refused("a forwarded agent", caller)
                        answer = Self.failure
                    } else {
                        server = BoundServer(fingerprint: Self.fingerprint(bind.hostKey), hostKey: bind.hostKey, session: bind.session)
                        answer = reply
                    }
                } else {
                    answer = Self.failure
                }
            case Message.sign:
                answer = sign(frame, server: server, up: up, caller: caller)
            default:
                // Adding, removing or locking keys is not for what comes through here.
                answer = Self.failure
            }
            guard let answer, Self.writeFrame(client, answer) else { return }
        }
    }

    private struct BoundServer {
        let fingerprint: String
        let hostKey: Data
        let session: Data
    }

    private func sign(
        _ frame: Data, server: BoundServer?, up: Int32, caller: AuditLog.Observed?
    ) -> Data {
        guard let server else {
            refused("no server named", caller)
            return Self.failure
        }
        guard let login = Self.login(inSignRequest: frame), login.session == server.session,
            login.hostKey == nil || login.hostKey == server.hostKey
        else {
            refused("not a login to that server", caller)
            return Self.failure
        }
        guard check(server.fingerprint) else {
            refused("server not allowed: \(server.fingerprint)", caller)
            return Self.failure
        }
        guard let reply = Self.relay(frame, to: up) else { return Self.failure }
        // Only a signature counts as signed. The agent can still say no.
        if reply.first == Message.signature { signed(Signature(user: login.user, server: server.fingerprint), caller) }
        return reply
    }

    private static let failure = Data([Message.failure])

    // MARK: Reading the protocol

    private struct Reader {
        var data: Data
        mutating func string() -> Data? {
            guard data.count >= 4 else { return nil }
            let length = data.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            guard data.count >= 4 + length else { return nil }
            let out = data.dropFirst(4).prefix(length)
            data = Data(data.dropFirst(4 + length))
            return Data(out)
        }
        mutating func byte() -> UInt8? {
            guard let first = data.first else { return nil }
            data = Data(data.dropFirst())
            return first
        }
    }

    /// `session-bind@openssh.com`: the server's public key, the session, its signature, and whether forwarded.
    static func sessionBind(_ frame: Data) -> (hostKey: Data, session: Data, forwarding: Bool)? {
        var reader = Reader(data: Data(frame.dropFirst()))
        guard let name = reader.string(), name == Data("session-bind@openssh.com".utf8),
            let hostKey = reader.string(), let session = reader.string(), reader.string() != nil,
            let forwarding = reader.byte()
        else { return nil }
        return (hostKey, session, forwarding != 0)
    }

    /// What a login signs, whole: the session, then SSH_MSG_USERAUTH_REQUEST with the user, the service, the
    /// method, the key, and for the method OpenSSH prefers the server's key too. Anything else, such as a
    /// signature for a file or a commit, or those words with something added, is not a login.
    static func login(inSignRequest frame: Data) -> (user: String, session: Data, hostKey: Data?)? {
        var request = Reader(data: Data(frame.dropFirst()))
        guard request.string() != nil, let blob = request.string() else { return nil }
        var reader = Reader(data: blob)
        guard let session = reader.string(), reader.byte() == 50, let user = reader.string(),
            let service = reader.string(), service == Data("ssh-connection".utf8),
            let name = String(data: user, encoding: .utf8), let method = reader.string(),
            reader.byte() == 1, reader.string() != nil, reader.string() != nil
        else { return nil }
        var hostKey: Data?
        switch String(data: method, encoding: .utf8) {
        case "publickey": break
        case "publickey-hostbound-v00@openssh.com":
            guard let bound = reader.string() else { return nil }
            hostKey = bound
        default: return nil
        }
        guard reader.data.isEmpty else { return nil }
        return (name, session, hostKey)
    }

    /// As `ssh-keygen -l` writes it, so it can be compared with what a server shows.
    static func fingerprint(_ hostKey: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: hostKey)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    private static func readExact(_ descriptor: Int32, _ count: Int) -> Data? {
        var out = Data(count: count)
        var got = 0
        while got < count {
            let read = out.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress! + got, count - got) }
            if read <= 0 { return nil }
            got += read
        }
        return out
    }

    static func readFrame(_ descriptor: Int32) -> Data? {
        guard let head = readExact(descriptor, 4) else { return nil }
        let length = head.reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, length <= 256 * 1024 else { return nil }
        return readExact(descriptor, length)
    }

    static func writeFrame(_ descriptor: Int32, _ frame: Data) -> Bool {
        let count = UInt32(frame.count).bigEndian
        var out = withUnsafeBytes(of: count) { Data($0) }
        out.append(frame)
        return out.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let wrote = Darwin.write(descriptor, raw.baseAddress! + offset, raw.count - offset)
                if wrote <= 0 { return false }
                offset += wrote
            }
            return true
        }
    }

    private static func relay(_ frame: Data, to up: Int32) -> Data? {
        writeFrame(up, frame) ? readFrame(up) : nil
    }
}

/// Points `ssh` at the door whatever its config says, and stops it offering keys from disk first.
public enum SSHCommand {
    public static let askpassVariable = "KEYREEVE_ASKPASS"

    public static func options(socket: String, identity: String) -> [String] {
        ["-o", "IdentityAgent=\(socket)", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=\(identity)"]
    }

    /// For `ssh`, `scp` and `sftp` directly. Anything else reaches them through the variables below.
    public static func arguments(for command: [String], socket: String, identity: String) -> [String] {
        guard let program = command.first,
            ["ssh", "scp", "sftp"].contains(URL(fileURLWithPath: program).lastPathComponent)
        else { return command }
        var out = [program]
        out.append(contentsOf: options(socket: socket, identity: identity))
        out.append(contentsOf: command.dropFirst())
        return out
    }

    /// What `git` and `rsync` read to run `ssh`. A value of yours stays.
    public static func variables(socket: String, identity: String) -> [String: String] {
        let words = options(socket: socket, identity: identity).map(quoted)
        let line = "ssh " + words.joined(separator: " ")
        return ["GIT_SSH_COMMAND": line, "RSYNC_RSH": line]
    }

    private static func quoted(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
