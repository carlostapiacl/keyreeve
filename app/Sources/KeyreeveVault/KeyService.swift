import Foundation

/// Whatever holds the real values and puts them on the wire. Tests use a stand-in for it.
public protocol KeyProxy: AnyObject, Sendable {
    /// `text` is the sealed file as it is. The proxy reads the key from it, as a check would.
    func add(grant: String, key: String, provider: String, text: String, field: String?, expires: Date) throws -> String
    func remove(grant: String)
    var endpoint: KeyService.ProxyEndpoint { get throws }
}

/// Starts a door for an SSH key. Tests can stand in for it.
public protocol SSHKeyAgents: AnyObject, Sendable {
    func open(
        grant: String, name: String, key: String, seconds: Int, check: @escaping SSHDoor.ServerCheck,
        signed: @escaping SSHDoor.SignatureLog, refused: @escaping SSHDoor.RefusalLog
    ) throws -> SSHDoorHandle
}

public protocol SSHDoorHandle: AnyObject {
    var socket: String { get }
    var identity: String? { get }
    func close()
}

extension SSHDoor: SSHDoorHandle {}

/// The real agents, one for each permission, with their sockets in the service's private folder.
public final class SystemSSHAgents: SSHKeyAgents, @unchecked Sendable {
    let folder: URL
    let askpass: String?

    /// An agent outlives a service that was killed, and its key stays until its limit. Starting clears those.
    public init(folder: URL, askpass: String? = nil) {
        self.folder = folder
        self.askpass = askpass
        let sweep = Process()
        sweep.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        sweep.arguments = ["-f", "^/usr/bin/ssh-agent -D -a \(NSRegularExpression.escapedPattern(for: folder.path))/a-"]
        sweep.standardOutput = FileHandle.nullDevice
        sweep.standardError = FileHandle.nullDevice
        try? sweep.run()
        sweep.waitUntilExit()
        let files = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        for name in files where (name.hasSuffix(".sock") || name.hasSuffix(".pub")) && (name.hasPrefix("a-") || name.hasPrefix("s-")) {
            unlink(folder.appendingPathComponent(name).path)
        }
    }

    public func open(
        grant: String, name: String, key: String, seconds: Int, check: @escaping SSHDoor.ServerCheck,
        signed: @escaping SSHDoor.SignatureLog, refused: @escaping SSHDoor.RefusalLog
    ) throws -> SSHDoorHandle {
        try SSHDoor.open(
            grant: grant, name: name, key: key, seconds: seconds, folder: folder, askpass: askpass,
            check: check, signed: signed, refused: refused)
    }
}

/// Decides who gets a key, keeps permissions for a short while, and writes down every decision. It
/// lives in its own process, so a permission outlasts one command and the agent never holds it.
public final class KeyService: @unchecked Sendable {
    public struct Request: Codable, Equatable, Sendable {
        public var op: String
        public var key: String?
        public var seconds: Int?
        public var program: String?
        public var arguments: Int?
        public var prompt: String?
        public var agent: String?
        public var reason: String?
        public var cwd: String?
        /// Asks for the value itself, for what cannot use a stand-in. It is never remembered.
        public var real: Bool?
        /// A permission that covers any program, for a key a person left free to agents.
        public var anyProgram: Bool?
        /// One permission to end, by its id, and no other.
        public var grant: String?

        public init(
            op: String, key: String? = nil, seconds: Int? = nil, program: String? = nil, arguments: Int? = nil,
            prompt: String? = nil, agent: String? = nil, reason: String? = nil, cwd: String? = nil, real: Bool? = nil,
            anyProgram: Bool? = nil, grant: String? = nil
        ) {
            self.anyProgram = anyProgram
            self.grant = grant
            self.op = op
            self.key = key
            self.seconds = seconds
            self.program = program
            self.arguments = arguments
            self.prompt = prompt
            self.agent = agent
            self.reason = reason
            self.cwd = cwd
            self.real = real
        }
    }

    public struct ProxyEndpoint: Codable, Equatable, Sendable {
        public var port: Int
        public var ca: String
        public var bundle: String
        public init(port: Int, ca: String, bundle: String) {
            self.port = port
            self.ca = ca
            self.bundle = bundle
        }
    }

    public struct Response: Codable, Equatable, Sendable {
        public var ok: Bool
        public var error: String?
        /// The real key, only for a request that asked for it with its own fingerprint.
        public var value: String?
        public var standIn: String?
        public var proxy: ProxyEndpoint?
        /// For an SSH key: the socket that signs with it. The key stays on the other side.
        public var sshSocket: String?
        /// The public half of that key, so `ssh` offers this one and no other.
        public var sshIdentity: String?
        public var variable: String?
        public var grants: [GrantInfo]?
        /// The permission this answer used.
        public var grant: String?

        public init(
            ok: Bool, error: String? = nil, value: String? = nil, standIn: String? = nil,
            proxy: ProxyEndpoint? = nil, sshSocket: String? = nil, sshIdentity: String? = nil, variable: String? = nil, grants: [GrantInfo]? = nil,
            grant: String? = nil
        ) {
            self.grant = grant
            self.ok = ok
            self.error = error
            self.value = value
            self.standIn = standIn
            self.proxy = proxy
            self.sshSocket = sshSocket
            self.sshIdentity = sshIdentity
            self.variable = variable
            self.grants = grants
        }
    }

    public struct GrantInfo: Codable, Equatable, Sendable {
        public var id: String
        public var key: String
        public var program: String
        public var expires: Date

        public init(id: String, key: String, program: String, expires: Date) {
            self.id = id
            self.key = key
            self.program = program
            self.expires = expires
        }
    }

    private struct Grant {
        let id: String
        let key: String
        let program: String
        let expires: Date
        let standIn: String
        /// An SSH key signs for whichever program asks, so its permission is for the key alone.
        let door: SSHDoorHandle?
    }

    /// What `provider` says for an SSH key that belongs to no provider's file, such as a server's.
    public static let sshProvider = "ssh"
    /// "90s", "5m" or "2h". Nil for what it cannot read, including a number too large to hold.
    public static func seconds(from text: String) -> Int? {
        guard let unit = text.last, let number = Int(text.dropLast()), number > 0 else { return Int(text) }
        let scale: Int
        switch unit {
        case "s": scale = 1
        case "m": scale = 60
        case "h": scale = 3600
        default: return nil
        }
        let (result, overflow) = number.multipliedReportingOverflow(by: scale)
        return overflow ? nil : result
    }

    public static let defaultSeconds = 5 * 60
    public static let maxSeconds = 24 * 60 * 60

    private let index: () throws -> KeyIndex
    private let open: (_ source: String, _ prompt: String) throws -> Data
    private let proxy: KeyProxy?
    private let agents: SSHKeyAgents?
    private let confirm: @Sendable (_ prompt: String) -> Bool
    private let log: AuditLog
    private let now: () -> Date
    private var grants: [Grant] = []
    /// Guards the list, and is never held while a person is being asked, so `revoke` always gets through.
    private let lock = NSLock()
    /// One prompt at a time: a second one would cancel the first.
    private let asking = NSLock()
    private var revocations = 0

    public init(
        index: @escaping () throws -> KeyIndex,
        open: @escaping (_ source: String, _ prompt: String) throws -> Data,
        proxy: KeyProxy?, agents: SSHKeyAgents? = nil, confirm: @escaping @Sendable (String) -> Bool = { _ in false },
        log: AuditLog, now: @escaping () -> Date = Date.init
    ) {
        self.proxy = proxy
        self.agents = agents
        self.confirm = confirm
        self.index = index
        self.open = open
        self.log = log
        self.now = now
    }

    public var isIdle: Bool {
        lock.lock()
        defer { lock.unlock() }
        dropExpired()
        return grants.isEmpty
    }

    private func dropExpired() {
        let current = now()
        for grant in grants where grant.expires <= current { end(grant) }
        grants.removeAll { $0.expires <= current }
    }

    private func end(_ grant: Grant) {
        if let door = grant.door {
            door.close()
        } else {
            proxy?.remove(grant: grant.id)
        }
    }

    /// One request that went out with a key, as the proxy reports it.
    public func record(grant: String, key: String, detail: String) {
        try? log.append(event: "request", key: key, grant: grant, detail: detail)
    }

    public func handle(_ request: Request, caller: AuditLog.Observed?) -> Response {
        do {
            switch request.op {
            case "use": return try use(request, caller: caller)
            case "grants":
                lock.lock()
                defer { lock.unlock() }
                dropExpired()
                return Response(
                    ok: true,
                    grants: grants.map { GrantInfo(id: $0.id, key: $0.key, program: $0.program, expires: $0.expires) })
            case "revoke":
                lock.lock()
                dropExpired()
                // Ending one permission that is done with does not cancel what others are opening.
                if request.grant == nil { revocations += 1 }
                let ends = { (grant: Grant) in
                    (request.key == nil || grant.key == request.key) && (request.grant == nil || grant.id == request.grant)
                }
                let closing = grants.filter(ends)
                for grant in closing { end(grant) }
                grants.removeAll(where: ends)
                lock.unlock()
                for grant in closing {
                    try? log.append(event: "closed", key: grant.key, grant: grant.id, observed: caller)
                }
                return Response(ok: true)
            default:
                return Response(ok: false, error: "unknown request")
            }
        } catch let error as VaultError {
            return Response(ok: false, error: error.description)
        } catch {
            // Errors from the system say nothing useful, and could quote what they were given.
            return Response(ok: false, error: "the fingerprint was not accepted, or the key could not be opened")
        }
    }

    /// An SSH key's permission covers every program. Any other covers one key with one program, so one
    /// for `netlify` does not also cover something else without showing you that it asked.
    /// The program name of a permission a person gave for any program.
    public static let anyProgram = "*"

    private func grantInForce(key: String, program: String) -> Grant? {
        lock.lock()
        defer { lock.unlock() }
        dropExpired()
        return grants.first { $0.key == key && ($0.door != nil || $0.program == program || $0.program == Self.anyProgram) }
    }

    private func answer(for grant: Grant, variable: String?) throws -> Response {
        if let door = grant.door { return Response(ok: true, sshSocket: door.socket, sshIdentity: door.identity, grant: grant.id) }
        guard let proxy else { throw VaultError("the proxy is not available") }
        return Response(ok: true, standIn: grant.standIn, proxy: try proxy.endpoint, variable: variable, grant: grant.id)
    }

    private func use(_ request: Request, caller: AuditLog.Observed?) throws -> Response {
        guard let id = request.key, let program = request.program, !program.isEmpty else {
            throw VaultError("this needs a key and a command")
        }
        let declared = AuditLog.Declared(
            agent: request.agent, reason: request.reason,
            command: "\(URL(fileURLWithPath: program).lastPathComponent) (\(request.arguments ?? 0) arguments)",
            cwd: request.cwd)
        guard let key = try index().key(id) else {
            try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "no such key")
            throw VaultError("no key is called \(id). `list` shows them")
        }
        let name = URL(fileURLWithPath: program).lastPathComponent
        // The account is the file's word and not the caller's, and it is how you notice the wrong one.
        let account = key.account.map { " (\($0))" } ?? ""
        if request.real == true {
            // Asked every time and never remembered: past this point nothing protects the value.
            asking.lock()
            defer { asking.unlock() }
            let sealed: Data
            do {
                sealed = try open(key.source, "give the real key \(id)\(account) to \(name)")
            } catch {
                try log.append(event: "denied", key: id, observed: caller, declared: declared, detail: "real key")
                throw error
            }
            let value = try EnvReferences.value(in: sealed, field: key.field)
            try log.append(event: "handed", key: id, observed: caller, declared: declared, detail: "real key")
            return Response(ok: true, value: value, variable: key.variable)
        }
        // No finger is spent on a key that could not be used anyway.
        guard let provider = key.provider else {
            throw VaultError(
                "\(id) has no provider, so nothing says where it may go. Set one (`ssh` for an SSH key), or use --real")
        }
        guard provider == Self.sshProvider || proxy != nil else {
            try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "no proxy")
            throw VaultError("the proxy is not available")
        }
        if let existing = grantInForce(key: id, program: name) {
            try log.append(event: "used", key: id, grant: existing.id, observed: caller, declared: declared)
            return try answer(for: existing, variable: key.variable)
        }
        asking.lock()
        defer { asking.unlock() }
        // While this waited, the prompt ahead of it may have given what this needs.
        if let existing = grantInForce(key: id, program: name) {
            try log.append(event: "used", key: id, grant: existing.id, observed: caller, declared: declared)
            return try answer(for: existing, variable: key.variable)
        }
        lock.lock()
        let revocationsBefore = revocations
        lock.unlock()
        let sealed: Data
        do {
            sealed = try open(key.source, (request.prompt ?? "run \(name) with the key \(id)") + account)
        } catch {
            try log.append(event: "denied", key: id, observed: caller, declared: declared)
            throw error
        }
        let seconds = min(max(request.seconds ?? Self.defaultSeconds, 1), Self.maxSeconds)
        let expires = now().addingTimeInterval(TimeInterval(seconds))
        let grantID = "g-" + UUID().uuidString.prefix(8).lowercased()
        let text = String(decoding: sealed, as: UTF8.self)
        let granted: Grant
        let detail: String
        if text.contains("PRIVATE KEY-----") {
            let door = try openDoor(grant: grantID, key: id, account: account, pinned: key.servers ?? [], text: text, seconds: seconds)
            granted = Grant(id: grantID, key: id, program: name, expires: expires, standIn: "", door: door)
            detail = "\(seconds) seconds, ssh"
        } else {
            guard provider != Self.sshProvider else {
                throw VaultError("\(id) says it is an SSH key, and what is sealed is not a private key")
            }
            guard let proxy else { throw VaultError("the proxy is not available") }
            // From here the value lives in the proxy, and this process keeps only the stand-in.
            let standIn = try proxy.add(
                grant: grantID, key: id, provider: provider, text: text, field: key.field, expires: expires)
            granted = Grant(
                id: grantID, key: id, program: request.anyProgram == true ? Self.anyProgram : name, expires: expires,
                standIn: standIn, door: nil)
            detail = "\(seconds) seconds"
        }
        lock.lock()
        // Locking the app while your finger was on its way ends this too.
        guard revocations == revocationsBefore else {
            end(granted)
            lock.unlock()
            throw VaultError("this was revoked while it was being opened")
        }
        grants.append(granted)
        lock.unlock()
        // A use that cannot be written down does not happen.
        do {
            try log.append(event: "granted", key: id, grant: grantID, observed: caller, declared: declared, detail: detail)
            try log.append(event: "used", key: id, grant: grantID, observed: caller, declared: declared)
            return try answer(for: granted, variable: key.variable)
        } catch {
            lock.lock()
            grants.removeAll { $0.id == grantID }
            end(granted)
            lock.unlock()
            throw error
        }
    }

    /// The first server is the one you just approved with your finger, unless the key names its servers.
    /// Each other asks again.
    private func openDoor(
        grant: String, key: String, account: String, pinned: [String], text: String, seconds: Int
    ) throws -> SSHDoorHandle {
        guard let agents else { throw VaultError("SSH keys are not available here") }
        let servers = ServerList(pinned: pinned)
        let log = self.log
        let confirm = self.confirm
        let asking = self.asking
        return try agents.open(
            grant: grant, name: key, key: text, seconds: seconds,
            check: { fingerprint in
                if servers.note(fingerprint, firstIsFree: false) == .known { return true }
                asking.lock()
                defer { asking.unlock() }
                switch servers.note(fingerprint) {
                case .known: return true
                case .first:
                    try? log.append(event: "server", key: key, grant: grant, detail: "\(fingerprint), with the permission")
                    return true
                case .new:
                    let allowed = confirm("sign in to a new server \(fingerprint) with the key \(key)\(account)")
                    if allowed { servers.allow(fingerprint) }
                    try? log.append(
                        event: allowed ? "server" : "denied", key: key, grant: grant, detail: "\(fingerprint), asked")
                    return allowed
                }
            },
            signed: { signature, caller in
                try? log.append(
                    event: "signed", key: key, grant: grant, observed: caller,
                    detail: "\(signature.user) at \(signature.server)")
            },
            refused: { why, caller in
                try? log.append(event: "refused", key: key, grant: grant, observed: caller, detail: why)
            })
    }
}

/// The servers one SSH permission has been approved for.
final class ServerList: @unchecked Sendable {
    enum Note { case first, known, new }
    private let lock = NSLock()
    private var servers: Set<String>
    private var firstIsFree: Bool

    init(pinned: [String] = []) {
        servers = Set(pinned)
        firstIsFree = pinned.isEmpty
    }

    func note(_ fingerprint: String, firstIsFree useFirst: Bool = true) -> Note {
        lock.lock()
        defer { lock.unlock() }
        if servers.contains(fingerprint) { return .known }
        if useFirst && firstIsFree {
            firstIsFree = false
            servers.insert(fingerprint)
            return .first
        }
        return .new
    }

    func allow(_ fingerprint: String) {
        lock.lock()
        defer { lock.unlock() }
        servers.insert(fingerprint)
    }
}
