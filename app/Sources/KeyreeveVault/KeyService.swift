import Foundation

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

        public init(
            op: String, key: String? = nil, seconds: Int? = nil, program: String? = nil, arguments: Int? = nil,
            prompt: String? = nil, agent: String? = nil, reason: String? = nil, cwd: String? = nil
        ) {
            self.op = op
            self.key = key
            self.seconds = seconds
            self.program = program
            self.arguments = arguments
            self.prompt = prompt
            self.agent = agent
            self.reason = reason
            self.cwd = cwd
        }
    }

    public struct Response: Codable, Equatable, Sendable {
        public var ok: Bool
        public var error: String?
        public var value: String?
        public var variable: String?
        public var grants: [GrantInfo]?

        public init(ok: Bool, error: String? = nil, value: String? = nil, variable: String? = nil, grants: [GrantInfo]? = nil) {
            self.ok = ok
            self.error = error
            self.value = value
            self.variable = variable
            self.grants = grants
        }
    }

    public struct GrantInfo: Codable, Equatable, Sendable {
        public var id: String
        public var key: String
        public var program: String
        public var expires: Date
    }

    private struct Grant {
        let id: String
        let key: String
        let program: String
        let expires: Date
        var value: String
    }

    public static let defaultSeconds = 5 * 60
    public static let maxSeconds = 24 * 60 * 60

    private let index: () throws -> KeyIndex
    private let open: (_ source: String, _ prompt: String) throws -> Data
    private let log: AuditLog
    private let now: () -> Date
    private var grants: [Grant] = []
    private let lock = NSLock()

    public init(
        index: @escaping () throws -> KeyIndex,
        open: @escaping (_ source: String, _ prompt: String) throws -> Data,
        log: AuditLog, now: @escaping () -> Date = Date.init
    ) {
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
        grants.removeAll { $0.expires <= current }
    }

    public func handle(_ request: Request, caller: AuditLog.Observed?) -> Response {
        lock.lock()
        defer { lock.unlock() }
        dropExpired()
        do {
            switch request.op {
            case "use": return try use(request, caller: caller)
            case "grants":
                return Response(
                    ok: true,
                    grants: grants.map { GrantInfo(id: $0.id, key: $0.key, program: $0.program, expires: $0.expires) })
            case "revoke":
                let closing = grants.filter { request.key == nil || $0.key == request.key }
                grants.removeAll { request.key == nil || $0.key == request.key }
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
        let granted: Grant
        if let existing = grants.first(where: { $0.key == id && $0.program == name }) {
            granted = existing
        } else {
            // A permission covers one key with one program, so one for `netlify` does not also let
            // `printenv` read the key without showing you that it wants to.
            // The account is the file's word and not the caller's, and it is how you notice the wrong one.
            let prompt = (request.prompt ?? "run \(name) with the key \(id)") + (key.account.map { " (\($0))" } ?? "")
            let sealed: Data
            do {
                sealed = try open(key.source, prompt)
            } catch {
                try log.append(event: "denied", key: id, observed: caller, declared: declared)
                throw error
            }
            let seconds = min(max(request.seconds ?? Self.defaultSeconds, 1), Self.maxSeconds)
            granted = Grant(
                id: "g-" + UUID().uuidString.prefix(8).lowercased(), key: id, program: name,
                expires: now().addingTimeInterval(TimeInterval(seconds)),
                value: try EnvReferences.value(in: sealed, field: key.field))
            grants.append(granted)
            try log.append(
                event: "granted", key: id, grant: granted.id, observed: caller, declared: declared,
                detail: "\(seconds) seconds")
        }
        try log.append(event: "used", key: id, grant: granted.id, observed: caller, declared: declared)
        return Response(ok: true, value: granted.value, variable: key.variable)
    }
}

/// What the system says about the process on the other end of a connection.
public enum CallerIdentity {
    static func parent(of pid: Int32) -> (parent: Int32, name: String)? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        var command = info.kp_proc.p_comm
        let name = withUnsafeBytes(of: &command) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        return (info.kp_eproc.e_ppid, name)
    }

    static func path(of pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 ? String(cString: buffer) : nil
    }

    /// A readable name for a process. Some tools install as `claude/versions/2.1.319`, and a log that
    /// says `2.1.319` says nothing about who it was.
    public static func label(path: String?, name: String) -> String {
        guard let path else { return name }
        let url = URL(fileURLWithPath: path)
        let base = url.lastPathComponent
        guard base.first?.isNumber == true, url.deletingLastPathComponent().lastPathComponent == "versions" else { return base }
        return url.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent
    }

    public static func observe(pid: Int32) -> AuditLog.Observed {
        var chain: [String] = []
        var current = pid
        for _ in 0..<8 {
            guard current > 1, let found = parent(of: current) else { break }
            chain.append(label(path: path(of: current), name: found.name))
            current = found.parent
        }
        return AuditLog.Observed(pid: pid, program: path(of: pid) ?? chain.first ?? "unknown", chain: chain)
    }

    /// Only this user's processes may talk to the service. The socket's mode says so too.
    static func peer(of descriptor: Int32) -> Int32? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(descriptor, &uid, &gid) == 0, uid == getuid() else { return nil }
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(descriptor, 0 /* SOL_LOCAL */, 2 /* LOCAL_PEERPID */, &pid, &size) == 0 else { return nil }
        return pid
    }
}

/// The service's socket. One line of JSON each way, one request per connection.
public enum KeySocket {
    static func address(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw VaultError("the socket's path is too long") }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: bytes)
        }
        return address
    }

    private static func readLine(_ descriptor: Int32, limit: Int = 1024 * 1024) -> Data? {
        var out = Data()
        var byte = [UInt8](repeating: 0, count: 4096)
        while out.count < limit {
            let got = read(descriptor, &byte, byte.count)
            if got <= 0 { break }
            out.append(contentsOf: byte[0..<got])
            if byte[0..<got].contains(10) { break }
        }
        return out.isEmpty ? nil : out
    }

    private static func writeAll(_ descriptor: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let wrote = write(descriptor, raw.baseAddress! + offset, raw.count - offset)
                if wrote <= 0 { return false }
                offset += wrote
            }
            return true
        }
    }

    public static func listen(path: String) throws -> Int32 {
        let folder = URL(fileURLWithPath: path).deletingLastPathComponent()
        let previous = umask(0o077)
        defer { umask(previous) }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // A refused connection means nothing is serving, so what is there is a leftover.
        if let existing = try? send(KeyService.Request(op: "grants"), path: path, timeout: 1), existing.ok {
            throw VaultError("the service is already running")
        }
        unlink(path)
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VaultError("the service could not start") }
        _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
        var target = try address(path)
        let bound = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, Darwin.listen(descriptor, 16) == 0, chmod(path, 0o600) == 0 else {
            close(descriptor)
            throw VaultError("the service could not start")
        }
        return descriptor
    }

    /// Serves until `shouldStop` says so. Requests are answered one at a time by the service's lock.
    public static func serve(descriptor: Int32, service: KeyService, shouldStop: @escaping () -> Bool = { false }) {
        var pollFD = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        while !shouldStop() {
            guard poll(&pollFD, 1, 1000) > 0 else { continue }
            let client = accept(descriptor, nil, nil)
            guard client >= 0 else { continue }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            Thread.detachNewThread {
                defer { close(client) }
                guard let pid = CallerIdentity.peer(of: client), let line = readLine(client),
                    let request = try? JSONDecoder().decode(KeyService.Request.self, from: line)
                else { return }
                let response = service.handle(request, caller: CallerIdentity.observe(pid: pid))
                if var out = try? JSONEncoder().encode(response) {
                    out.append(10)
                    _ = writeAll(client, out)
                }
            }
        }
    }

    public static func send(_ request: KeyService.Request, path: String, timeout: Int32 = 120) throws -> KeyService.Response {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VaultError("the service could not be reached") }
        defer { close(descriptor) }
        _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
        var limit = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        var target = try address(path)
        let connected = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { throw VaultError("the service could not be reached") }
        var out = try JSONEncoder().encode(request)
        out.append(10)
        guard writeAll(descriptor, out), let line = readLine(descriptor) else {
            throw VaultError("the service did not answer")
        }
        return try JSONDecoder().decode(KeyService.Response.self, from: line)
    }
}
