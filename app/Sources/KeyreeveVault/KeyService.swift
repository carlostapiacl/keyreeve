import Foundation

/// Whatever holds the real values and puts them on the wire. Tests use a stand-in for it.
public protocol KeyProxy: AnyObject, Sendable {
    /// `text` is the sealed file as it is. The proxy reads the key from it, as a check would.
    func add(grant: String, key: String, provider: String, text: String, field: String?, expires: Date) throws -> String
    func remove(grant: String)
    var endpoint: KeyService.ProxyEndpoint { get throws }
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

        public init(
            op: String, key: String? = nil, seconds: Int? = nil, program: String? = nil, arguments: Int? = nil,
            prompt: String? = nil, agent: String? = nil, reason: String? = nil, cwd: String? = nil, real: Bool? = nil
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
        public var variable: String?
        public var grants: [GrantInfo]?

        public init(
            ok: Bool, error: String? = nil, value: String? = nil, standIn: String? = nil,
            proxy: ProxyEndpoint? = nil, variable: String? = nil, grants: [GrantInfo]? = nil
        ) {
            self.ok = ok
            self.error = error
            self.value = value
            self.standIn = standIn
            self.proxy = proxy
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
        let standIn: String
    }

    public static let defaultSeconds = 5 * 60
    public static let maxSeconds = 24 * 60 * 60

    private let index: () throws -> KeyIndex
    private let open: (_ source: String, _ prompt: String) throws -> Data
    private let proxy: KeyProxy?
    private let log: AuditLog
    private let now: () -> Date
    private var grants: [Grant] = []
    private let lock = NSLock()

    public init(
        index: @escaping () throws -> KeyIndex,
        open: @escaping (_ source: String, _ prompt: String) throws -> Data,
        proxy: KeyProxy?, log: AuditLog, now: @escaping () -> Date = Date.init
    ) {
        self.proxy = proxy
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
        for grant in grants where grant.expires <= current { proxy?.remove(grant: grant.id) }
        grants.removeAll { $0.expires <= current }
    }

    /// One request that went out with a key, as the proxy reports it.
    public func record(grant: String, key: String, detail: String) {
        try? log.append(event: "request", key: key, grant: grant, detail: detail)
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
                for grant in closing { proxy?.remove(grant: grant.id) }
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
        // The account is the file's word and not the caller's, and it is how you notice the wrong one.
        let account = key.account.map { " (\($0))" } ?? ""
        if request.real == true {
            // Asked every time and never remembered: past this point nothing protects the value.
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
        guard let proxy else { throw VaultError("the proxy is not available") }
        guard let provider = key.provider else {
            throw VaultError("\(id) has no provider, so nothing says where it may go. Set one, or use --real")
        }
        let granted: Grant
        if let existing = grants.first(where: { $0.key == id && $0.program == name }) {
            granted = existing
        } else {
            // A permission covers one key with one program, so one for `netlify` does not also cover
            // something else without showing you that it asked.
            let prompt = (request.prompt ?? "run \(name) with the key \(id)") + account
            let sealed: Data
            do {
                sealed = try open(key.source, prompt)
            } catch {
                try log.append(event: "denied", key: id, observed: caller, declared: declared)
                throw error
            }
            let seconds = min(max(request.seconds ?? Self.defaultSeconds, 1), Self.maxSeconds)
            let expires = now().addingTimeInterval(TimeInterval(seconds))
            let grantID = "g-" + UUID().uuidString.prefix(8).lowercased()
            // From here the value lives in the proxy, and this process keeps only the stand-in.
            let standIn = try proxy.add(
                grant: grantID, key: id, provider: provider, text: String(decoding: sealed, as: UTF8.self),
                field: key.field, expires: expires)
            granted = Grant(id: grantID, key: id, program: name, expires: expires, standIn: standIn)
            grants.append(granted)
            try log.append(
                event: "granted", key: id, grant: granted.id, observed: caller, declared: declared,
                detail: "\(seconds) seconds")
        }
        try log.append(event: "used", key: id, grant: granted.id, observed: caller, declared: declared)
        return Response(
            ok: true, standIn: granted.standIn, proxy: try proxy.endpoint, variable: key.variable)
    }
}

/// Starts the proxy and talks to it. It stops when this process does, since it reads until stdin ends.
public final class ProxyProcess: KeyProxy, @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let lock = NSLock()
    private var waiting: [String: DispatchSemaphore] = [:]
    private var answers: [String: [String: Any]] = [:]
    private var ready: KeyService.ProxyEndpoint?
    private let started = DispatchSemaphore(value: 0)
    /// Each request that went out: grant, key and a line for the log.
    public var onEvent: (@Sendable (String, String, String) -> Void)?

    public init(binary: URL, runFolder: URL) throws {
        for handle in [input.fileHandleForReading, input.fileHandleForWriting, output.fileHandleForReading, output.fileHandleForWriting] {
            _ = fcntl(handle.fileDescriptor, F_SETFD, FD_CLOEXEC)
        }
        process.executableURL = binary
        process.arguments = ["proxy", "--run-dir", runFolder.path]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        signal(SIGPIPE, SIG_IGN)
        try process.run()
        let reader = output.fileHandleForReading
        Thread.detachNewThread { [weak self] in
            var pending = Data()
            while true {
                let chunk = reader.availableData
                if chunk.isEmpty { break }
                pending.append(chunk)
                while let end = pending.firstIndex(of: 10) {
                    let line = pending[pending.startIndex..<end]
                    pending.removeSubrange(pending.startIndex...end)
                    self?.handle(Data(line))
                }
            }
            self?.failAll()
        }
        guard started.wait(timeout: .now() + 10) == .success, ready != nil else {
            throw VaultError("the proxy did not start")
        }
    }

    private func handle(_ line: Data) {
        guard let message = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
            let op = message["op"] as? String
        else { return }
        switch op {
        case "ready":
            if let port = message["port"] as? Int, let ca = message["ca"] as? String, let bundle = message["bundle"] as? String {
                ready = KeyService.ProxyEndpoint(port: port, ca: ca, bundle: bundle)
            }
            started.signal()
        case "event":
            guard let grant = message["grant"] as? String, let key = message["key"] as? String else { return }
            let parts = [message["method"], message["host"], message["path"], message["status"]]
            let method = parts[0] as? String ?? "?"
            let place = "\(parts[1] as? String ?? "?")\(parts[2] as? String ?? "")"
            onEvent?(grant, key, "\(method) \(place) \(parts[3] as? Int ?? 0)")
        default:
            guard let grant = message["grant"] as? String else { return }
            lock.lock()
            answers[grant] = message
            let semaphore = waiting[grant]
            lock.unlock()
            semaphore?.signal()
        }
    }

    private func failAll() {
        lock.lock()
        ready = nil
        let all = waiting.values
        lock.unlock()
        for semaphore in all { semaphore.signal() }
        started.signal()
    }

    public var endpoint: KeyService.ProxyEndpoint {
        get throws {
            guard let ready else { throw VaultError("the proxy stopped") }
            return ready
        }
    }

    private func send(_ object: [String: Any]) throws {
        var line = try JSONSerialization.data(withJSONObject: object)
        line.append(10)
        try input.fileHandleForWriting.write(contentsOf: line)
    }

    public func add(grant: String, key: String, provider: String, text: String, field: String?, expires: Date) throws -> String {
        let semaphore = DispatchSemaphore(value: 0)
        lock.lock()
        waiting[grant] = semaphore
        lock.unlock()
        defer {
            lock.lock()
            waiting[grant] = nil
            answers[grant] = nil
            lock.unlock()
        }
        do {
            var message: [String: Any] = [
                "op": "add", "grant": grant, "key": key, "provider": provider, "text": text,
                "expires": Int(expires.timeIntervalSince1970),
            ]
            if let field { message["field"] = field }
            try send(message)
        } catch {
            throw VaultError("the proxy stopped")
        }
        guard semaphore.wait(timeout: .now() + 10) == .success else { throw VaultError("the proxy did not answer") }
        lock.lock()
        let answer = answers[grant]
        lock.unlock()
        if let standIn = answer?["stand_in"] as? String { return standIn }
        throw VaultError(answer?["error"] as? String ?? "the proxy did not answer")
    }

    public func remove(grant: String) {
        try? send(["op": "remove", "grant": grant])
    }

    deinit {
        try? input.fileHandleForWriting.close()
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
