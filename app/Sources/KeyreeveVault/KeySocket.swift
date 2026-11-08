import Foundation

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

    /// A private socket, ready to accept. Anything at that path is replaced.
    static func bound(path: String) throws -> Int32 {
        unlink(path)
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VaultError("the socket could not be opened") }
        _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
        var target = try address(path)
        let done = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard done == 0, Darwin.listen(descriptor, 16) == 0, chmod(path, 0o600) == 0 else {
            close(descriptor)
            throw VaultError("the socket could not be opened")
        }
        return descriptor
    }

    static func connected(path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VaultError("the socket could not be opened") }
        _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
        var target = try address(path)
        let done = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard done == 0 else {
            close(descriptor)
            throw VaultError("the socket could not be reached")
        }
        return descriptor
    }

    public static func listen(path: String) throws -> Int32 {
        let folder = URL(fileURLWithPath: path).deletingLastPathComponent()
        // The folder is 0700, so the socket in it is out of other users' reach whatever its own mode.
        try PrivateFile.folder(folder)
        // The system lets one process hold this and frees it when that process ends, so a busy service
        // is never mistaken for a dead one. It stays open on purpose, for as long as this process runs.
        let holder = open(path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard holder >= 0 else { throw VaultError("the service could not start") }
        guard flock(holder, LOCK_EX | LOCK_NB) == 0 else {
            close(holder)
            throw VaultError("the service is already running")
        }
        return try bound(path: path)
    }

    /// What to say when the service is there and said nothing in time. A use that waits that long is almost
    /// always waiting for a fingerprint nobody has seen yet, and that is what the agent needs to pass on.
    /// The answer may only have been lost, so nothing here says that nothing happened.
    public static func silence(for op: String) -> String {
        switch op {
        case "use":
            return "no answer in two minutes: Keyreeve is most likely waiting for the person's fingerprint on this Mac. "
                + "Ask them to look for the prompt. Whether a permission opened is not known: `keyreeve grants` shows it"
        case "revoke":
            return "the key service did not answer, so it is not known whether the permissions ended. "
                + "`keyreeve grants` shows what is in force, and quitting Keyreeve ends them all"
        default:
            return "the key service did not answer, so whether anything changed is not known"
        }
    }

    /// Whether something is listening, whatever it answers or fails to answer.
    public static func isListening(path: String) -> Bool {
        guard let descriptor = try? connected(path: path) else { return false }
        close(descriptor)
        return true
    }

    /// Serves until `shouldStop` says so.
    /// How many requests are served at once. Past it, only what ends permissions or lists them gets in,
    /// so the emergency stop works while every other slot waits on a fingerprint.
    static let slots = 64
    static let urgentSlots = 16

    public static func serve(descriptor: Int32, service: KeyService, shouldStop: @escaping () -> Bool = { false }) {
        var pollFD = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        let ordinary = DispatchSemaphore(value: slots)
        let urgent = DispatchSemaphore(value: urgentSlots)
        while !shouldStop() {
            guard poll(&pollFD, 1, 1000) > 0 else { continue }
            let client = accept(descriptor, nil, nil)
            guard client >= 0 else { continue }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            let full = ordinary.wait(timeout: .now()) == .timedOut
            if full, urgent.wait(timeout: .now()) == .timedOut {
                close(client)
                continue
            }
            // A request is one short line, so a client that says nothing does not keep a thread; past
            // the limit it gets one second.
            var patience = timeval(tv_sec: full ? 1 : 10, tv_usec: 0)
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &patience, socklen_t(MemoryLayout<timeval>.size))
            Thread.detachNewThread {
                defer {
                    close(client)
                    (full ? urgent : ordinary).signal()
                }
                guard let pid = CallerIdentity.peer(of: client), let line = readLine(client),
                    let request = try? JSONDecoder().decode(KeyService.Request.self, from: line)
                else { return }
                let response = full && !["revoke", "grants"].contains(request.op)
                    ? KeyService.Response(ok: false, error: "the key service is busy, so try again in a moment")
                    : service.handle(request, caller: CallerIdentity.observe(pid: pid))
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
