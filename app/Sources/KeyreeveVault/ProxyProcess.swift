import Foundation

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
            // How far it got, when it did not get all the way: the provider may have acted on it all the same.
            let outcome = (message["outcome"] as? String).flatMap { $0 == "complete" ? nil : ", \($0)" } ?? ""
            onEvent?(grant, key, "\(method) \(place) \(parts[3] as? Int ?? 0)\(outcome)")
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
            lock.lock()
            defer { lock.unlock() }
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
