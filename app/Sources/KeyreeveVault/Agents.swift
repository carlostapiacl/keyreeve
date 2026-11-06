import Foundation

/// Reads `keyreeve://name` references from an env file, so a repository or an agent's working folder
/// can hold the reference and never the value.
public enum EnvReferences {
    public enum Line: Equatable {
        case value(name: String, value: String)
        case reference(name: String, key: String, field: String?)
    }

    public static let scheme = "keyreeve://"

    public static func parse(_ text: String) -> [Line] {
        text.split(whereSeparator: \.isNewline).compactMap { raw in
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { return nil }
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)) }
            guard let separator = line.firstIndex(of: "=") else { return nil }
            let name = line[..<separator].trimmingCharacters(in: .whitespaces)
            let value = cleaned(line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces))
            guard value.hasPrefix(scheme) else { return .value(name: name, value: value) }
            let target = value.dropFirst(scheme.count)
            // A path can hold `#` only in a rotation's own names, which are not keys anyone refers to.
            if let mark = target.lastIndex(of: "#") {
                return .reference(
                    name: name, key: String(target[..<mark]), field: String(target[target.index(after: mark)...]))
            }
            return .reference(name: name, key: String(target), field: nil)
        }
    }

    /// A quoted value ends at its quote, and an unquoted one at a comment after a space.
    private static func cleaned(_ text: String) -> String {
        if let first = text.first, first == "\"" || first == "'",
            let end = text.dropFirst().firstIndex(of: first)
        {
            return String(text[text.index(after: text.startIndex)..<end])
        }
        if let comment = text.range(of: " #") {
            return text[..<comment.lowerBound].trimmingCharacters(in: .whitespaces)
        }
        return text
    }

    /// The value a reference means, from the sealed text of a file: one field, or a one-line file.
    public static func value(in sealed: Data, field: String?) throws -> String {
        guard let text = String(data: sealed, encoding: .utf8) else { throw VaultError("this key is not text") }
        if let field {
            // The last one, as a shell or `env` would end up with.
            for case .value(let name, let value) in parse(text).reversed() where name == field { return value }
            throw VaultError("this key has no field \(field)")
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: \.isNewline) else {
            throw VaultError("this key's file has several lines, so name a field")
        }
        return trimmed
    }
}

/// Which programs an agent may run with which keys, written by a person. Empty means nothing, so an
/// agent gets no key until someone says so. Each use still asks for a fingerprint.
public struct AgentPolicy: Codable, Equatable, Sendable {
    public var commands: [String: [String]]

    public init(commands: [String: [String]] = [:]) { self.commands = commands }

    public static func load(from url: URL) -> AgentPolicy {
        guard let data = try? Data(contentsOf: url) else { return AgentPolicy() }
        return (try? JSONDecoder().decode(AgentPolicy.self, from: data)) ?? AgentPolicy()
    }

    /// The whole program name must match, so `deploy.sh` does not also allow `deploy.sh.evil`.
    public func allows(_ program: String, with key: String) -> Bool {
        commands[key]?.contains(program) ?? false
    }
}

/// A small MCP server over stdin and stdout. An agent can learn which keys it may use and run an
/// allowed program with one, and no tool returns a value.
public struct AgentBridge {
    public struct Output: Equatable {
        public let status: Int32
        public let text: String
        public init(status: Int32, text: String) {
            self.status = status
            self.text = text
        }
    }

    let policy: AgentPolicy
    /// Names in the vault.
    let names: () throws -> [String]
    /// Opens a key, which asks for a fingerprint. The text is what the person sees in the prompt.
    let open: (_ key: String, _ prompt: String) throws -> Data
    let run: (_ command: [String], _ variable: String, _ value: String) throws -> Output
    let record: (_ key: String, _ program: String, _ reason: String) -> Void

    public init(
        policy: AgentPolicy, names: @escaping () throws -> [String],
        open: @escaping (_ key: String, _ prompt: String) throws -> Data,
        run: @escaping (_ command: [String], _ variable: String, _ value: String) throws -> Output,
        record: @escaping (_ key: String, _ program: String, _ reason: String) -> Void
    ) {
        self.policy = policy
        self.names = names
        self.open = open
        self.run = run
        self.record = record
    }

    /// Answers one line of JSON-RPC, or nothing for a notification.
    public func handle(_ line: String) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
            return reply(id: NSNull(), error: (-32700, "that is not JSON"))
        }
        guard let method = object["method"] as? String else {
            return reply(id: object["id"] ?? NSNull(), error: (-32600, "there is no method"))
        }
        guard let id = object["id"] else { return nil }
        let params = object["params"] as? [String: Any] ?? [:]
        switch method {
        case "initialize":
            return reply(id: id, result: [
                "protocolVersion": Self.version(for: params["protocolVersion"] as? String),
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "keyreeve", "version": "0.1.0"],
            ])
        case "ping":
            return reply(id: id, result: [String: Any]())
        case "tools/list":
            return reply(id: id, result: ["tools": Self.tools])
        case "tools/call":
            let arguments = params["arguments"] as? [String: Any] ?? [:]
            let text: (String, Bool)
            do {
                text = (try call(params["name"] as? String ?? "", arguments), false)
            } catch let error as VaultError {
                text = (error.description, true)
            } catch {
                // Errors from the system say nothing useful, and could quote what they were given.
                text = ("the fingerprint was not accepted, or the key could not be opened", true)
            }
            return reply(id: id, result: ["content": [["type": "text", "text": text.0]], "isError": text.1])
        default:
            return reply(id: id, error: (-32601, "no such method"))
        }
    }

    private func call(_ tool: String, _ arguments: [String: Any]) throws -> String {
        switch tool {
        case "list_keys":
            let known = Set(try names())
            let lines = policy.commands.keys.sorted().filter(known.contains).map { key in
                "\(key): \((policy.commands[key] ?? []).joined(separator: ", "))"
            }
            return lines.isEmpty ? "No key is allowed for agents yet." : lines.joined(separator: "\n")
        case "run_with_key":
            return try runWithKey(arguments)
        default:
            throw VaultError("no such tool")
        }
    }

    private func runWithKey(_ arguments: [String: Any]) throws -> String {
        guard let key = arguments["key"] as? String,
            let variable = arguments["variable"] as? String,
            let command = arguments["command"] as? [String], let program = command.first,
            let reason = arguments["reason"] as? String, !reason.isEmpty
        else { throw VaultError("this needs key, variable, command and reason") }
        guard Self.isVariableName(variable) else { throw VaultError("that is not a variable name") }
        // Checked first, so a refused request never reaches the person's finger.
        guard policy.allows(program, with: key) else {
            throw VaultError("\(program) is not allowed to use \(key). A person adds that in agent-commands.json")
        }
        // The agent's words stay out of the prompt, where they could pose as the app.
        let prompt = "let an agent run \(URL(fileURLWithPath: program).lastPathComponent) with \(key)"
        let sealed = try open(key, prompt)
        let value = try EnvReferences.value(in: sealed, field: arguments["field"] as? String)
        record(key, program, reason)
        let output = try run(command, variable, value)
        // Hidden first and cut after, so the cut cannot leave half a key showing.
        let clean = String(decoding: Data(Self.redact(output.text, value: value).utf8).prefix(AgentRunner.maxOutput), as: UTF8.self)
        return "exit \(output.status)\n\(clean)"
    }

    /// The client's version if this speaks it, or else the newest this does speak, as MCP asks.
    static func version(for requested: String?) -> String {
        let supported = ["2025-06-18", "2025-03-26", "2024-11-05"]
        return requested.flatMap { supported.contains($0) ? $0 : nil } ?? supported[0]
    }

    static func isVariableName(_ name: String) -> Bool {
        guard let first = name.utf8.first, first == 95 || (65...90).contains(first) || (97...122).contains(first) else {
            return false
        }
        return name.utf8.allSatisfy { $0 == 95 || (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }
    }

    /// Catches a program that prints the key plainly. It cannot catch one that hides it on purpose,
    /// which is why the list of allowed programs is the real protection.
    static func redact(_ text: String, value: String) -> String {
        guard !value.isEmpty else { return text }
        let encoded = Data(value.utf8).base64EncodedString()
        return text.replacingOccurrences(of: value, with: "[redacted]")
            .replacingOccurrences(of: encoded, with: "[redacted]")
    }

    private func reply(id: Any, result: [String: Any]) -> String? {
        encode(["jsonrpc": "2.0", "id": id, "result": result])
    }

    private func reply(id: Any, error: (Int, String)) -> String? {
        encode(["jsonrpc": "2.0", "id": id, "error": ["code": error.0, "message": error.1]])
    }

    private func encode(_ object: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    private static let tools: [[String: Any]] = [
        [
            "name": "list_keys",
            "description": "List the keys an agent may use and the programs allowed with each. No values.",
            "inputSchema": ["type": "object", "properties": [String: Any]()],
        ],
        [
            "name": "run_with_key",
            "description":
                "Run an allowed program with a key in one environment variable. The person confirms with a fingerprint. The key is never returned, and appears as [redacted] in the output.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "key": ["type": "string"],
                    "variable": ["type": "string", "description": "The environment variable to set"],
                    "command": ["type": "array", "items": ["type": "string"]],
                    "field": ["type": "string", "description": "The field to use, when the key's file has several"],
                    "reason": ["type": "string", "description": "Why, kept in the usage log"],
                ],
                "required": ["key", "variable", "command", "reason"],
            ],
        ],
    ]
}

/// Runs a program for an agent, with a time limit and a cap on what comes back.
public enum AgentRunner {
    public static let limit: TimeInterval = 120
    public static let maxOutput = 64 * 1024

    public static func run(
        _ command: [String], variable: String, value: String, limit: TimeInterval = limit
    ) throws -> AgentBridge.Output {
        let process = Process()
        let pipe = Pipe()
        // A program started later must not inherit this, or the output would never end.
        _ = fcntl(pipe.fileHandleForReading.fileDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = command
        process.environment = ProcessInfo.processInfo.environment.merging([variable: value]) { _, new in new }
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()

        // Room past the cap, so a key that starts before the cap arrives whole and can be hidden.
        let keep = maxOutput + value.utf8.count * 2 + 16
        let collected = Collected()
        let reader = DispatchGroup()
        reader.enter()
        let handle = pipe.fileHandleForReading
        // On a thread of its own, which may stay blocked until a stubborn child lets go of the pipe.
        Thread.detachNewThread {
            while true {
                let chunk = handle.availableData
                if chunk.isEmpty { break }
                collected.add(chunk, keeping: keep)
            }
            reader.leave()
        }
        // A program can ignore being asked to stop, or leave a child holding the output open. Neither
        // may hold the server, which has one request at a time.
        let finished = reader.wait(timeout: .now() + limit) == .success
        if !finished, process.isRunning {
            process.terminate()
            Thread.sleep(forTimeInterval: 1)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
        if finished { process.waitUntilExit() }
        let status: Int32 = finished ? process.terminationStatus : -1
        return AgentBridge.Output(status: status, text: String(decoding: collected.data, as: UTF8.self))
    }

    private final class Collected: @unchecked Sendable {
        private let lock = NSLock()
        private var bytes = Data()

        func add(_ chunk: Data, keeping limit: Int) {
            lock.lock()
            defer { lock.unlock() }
            if bytes.count < limit { bytes += chunk.prefix(limit - bytes.count) }
        }

        var data: Data {
            lock.lock()
            defer { lock.unlock() }
            return bytes
        }
    }
}
