import CryptoKit
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
            if let data = text.data(using: .utf8),
                let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let value = object[field] as? String
            {
                return value
            }
            for raw in text.split(whereSeparator: \.isNewline).reversed() {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.hasPrefix(field + ":") {
                    return cleaned(String(line.dropFirst(field.count + 1)).trimmingCharacters(in: .whitespaces))
                }
            }
            throw VaultError("this key has no field \(field)")
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: \.isNewline) else {
            throw VaultError("this key's file has several lines, so name a field")
        }
        return trimmed
    }
}

/// What agents may do with each key, written by a person in `agents.toml`. A key that is not listed is
/// yours alone, so an agent gets nothing until someone says so.
public struct AgentPolicy: Equatable, Sendable {
    /// How an agent's request is answered.
    public enum Level: String, Equatable, Sendable, CaseIterable {
        /// You choose once or for some hours, then confirm with your finger.
        case ask
        /// One fingerprint, then no more questions until you lock the app.
        case free
    }

    /// Programs allowed to receive the key itself, for what the proxy cannot do.
    public var commands: [String: [String]]
    /// Keys open to agents through the proxy, and how. A key with programs and no level is `ask`.
    public var levels: [String: Level]
    /// The agents a key is limited to. Missing or empty means any agent.
    public var agents: [String: [String]]
    /// Each allowed program's SHA-256, taken when a person allowed it. A program that changed since is refused.
    public var hashes: [String: String]

    public init(
        commands: [String: [String]] = [:], levels: [String: Level] = [:], agents: [String: [String]] = [:],
        hashes: [String: String] = [:]
    ) {
        self.commands = commands
        self.levels = levels
        self.agents = agents
        self.hashes = hashes
    }

    public static let fileName = "agents.toml"

    /// The level for a key, or nil when agents cannot use it.
    public func level(of key: String) -> Level? {
        levels[key] ?? ((commands[key] ?? []).isEmpty ? nil : .ask)
    }

    /// Every key open to agents in some way.
    public var keys: [String] {
        Set(levels.keys).union(commands.filter { !$0.value.isEmpty }.keys).sorted()
    }

    public func admits(agent: String, for key: String) -> Bool {
        let limited = agents[key] ?? []
        return limited.isEmpty || limited.contains(agent)
    }

    /// A program that does whatever its arguments say, or prints what it is given. Since the agent
    /// chooses the arguments, allowing one of these would hand it the key.
    public static let neverAllowed: Set<String> = [
        "sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "csh", "env", "printenv", "cat", "echo", "printf", "tee",
        "xargs", "sudo", "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua",
        "osascript", "curl", "wget", "nc", "ncat", "ssh", "scp", "awk", "sed", "make", "docker", "pbcopy",
    ]

    public static func isNeverAllowed(_ program: String) -> Bool {
        neverAllowed.contains(URL(fileURLWithPath: program).lastPathComponent.lowercased())
    }

    /// The SHA-256 of a program's file, in hex, or nil if it cannot be read.
    public static func fingerprint(of path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// A file that cannot be read allows nothing, so a typo never widens what an agent can do.
    public static func load(from url: URL) -> AgentPolicy {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return AgentPolicy() }
        return (try? parse(text)) ?? AgentPolicy()
    }

    /// The whole program name must match, so `deploy.sh` does not also allow `deploy.sh.evil`.
    public func allows(_ program: String, with key: String) -> Bool {
        !Self.isNeverAllowed(program) && (commands[key]?.contains(program) ?? false)
    }

    /// Reads the part of TOML this file uses: `[[key]]` tables, and the older `[[allow]]` ones. Anything
    /// else is an error, and not something to guess at.
    public static func parse(_ text: String) throws -> AgentPolicy {
        var policy = AgentPolicy()
        var key: String?
        var programs: [String]?
        var hashes: [String]?
        var level: Level?
        var agents: [String]?
        var table: String?
        func finish(_ bad: VaultError) throws {
            guard let table else { return }
            guard let key else { throw VaultError("each [[\(table)]] needs a key") }
            if table == "allow" && programs == nil { throw VaultError("each [[allow]] needs a key and programs") }
            if let hashes {
                guard hashes.count == (programs ?? []).count else { throw bad }
                for (program, hash) in zip(programs ?? [], hashes) where !hash.isEmpty { policy.hashes[program] = hash }
            }
            if let programs { policy.commands[key, default: []] += programs }
            if let level { policy.levels[key] = level }
            if let agents, !agents.isEmpty { policy.agents[key] = agents }
        }
        for (index, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let bad = VaultError("agents.toml, line \(index + 1), is not something this reads")
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "[[allow]]" || line == "[[key]]" {
                try finish(bad)
                key = nil; programs = nil; hashes = nil; level = nil; agents = nil
                table = line == "[[allow]]" ? "allow" : "key"
                continue
            }
            guard let table, let equals = line.firstIndex(of: "=") else { throw bad }
            let name = line[..<equals].trimmingCharacters(in: .whitespaces)
            var scanner = TomlScanner(text: String(line[line.index(after: equals)...]))
            switch (table, name) {
            case (_, "key"):
                guard key == nil else { throw bad }
                key = try scanner.string(bad)
            case (_, "programs"):
                guard programs == nil else { throw bad }
                programs = try scanner.list(bad)
            case ("key", "hashes"):
                guard hashes == nil else { throw bad }
                hashes = try scanner.list(bad)
            case ("key", "level"):
                guard level == nil, let parsed = Level(rawValue: try scanner.string(bad)) else { throw bad }
                level = parsed
            case ("key", "agents"):
                guard agents == nil else { throw bad }
                agents = try scanner.list(bad)
            default:
                throw bad
            }
            try scanner.end(bad)
        }
        try finish(VaultError("agents.toml does not hold together"))
        return policy
    }

    public var toml: String {
        var out = """
            # What agents may do with each key in your vault. A key that is not here is yours alone.
            # level = "ask" asks you each time, once or for some hours; "free" asks once, until you lock the app.
            # agents limits a key to some agents, such as ["claude"]. programs receive the key itself, and each
            # is pinned by its SHA-256 in hashes, so a program that changed is refused.

            """
        for key in keys {
            out += "\n[[key]]\nkey = \(Self.quoted(key))\n"
            if let level = levels[key] { out += "level = \(Self.quoted(level.rawValue))\n" }
            if let limited = agents[key], !limited.isEmpty {
                out += "agents = [\(limited.map(Self.quoted).joined(separator: ", "))]\n"
            }
            let programs = commands[key] ?? []
            if !programs.isEmpty {
                out += "programs = [\(programs.map(Self.quoted).joined(separator: ", "))]\n"
                out += "hashes = [\(programs.map { Self.quoted(hashes[$0] ?? "") }.joined(separator: ", "))]\n"
            }
        }
        return out
    }

    private static func quoted(_ text: String) -> String { tomlQuoted(text) }
}

/// What an agent asks for, shown to the person before the fingerprint. The key and the program come
/// from keyreeve; the reason is the agent's own words, cleaned and cut.
public struct AgentRequest: Equatable, Sendable {
    public let key: String
    public let program: String
    public let reason: String
    /// The whole command, as the agent sent it, on one line and cut.
    public let command: String

    public init(key: String, program: String, reason: String, command: [String] = []) {
        self.key = key
        self.program = URL(fileURLWithPath: program).lastPathComponent
        self.reason = String(Self.oneLine(reason).prefix(200))
        self.command = String(Self.oneLine(Self.shown(command)).prefix(300))
    }

    static func oneLine(_ text: String) -> String {
        String(text.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : Character($0) })
            .trimmingCharacters(in: .whitespaces)
    }

    /// A command as a person would type it, with quotes where a word needs them.
    public static func shown(_ command: [String]) -> String {
        command.map { word in
            word.isEmpty || word.contains(where: { " \"'$`\\".contains($0) }) ? "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'" : word
        }.joined(separator: " ")
    }
}

/// How long the person's yes lasts, for this key and program in this agent's session.
public enum AgentApproval: Equatable, Sendable {
    case once
    case lasting(TimeInterval)

    public static let choices: [(label: String, approval: AgentApproval)] = [
        ("Once", .once), ("1 hour", .lasting(3600)), ("4 hours", .lasting(4 * 3600)),
        ("8 hours", .lasting(8 * 3600)), ("24 hours", .lasting(24 * 3600)),
    ]
}

/// A small MCP server over stdin and stdout. An agent can learn which keys it may use and run an
/// allowed program with one, and no tool returns a value.
public struct AgentBridge {
    /// Opened keys a person approved for a while, held by this server alone, which ends with the agent's session.
    final class Held: @unchecked Sendable {
        var entries: [String: (from: Date, until: Date, opened: Data)] = [:]
    }

    /// Ends everything agents were approved for a while: the app's lock and `revoke` touch this file, and
    /// each agent server compares its approvals with it.
    public static func endedFile(home: URL) -> URL { home.appendingPathComponent("run/agents-ended") }

    public static func endAll(home: URL) {
        let file = endedFile(home: home)
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? Data().write(to: file)
        try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: file.path)
    }

    public static func endedAt(home: URL) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: endedFile(home: home).path))?[.modificationDate] as? Date
    }

    public struct Output: Equatable {
        public let status: Int32
        public let text: String
        public init(status: Int32, text: String) {
            self.status = status
            self.text = text
        }
    }

    /// Read again for each request, so a permission you change in the app counts without restarting the agent.
    let currentPolicy: () -> AgentPolicy
    var policy: AgentPolicy { currentPolicy() }
    /// Names in the vault.
    let names: () throws -> [String]
    /// Opens a key, which asks for a fingerprint. The text is what the person sees in the prompt.
    let open: (_ key: String, _ prompt: String) throws -> Data
    let run: (_ command: [String], _ variable: String, _ value: String) throws -> Output
    let record: (_ key: String, _ program: String, _ reason: String) -> Void
    /// Asks the person, before the fingerprint. Nil is a no.
    let approve: (AgentRequest) -> AgentApproval?
    /// When the person last ended every approval, if ever.
    let endedAt: () -> Date?
    let now: () -> Date
    /// Who started this server, as the process tree says: `claude`, `codex`, or the program's name.
    let agent: String
    /// The key service, which opens keys with a fingerprint and holds them behind the proxy.
    let service: ((KeyService.Request) throws -> KeyService.Response)?
    let runPrepared: (_ environment: UseEnvironment) throws -> Output
    /// Writes a line in the usage log for what this server decides on its own.
    let log: (_ event: String, _ key: String, _ detail: String, _ reason: String?) -> Void
    /// Whether a program's file still is the one a person allowed.
    let pinned: (_ program: String, _ hash: String?) -> Bool
    /// Every key's provider and usual variable, from the identifiers file, read once per listing.
    let describe: () -> [String: KeyIndex.Key]
    /// Keeps what ran and what came back, for the person to read.
    let transcript: (AgentTranscript.Entry) -> Void
    let held = Held()

    public init(
        policy: AgentPolicy, names: @escaping () throws -> [String],
        open: @escaping (_ key: String, _ prompt: String) throws -> Data,
        run: @escaping (_ command: [String], _ variable: String, _ value: String) throws -> Output,
        record: @escaping (_ key: String, _ program: String, _ reason: String) -> Void,
        pinned: @escaping (_ program: String, _ hash: String?) -> Bool = AgentBridge.matchesPin
    ) {
        self.init(policy: { policy }, names: names, open: open, run: run, record: record, pinned: pinned)
    }

    public init(
        policy: @escaping () -> AgentPolicy, names: @escaping () throws -> [String],
        open: @escaping (_ key: String, _ prompt: String) throws -> Data,
        run: @escaping (_ command: [String], _ variable: String, _ value: String) throws -> Output,
        record: @escaping (_ key: String, _ program: String, _ reason: String) -> Void,
        approve: @escaping (AgentRequest) -> AgentApproval? = { _ in .once },
        endedAt: @escaping () -> Date? = { nil },
        now: @escaping () -> Date = Date.init,
        agent: String = "agent",
        service: ((KeyService.Request) throws -> KeyService.Response)? = nil,
        runPrepared: @escaping (_ environment: UseEnvironment) throws -> Output = { try AgentRunner.run($0) },
        log: @escaping (_ event: String, _ key: String, _ detail: String, _ reason: String?) -> Void = { _, _, _, _ in },
        pinned: @escaping (_ program: String, _ hash: String?) -> Bool = AgentBridge.matchesPin,
        describe: @escaping () -> [String: KeyIndex.Key] = { [:] },
        transcript: @escaping (AgentTranscript.Entry) -> Void = { _ in }
    ) {
        currentPolicy = policy
        self.names = names
        self.open = open
        self.run = run
        self.record = record
        self.approve = approve
        self.endedAt = endedAt
        self.now = now
        self.agent = agent
        self.service = service
        self.runPrepared = runPrepared
        self.log = log
        self.pinned = pinned
        self.describe = describe
        self.transcript = transcript
    }

    /// Runs and writes down what ran, with the key and its stand-in taken out of what is kept.
    private func ran(
        key: String, command: [String], reason: String, hiding secrets: [String], _ body: () throws -> Output
    ) throws -> String {
        let started = Date()
        let output = try body()
        var text = output.text
        for secret in secrets { text = Self.redact(text, value: secret) }
        let kept = String(decoding: Data(text.utf8).prefix(AgentRunner.maxOutput), as: UTF8.self)
        transcript(AgentTranscript.Entry(
            at: started, agent: agent, key: key, command: AgentRequest.shown(command), reason: reason, exit: output.status,
            output: kept, milliseconds: Int(Date().timeIntervalSince(started) * 1000)))
        return "exit \(output.status)\n\(kept)"
    }

    public static func matchesPin(_ program: String, _ hash: String?) -> Bool {
        guard let hash, !hash.isEmpty else { return false }
        return AgentPolicy.fingerprint(of: program) == hash
    }

    /// The agent behind a process chain, which starts with this server.
    public static func agentName(chain: [String]) -> String {
        for name in chain.dropFirst() {
            let lower = name.lowercased()
            if lower.contains("claude") { return "claude" }
            if lower.contains("codex") { return "codex" }
        }
        return chain.dropFirst().first ?? "agent"
    }

    /// The opened key, if the person approved this pair for a while and nothing ended it since.
    private func stillHeld(_ slot: String) -> Data? {
        guard let entry = held.entries[slot] else { return nil }
        let ended = endedAt().map { $0 >= entry.from } ?? false
        guard !ended, now() < entry.until else {
            held.entries[slot] = nil
            return nil
        }
        return entry.opened
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
            let policy = self.policy
            let known = Set(try names())
            let described = describe()
            let lines = policy.keys.filter { known.contains($0) && policy.admits(agent: agent, for: $0) }.compactMap { key -> String? in
                guard let level = policy.level(of: key) else { return nil }
                var parts = [level == .free ? "free until the person locks the app" : "asks the person"]
                let info = described[key]
                if policy.levels[key] != nil {
                    if info?.provider == KeyService.sshProvider {
                        parts.append("use_key for ssh, scp, sftp, git or rsync")
                    } else {
                        parts.append("use_key with any command" + (info?.variable.map { ", as \($0)" } ?? ""))
                    }
                }
                // Only programs run_with_key would accept, so an agent is not sent to one that is refused.
                let programs = (policy.commands[key] ?? []).filter {
                    policy.allows($0, with: key) && policy.hashes[$0] != nil && pinned($0, policy.hashes[$0])
                }
                if !programs.isEmpty { parts.append("run_with_key with " + programs.joined(separator: ", ")) }
                return "\(key): " + parts.joined(separator: "; ")
            }
            return lines.isEmpty ? "No key is allowed for agents yet." : lines.joined(separator: "\n")
        case "use_key":
            return try useKey(arguments)
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
        let name = URL(fileURLWithPath: program).lastPathComponent
        // Checked first, so a refused request never reaches the person's finger.
        let policy = self.policy
        try admit(key, policy: policy, reason: reason)
        guard policy.allows(program, with: key) else {
            log("refused", key, "\(name) is not allowed", reason)
            throw VaultError("\(name) may not run with \(key). A person allows programs in the app, under Agents")
        }
        guard policy.hashes[program] != nil else {
            log("refused", key, "\(name) was allowed before programs were pinned", reason)
            throw VaultError("\(name) was allowed before keyreeve pinned programs, so a person has to allow it again in the app")
        }
        guard pinned(program, policy.hashes[program]) else {
            log("refused", key, "\(name) changed since it was allowed", reason)
            throw VaultError("\(name) changed since a person allowed it, so it is refused until they allow it again")
        }
        let slot = key + "\u{0}" + program
        let sealed: Data
        if let opened = stillHeld(slot) {
            sealed = opened
        } else {
            // The person sees the request with the agent's reason, set apart, and chooses how long a yes lasts.
            guard let approval = approve(AgentRequest(key: key, program: program, reason: reason, command: command)) else {
                log("denied", key, "the person said no to \(name)", reason)
                throw VaultError("the person said no to \(key) for \(name)")
            }
            // The agent's words stay out of the fingerprint prompt, where they could pose as the app.
            let prompt = "let an agent run \(name) with \(key)"
            do {
                sealed = try open(key, prompt)
            } catch {
                log("denied", key, "fingerprint for \(name)", reason)
                throw error
            }
            if case .lasting(let seconds) = approval {
                let start = now()
                held.entries[slot] = (start, start.addingTimeInterval(seconds), sealed)
                log("granted", key, "\(Int(seconds)) seconds, \(name)", reason)
            } else {
                log("granted", key, "once, \(name)", reason)
            }
        }
        let value = try EnvReferences.value(in: sealed, field: arguments["field"] as? String)
        record(key, program, reason)
        // Hidden first and cut after, so the cut cannot leave half a key showing.
        return try ran(key: key, command: command, reason: reason, hiding: [value]) { try run(command, variable, value) }
    }

    /// Refuses, and writes down, a key that is not open to agents or not to this one.
    private func admit(_ key: String, policy: AgentPolicy, reason: String) throws {
        guard policy.level(of: key) != nil else {
            log("refused", key, "not open to agents", reason)
            throw VaultError("\(key) is not open to agents. A person opens keys in the app, under Agents")
        }
        guard policy.admits(agent: agent, for: key) else {
            log("refused", key, "not open to \(agent)", reason)
            throw VaultError("\(key) is not open to \(agent). A person chooses which agents in the app, under Agents")
        }
    }

    /// Runs a command with a stand-in for the key. The proxy swaps in the real key only on the way to the
    /// key's provider, so the command and the agent never hold it.
    private func useKey(_ arguments: [String: Any]) throws -> String {
        guard let key = arguments["key"] as? String,
            let command = arguments["command"] as? [String], let program = command.first, !program.isEmpty,
            let reason = arguments["reason"] as? String, !reason.isEmpty
        else { throw VaultError("this needs key, command and reason") }
        let variable = arguments["variable"] as? String
        if let variable, !Self.isVariableName(variable) { throw VaultError("that is not a variable name") }
        let policy = self.policy
        try admit(key, policy: policy, reason: reason)
        guard let level = policy.levels[key] else {
            log("refused", key, "only through allowed programs", reason)
            throw VaultError("\(key) is open to agents only through run_with_key with an allowed program")
        }
        guard let service else { throw VaultError("the key service is not available") }
        let name = URL(fileURLWithPath: program).lastPathComponent
        var request = KeyService.Request(
            op: "use", key: key, program: program, arguments: command.count - 1, agent: agent, reason: reason)
        var once = false
        switch level {
        case .free:
            // One fingerprint covers every command until the app locks, at most a day.
            request.anyProgram = true
            request.seconds = KeyService.maxSeconds
            request.prompt = "let \(agent) use \(key) until you lock the app"
        case .ask:
            let open = (try? service(KeyService.Request(op: "grants")))?.grants ?? []
            let covered = open.contains { $0.key == key && ($0.program == name || $0.program == KeyService.anyProgram) }
            if !covered {
                guard let approval = approve(AgentRequest(key: key, program: program, reason: reason, command: command)) else {
                    log("denied", key, "the person said no to \(name)", reason)
                    throw VaultError("the person said no to \(key) for \(name)")
                }
                switch approval {
                case .once:
                    once = true
                    request.seconds = Int(AgentRunner.limit) + 30
                case .lasting(let seconds):
                    request.seconds = Int(seconds)
                }
                request.prompt = "let \(agent) run \(name) with \(key)"
                    + (once ? "" : " for \(Int(request.seconds ?? 0) / 3600) hours")
            }
        }
        let answer = try service(request)
        guard answer.ok else { throw VaultError(answer.error ?? "the key could not be used") }
        defer {
            if once, let grant = answer.grant { _ = try? service(KeyService.Request(op: "revoke", key: key, grant: grant)) }
        }
        let prepared = try UseEnvironment(answer: answer, command: command, variable: variable ?? answer.variable)
        return try ran(key: key, command: command, reason: reason, hiding: [answer.standIn].compactMap { $0 }) {
            try runPrepared(prepared)
        }
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
            "description": "List the keys this agent may use, how, and whether the person is asked. No values.",
            "inputSchema": ["type": "object", "properties": [String: Any]()],
        ],
        [
            "name": "use_key",
            "description":
                "Run a command with a key. The command gets a stand-in in the key's variable, and a local proxy swaps in the real key only for requests to the key's provider, so any command works, including curl. For an SSH key, ssh, scp, sftp, git and rsync sign in through keyreeve. The person may be asked first. The key is never returned.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "key": ["type": "string"],
                    "command": ["type": "array", "items": ["type": "string"]],
                    "variable": ["type": "string", "description": "The variable for the stand-in, if not the key's usual one"],
                    "reason": ["type": "string", "description": "Why, shown to the person and kept in the usage log"],
                ],
                "required": ["key", "command", "reason"],
            ],
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
        var environment = UseEnvironment.plain(command: command)
        environment.set[variable] = value
        return try run(environment, keep: value.utf8.count, limit: limit)
    }

    /// Runs a command prepared by the key service: a stand-in and the proxy, or an SSH socket.
    public static func run(_ environment: UseEnvironment, keep extra: Int = 0, limit: TimeInterval = limit) throws -> AgentBridge.Output {
        let command = environment.command
        let process = Process()
        let pipe = Pipe()
        // A program started later must not inherit this, or the output would never end.
        _ = fcntl(pipe.fileHandleForReading.fileDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = command
        process.environment = environment.applied(to: ProcessInfo.processInfo.environment)
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = pipe
        // Told when it ends. waitUntilExit polls a run loop and added tens of milliseconds to each command.
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        try process.run()

        // Room past the cap, so a key that starts before the cap arrives whole and can be hidden.
        let keep = maxOutput + extra * 2 + 16
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
        if finished { exited.wait() }
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
