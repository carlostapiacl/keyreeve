import CryptoKit
import Foundation

/// What agents may do with each key, written by a person in `agents.toml`. A key that is not listed is
/// yours alone, so an agent gets nothing until someone says so.
public struct AgentPolicy: Equatable, Sendable {
    /// How an agent's request is answered.
    public enum Level: String, Equatable, Sendable, CaseIterable {
        /// You choose once or for some hours, then confirm with your finger.
        case ask
        /// One fingerprint, then no more questions until the time is up or you quit Keyreeve.
        case free
    }

    /// Programs allowed to receive the key itself, for what the proxy cannot do.
    public var commands: [String: [String]]
    /// Keys open to agents through the proxy, and how. A key with programs and no level is `ask`.
    public var levels: [String: Level]
    /// The agents a key is limited to. Missing or empty means any agent.
    public var agents: [String: [String]]
    /// Each allowed program's SHA-256, taken when a person allowed it. A program that changed since is refused.
    /// For each key, each allowed program's SHA-256, taken when a person allowed it for that key. A new
    /// version allowed for one key is not allowed for another.
    public var hashes: [String: [String: String]]
    /// When a key opened for some hours closes again. Missing means it stays open.
    public var until: [String: Date]

    public init(
        commands: [String: [String]] = [:], levels: [String: Level] = [:], agents: [String: [String]] = [:],
        hashes: [String: [String: String]] = [:], until: [String: Date] = [:]
    ) {
        self.commands = commands
        self.levels = levels
        self.agents = agents
        self.hashes = hashes
        self.until = until
    }

    public static let fileName = "agents.toml"

    /// The level for a key, or nil when agents cannot use it.
    public func level(of key: String, at date: Date = Date()) -> Level? {
        if let closes = until[key], date >= closes { return nil }
        return levels[key] ?? ((commands[key] ?? []).isEmpty ? nil : .ask)
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

    /// Reads, changes and writes the file under one lock, so the app and agent servers changing it at
    /// once never undo each other. Returns the file as it was and as it is now.
    @discardableResult
    public static func update(at url: URL, _ change: (inout AgentPolicy) throws -> Void) throws -> (before: AgentPolicy, after: AgentPolicy) {
        try PrivateFile.folder(url.deletingLastPathComponent())
        let lockFile = open(url.path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lockFile >= 0 else { throw VaultError("the permissions could not be locked") }
        defer { close(lockFile) }
        guard flock(lockFile, LOCK_EX) == 0 else { throw VaultError("the permissions could not be locked") }
        defer { flock(lockFile, LOCK_UN) }
        let before = load(from: url)
        var after = before
        try change(&after)
        if after != before { try PrivateFile.write(Data(after.toml.utf8), to: url) }
        return (before, after)
    }

    /// The pin a person gave this program for this key, if any.
    public func hash(of program: String, for key: String) -> String? { hashes[key]?[program] }

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
        var closes: Date?
        var table: String?
        func finish(_ bad: VaultError) throws {
            guard let table else { return }
            guard let key else { throw VaultError("each [[\(table)]] needs a key") }
            if table == "allow" && programs == nil { throw VaultError("each [[allow]] needs a key and programs") }
            if let hashes {
                guard hashes.count == (programs ?? []).count else { throw bad }
                for (program, hash) in zip(programs ?? [], hashes) where !hash.isEmpty { policy.hashes[key, default: [:]][program] = hash }
            }
            if let programs { policy.commands[key, default: []] += programs }
            if let level { policy.levels[key] = level }
            if let agents, !agents.isEmpty { policy.agents[key] = agents }
            if let closes { policy.until[key] = closes }
        }
        for (index, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let bad = VaultError("agents.toml, line \(index + 1), is not something this reads")
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "[[allow]]" || line == "[[key]]" {
                try finish(bad)
                key = nil; programs = nil; hashes = nil; level = nil; agents = nil; closes = nil
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
            case ("key", "until"):
                guard closes == nil, let parsed = ISO8601DateFormatter().date(from: try scanner.string(bad)) else { throw bad }
                closes = parsed
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
            # level = "ask" asks you each time, once or for some hours; "free" asks once, until you quit Keyreeve.
            # agents limits a key to some agents, such as ["claude"]. programs receive the key itself, and each
            # is pinned by its SHA-256 in hashes, so a program that changed is refused. until closes the key again
            # at that time, for a key opened for some hours.

            """
        for key in keys {
            out += "\n[[key]]\nkey = \(Self.quoted(key))\n"
            if let level = levels[key] { out += "level = \(Self.quoted(level.rawValue))\n" }
            if let limited = agents[key], !limited.isEmpty {
                out += "agents = [\(limited.map(Self.quoted).joined(separator: ", "))]\n"
            }
            if let closes = until[key] { out += "until = \(Self.quoted(ISO8601DateFormatter().string(from: closes)))\n" }
            let programs = commands[key] ?? []
            if !programs.isEmpty {
                out += "programs = [\(programs.map(Self.quoted).joined(separator: ", "))]\n"
                out += "hashes = [\(programs.map { Self.quoted(hash(of: $0, for: key) ?? "") }.joined(separator: ", "))]\n"
            }
        }
        return out
    }

    private static func quoted(_ text: String) -> String { tomlQuoted(text) }

    /// What changed for each key, in words, for the usage log. Programs are named, not their paths.
    public func changes(from old: AgentPolicy) -> [(key: String, detail: String)] {
        let format = ISO8601DateFormatter()
        func describe(_ policy: AgentPolicy, _ key: String) -> String {
            var parts = [policy.levels[key]?.rawValue ?? ((policy.commands[key] ?? []).isEmpty ? "only me" : "ask")]
            if let agents = policy.agents[key], !agents.isEmpty { parts.append("agents " + agents.joined(separator: " ")) }
            if let closes = policy.until[key] { parts.append("until " + format.string(from: closes)) }
            let programs = (policy.commands[key] ?? []).map { URL(fileURLWithPath: $0).lastPathComponent }
            if !programs.isEmpty { parts.append("programs " + programs.joined(separator: " ")) }
            return parts.joined(separator: ", ")
        }
        return Set(keys).union(old.keys).sorted().compactMap { key in
            let before = describe(old, key), after = describe(self, key)
            return before == after ? nil : (key, "\(before) -> \(after)")
        }
    }
}
