import Foundation

/// The names people and agents use for keys, kept apart from files. A file can hold several keys, and
/// renaming or moving one breaks nothing that refers to its identifier. This file holds no value.
public struct KeyIndex: Equatable, Sendable {
    public struct Key: Equatable, Sendable, Identifiable {
        public var id: String
        public var source: String
        public var field: String?
        public var provider: String?
        public var project: String?
        /// Whose key it is, at the provider. Several keys of one provider differ by this.
        public var account: String?
        public var description: String?
        /// The variable a command gets the key in, when nothing else says.
        public var variable: String?
        /// For an SSH key: the fingerprints of the servers it may sign in to with no question.
        public var servers: [String]?

        public init(
            id: String, source: String, field: String? = nil, provider: String? = nil, project: String? = nil,
            account: String? = nil, description: String? = nil, variable: String? = nil, servers: [String]? = nil
        ) {
            self.servers = servers
            self.id = id
            self.source = source
            self.field = field
            self.provider = provider
            self.project = project
            self.account = account
            self.description = description
            self.variable = variable
        }
    }

    public var keys: [Key]
    public static let fileName = "keys.toml"

    public init(keys: [Key] = []) { self.keys = keys }

    public func key(_ id: String) -> Key? { keys.first { $0.id == id } }
    public func keys(forSource source: String) -> [Key] { keys.filter { $0.source == source } }

    /// Lower case with dashes: it ends up in scripts, so it has to be easy to type and safe to pass around.
    public static func isValid(id: String) -> Bool {
        guard (1...64).contains(id.count), let first = id.utf8.first, let last = id.utf8.last,
            first != 45, last != 45
        else { return false }
        return id.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }

    public mutating func add(_ key: Key) throws {
        try Self.check(key, taken: self.key(key.id) != nil)
        // In its place, rather than sorting the whole list again for each key a file adds.
        keys.insert(key, at: keys.firstIndex { $0.id > key.id } ?? keys.endIndex)
    }

    private static func check(_ key: Key, taken: Bool) throws {
        guard isValid(id: key.id) else {
            throw VaultError("an identifier uses lower case letters, digits and dashes")
        }
        guard !taken else { throw VaultError("\(key.id) is already in use") }
        guard !key.source.isEmpty else { throw VaultError("\(key.id) needs a source") }
    }

    public mutating func remove(id: String) { keys.removeAll { $0.id == id } }

    /// Lowercase ASCII letters, digits and single hyphens: "Mi clave de correo" is "mi-clave-de-correo".
    public static func slug(_ text: String) -> String {
        let mapped = text.lowercased().folding(options: .diacriticInsensitive, locale: nil).map { character -> Character in
            character.isASCII && (character.isLetter || character.isNumber) ? character : "-"
        }
        return String(mapped).split(separator: "-").joined(separator: "-")
    }

    /// The identifier for a name a person wrote in their own words, free and valid, with a number if
    /// taken. The name stays as written, apart from it.
    public func identifier(for name: String) -> String {
        let base = String(Self.slug(name).prefix(40)).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        let start = base.isEmpty ? "key" : base
        if key(start) == nil, Self.isValid(id: start) { return start }
        var number = 2
        while key("\(start)-\(number)") != nil { number += 1 }
        return "\(start)-\(number)"
    }

    /// An identifier for a key that has none: its provider, then its project or account, then a number.
    public func suggestion(provider: String?, project: String?, account: String? = nil, source: String) -> String {
        let slug = Self.slug
        var fileBase = URL(fileURLWithPath: source).lastPathComponent
        while let dot = fileBase.lastIndex(of: "."), dot != fileBase.startIndex { fileBase = String(fileBase[..<dot]) }
        let base = slug(provider ?? "").isEmpty ? slug(fileBase) : slug(provider ?? "")
        let start = base.isEmpty ? "key" : String(base.prefix(40))
        var tries = [start]
        if let project, !slug(project).isEmpty, slug(project) != start { tries.append("\(start)-\(slug(project).prefix(20))") }
        // The part before the @, since a whole address makes a long and very public name.
        let accountName = account.map { String($0.split(separator: "@").first ?? "") } ?? ""
        if !slug(accountName).isEmpty, slug(accountName) != start { tries.append("\(start)-\(slug(accountName).prefix(24))") }
        for candidate in tries where key(candidate) == nil && Self.isValid(id: candidate) { return candidate }
        let stem = tries.last ?? start
        var number = 2
        while key("\(stem)-\(number)") != nil { number += 1 }
        return "\(stem)-\(number)"
    }

    // MARK: File

    public static func load(from url: URL) throws -> KeyIndex {
        guard FileManager.default.fileExists(atPath: url.path) else { return KeyIndex() }
        return try parse(try String(contentsOf: url, encoding: .utf8))
    }

    /// Reads the part of TOML this file uses, and calls anything else an error, since a guess could
    /// send one key where another was meant.
    public static func parse(_ text: String) throws -> KeyIndex {
        // Each key checked as `add` would, against a set of the names seen, and the whole list sorted once:
        // a file of many keys is read in one pass, not one search and insertion per key.
        var read: [Key] = []
        var seen: Set<String> = []
        var current: [String: String]?
        func finish() throws {
            guard let current else { return }
            guard let id = current["id"], let source = current["source"] else {
                throw VaultError("each [[key]] in keys.toml needs an id and a source")
            }
            let servers = current["servers"]?.split(whereSeparator: \.isWhitespace).map(String.init)
            guard servers?.allSatisfy({ $0.hasPrefix("SHA256:") }) ?? true else {
                throw VaultError("servers in keys.toml are fingerprints like SHA256:abc, as `ssh-keygen -l` writes them")
            }
            let key = Key(
                id: id, source: source, field: current["field"], provider: current["provider"],
                project: current["project"], account: current["account"], description: current["description"], variable: current["variable"],
                servers: servers)
            try check(key, taken: seen.contains(id))
            seen.insert(id)
            read.append(key)
        }
        for (number, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let bad = VaultError("keys.toml, line \(number + 1), is not something this reads")
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "[[key]]" {
                try finish()
                current = [:]
                continue
            }
            guard current != nil, let equals = line.firstIndex(of: "=") else { throw bad }
            let name = line[..<equals].trimmingCharacters(in: .whitespaces)
            guard ["id", "source", "field", "provider", "project", "account", "description", "variable", "servers"].contains(name),
                current?[name] == nil
            else { throw bad }
            var scanner = TomlScanner(text: String(line[line.index(after: equals)...]))
            current?[name] = try scanner.string(bad)
            try scanner.end(bad)
        }
        try finish()
        var index = KeyIndex()
        index.keys = read.sorted { $0.id < $1.id }
        return index
    }

    public var toml: String {
        var out = "# Your keys by identifier. This file holds no value. Edit it in the app, or here.\n"
        for key in keys {
            out += "\n[[key]]\nid = \(tomlQuoted(key.id))\n"
            if let description = key.description { out += "description = \(tomlQuoted(description))\n" }
            if let provider = key.provider { out += "provider = \(tomlQuoted(provider))\n" }
            if let project = key.project { out += "project = \(tomlQuoted(project))\n" }
            if let account = key.account { out += "account = \(tomlQuoted(account))\n" }
            out += "source = \(tomlQuoted(key.source))\n"
            if let field = key.field { out += "field = \(tomlQuoted(field))\n" }
            if let variable = key.variable { out += "variable = \(tomlQuoted(variable))\n" }
            if let servers = key.servers { out += "servers = \(tomlQuoted(servers.joined(separator: " ")))\n" }
        }
        return out
    }
}

func tomlQuoted(_ text: String) -> String {
    "\""
        + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "\\r")
        + "\""
}

struct TomlScanner {
    var rest: Substring
    init(text: String) { rest = Substring(text) }

    mutating func skipSpace() { rest = rest.drop { $0 == " " || $0 == "\t" } }

    mutating func string(_ bad: VaultError) throws -> String {
        skipSpace()
        guard rest.first == "\"" else { throw bad }
        rest = rest.dropFirst()
        var out = ""
        while let character = rest.first {
            rest = rest.dropFirst()
            switch character {
            case "\"": return out
            case "\\":
                guard let next = rest.first else { throw bad }
                switch next {
                case "\"", "\\": out.append(next)
                case "n": out.append("\n")
                case "r": out.append("\r")
                default: throw bad
                }
                rest = rest.dropFirst()
            default: out.append(character)
            }
        }
        throw bad
    }

    mutating func list(_ bad: VaultError) throws -> [String] {
        skipSpace()
        guard rest.first == "[" else { throw bad }
        rest = rest.dropFirst()
        var out: [String] = []
        while true {
            skipSpace()
            if rest.first == "]" {
                rest = rest.dropFirst()
                return out
            }
            out.append(try string(bad))
            skipSpace()
            if rest.first == "," {
                rest = rest.dropFirst()
            } else if rest.first != "]" {
                throw bad
            }
        }
    }

    mutating func end(_ bad: VaultError) throws {
        skipSpace()
        guard rest.isEmpty || rest.first == "#" else { throw bad }
    }
}
