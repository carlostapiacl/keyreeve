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
        /// What a book of every key (schema 2) also says of a key. The app keeps it as it reads it.
        public var more = More()

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

    /// The rest of what a book of every key says of one: kept as read and written back as it was.
    public struct More: Equatable, Sendable {
        public var recipes: [String]?
        public var name: String?
        public var level: String?
        public var tags: [String]?
        public var host: String?
        public var expires: String?
        public var criticality: Int?
        public var archived = false
        /// `static` or `oauth`. Only static keys work today.
        public var auth: String?
        /// `active` or `reauthorize`.
        public var state: String?
        public init() {}
    }

    /// The keys offered to agents. Everything that reads keys for agents sees these alone.
    public var keys: [Key]
    /// Keys a book of every key holds that no person has given to agents yet. They are kept, so no
    /// identifier is given twice and nothing is lost when the file is written again.
    public var unoffered: [Key] = []
    /// 1 for a book of agents' keys only, 2 for a book of every key, written by `keyreeve migrate`.
    public var schema = 1
    public static let fileName = "keys.toml"

    public init(keys: [Key] = []) { self.keys = keys }

    public func key(_ id: String) -> Key? { keys.first { $0.id == id } }

    /// Whether an identifier is in use, by a key offered to agents or not.
    public func isTaken(_ id: String) -> Bool { key(id) != nil || unoffered.contains { $0.id == id } }
    public func keys(forSource source: String) -> [Key] { keys.filter { $0.source == source } }
    /// The keys of a file, offered to agents or not: what the person sees in the app.
    public func allKeys(forSource source: String) -> [Key] { (keys + unoffered).filter { $0.source == source } }
    /// Whether agents may see the key by this identifier. A key not offered is one they cannot name.
    public func isOffered(_ id: String) -> Bool { key(id) != nil }

    /// The identifiers an agent may name: keys offered to agents whose file is sealed. A key not offered is left
    /// out here, so no agent learns that it exists.
    public func agentNames(sealed: Set<String>) -> [String] {
        keys.filter { sealed.contains($0.source) }.map(\.id)
    }

    /// What agents may read of each key offered to them, by identifier.
    public var agentDescriptions: [String: Key] {
        Dictionary(keys.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// Lower case with dashes: it ends up in scripts, so it has to be easy to type and safe to pass around.
    public static func isValid(id: String) -> Bool {
        guard (1...64).contains(id.count), let first = id.utf8.first, let last = id.utf8.last,
            first != 45, last != 45
        else { return false }
        return id.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }

    public mutating func add(_ key: Key) throws {
        var key = key
        // A key of the same file and field that waited, unoffered, is this one: it is taken over, with
        // what it said that this one does not, rather than kept as a second name for the same key.
        if let at = unoffered.firstIndex(where: { $0.source == key.source && ($0.field == key.field || $0.field == nil || key.field == nil) }) {
            let waiting = unoffered.remove(at: at)
            key.field = key.field ?? waiting.field
            key.provider = key.provider ?? waiting.provider
            key.project = key.project ?? waiting.project
            key.account = key.account ?? waiting.account
            key.description = key.description ?? waiting.description
            key.variable = key.variable ?? waiting.variable
            key.servers = key.servers ?? waiting.servers
            if key.more == More() { key.more = waiting.more }
        }
        try Self.check(key, taken: isTaken(key.id))
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

    /// Adds a key no agent sees until a person offers it: what an identifier given in bulk, not chosen by a
    /// person for this key, starts as.
    public mutating func addUnoffered(_ key: Key) throws {
        try Self.check(key, taken: isTaken(key.id))
        unoffered.insert(key, at: unoffered.firstIndex { $0.id > key.id } ?? unoffered.endIndex)
    }

    /// Lets agents see the key: list it, ask for it, and use it once a person opens it to them.
    public mutating func offer(id: String) {
        guard let at = unoffered.firstIndex(where: { $0.id == id }) else { return }
        let key = unoffered.remove(at: at)
        keys.insert(key, at: keys.firstIndex { $0.id > key.id } ?? keys.endIndex)
    }

    /// Takes the key out of agents' sight, keeping its identifier and all it says.
    public mutating func withdraw(id: String) {
        guard let at = keys.firstIndex(where: { $0.id == id }) else { return }
        let key = keys.remove(at: at)
        unoffered.insert(key, at: unoffered.firstIndex { $0.id > key.id } ?? unoffered.endIndex)
    }

    /// Changes a key wherever it is, offered or not.
    public mutating func update(id: String, _ change: (inout Key) -> Void) {
        if let at = keys.firstIndex(where: { $0.id == id }) { change(&keys[at]) }
        if let at = unoffered.firstIndex(where: { $0.id == id }) { change(&unoffered[at]) }
    }

    public mutating func remove(id: String) {
        keys.removeAll { $0.id == id }
        unoffered.removeAll { $0.id == id }
    }

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
        if !isTaken(start), Self.isValid(id: start) { return start }
        var number = 2
        while isTaken("\(start)-\(number)") { number += 1 }
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
        for candidate in tries where !isTaken(candidate) && Self.isValid(id: candidate) { return candidate }
        let stem = tries.last ?? start
        var number = 2
        while isTaken("\(stem)-\(number)") { number += 1 }
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
        var waiting: [Key] = []
        var seen: Set<String> = []
        var schema = 1
        var current: [String: String]?
        var lists: [String: [String]] = [:]
        var flags: [String: Bool] = [:]
        var numbers: [String: Int] = [:]
        let texts = ["id", "source", "field", "provider", "project", "account", "description", "variable", "servers",
                     "name", "level", "host", "expires", "auth", "state"]
        let listNames = ["recipes", "tags", "parts"]
        let flagNames = ["archived", "offered"]
        let numberNames = ["criticality"]
        func finish() throws {
            guard let current else { return }
            guard let id = current["id"], let source = current["source"] else {
                throw VaultError("each [[key]] in keys.toml needs an id and a source")
            }
            let servers = current["servers"]?.split(whereSeparator: \.isWhitespace).map(String.init)
            guard servers?.allSatisfy({ $0.hasPrefix("SHA256:") }) ?? true else {
                throw VaultError("servers in keys.toml are fingerprints like SHA256:abc, as `ssh-keygen -l` writes them")
            }
            if current["field"] != nil, lists["parts"] != nil {
                throw VaultError("\(id) in keys.toml names a field and parts: one or the other")
            }
            if let parts = lists["parts"], parts.count < 2 || parts.contains(where: \.isEmpty) {
                throw VaultError("parts in keys.toml are two or more labels")
            }
            if let auth = current["auth"], !["static", "oauth"].contains(auth) {
                throw VaultError("auth in keys.toml is static or oauth")
            }
            if let state = current["state"], !["active", "reauthorize"].contains(state) {
                throw VaultError("state in keys.toml is active or reauthorize")
            }
            if let level = current["level"], !["none", "free", "ask", "never"].contains(level) {
                throw VaultError("level in keys.toml is none, free, ask or never")
            }
            var more = More()
            more.recipes = lists["recipes"]
            more.tags = lists["tags"]
            more.name = current["name"]
            more.level = current["level"]
            more.host = current["host"]
            more.expires = current["expires"]
            more.criticality = numbers["criticality"].map { min($0, 5) }
            more.archived = flags["archived"] ?? false
            more.auth = current["auth"]
            more.state = current["state"]
            var key = Key(
                id: id, source: source, field: current["field"] ?? lists["parts"]?.joined(separator: "+"),
                provider: current["provider"], project: current["project"], account: current["account"],
                description: current["description"], variable: current["variable"], servers: servers)
            key.more = more
            try check(key, taken: seen.contains(id))
            seen.insert(id)
            if flags["offered"] == false { waiting.append(key) } else { read.append(key) }
        }
        for (number, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let bad = VaultError("keys.toml, line \(number + 1), is not something this reads")
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "[[key]]" {
                try finish()
                current = [:]
                lists = [:]
                flags = [:]
                numbers = [:]
                continue
            }
            guard let equals = line.firstIndex(of: "=") else { throw bad }
            let name = line[..<equals].trimmingCharacters(in: .whitespaces)
            var scanner = TomlScanner(text: String(line[line.index(after: equals)...]))
            guard current != nil else {
                // Before the first key, only the schema.
                guard name == "schema", let value = Int(try scanner.word(bad)), value >= 1 else { throw bad }
                try scanner.end(bad)
                schema = value
                continue
            }
            let taken = current?[name] != nil || lists[name] != nil || flags[name] != nil || numbers[name] != nil
            guard !taken else { throw bad }
            if texts.contains(name) {
                current?[name] = try scanner.string(bad)
            } else if listNames.contains(name) {
                lists[name] = try scanner.list(bad)
            } else if flagNames.contains(name) {
                switch try scanner.word(bad) {
                case "true": flags[name] = true
                case "false": flags[name] = false
                default: throw bad
                }
            } else if numberNames.contains(name) {
                guard let value = Int(try scanner.word(bad)), value >= 0 else { throw bad }
                numbers[name] = value
            } else {
                throw bad
            }
            try scanner.end(bad)
        }
        try finish()
        var index = KeyIndex()
        index.keys = read.sorted { $0.id < $1.id }
        index.unoffered = waiting.sorted { $0.id < $1.id }
        index.schema = schema
        return index
    }

    public var toml: String {
        var out = "# Your keys by identifier. This file holds no value. Edit it in the app, or here.\n"
        if schema >= 2 { out += "schema = \(schema)\n" }
        let all = (keys.map { ($0, true) } + unoffered.map { ($0, false) }).sorted { $0.0.id < $1.0.id }
        func list(_ items: [String]) -> String { "[" + items.map(tomlQuoted).joined(separator: ", ") + "]" }
        for (key, offered) in all {
            out += "\n[[key]]\nid = \(tomlQuoted(key.id))\n"
            if let description = key.description { out += "description = \(tomlQuoted(description))\n" }
            if let name = key.more.name { out += "name = \(tomlQuoted(name))\n" }
            if let provider = key.provider { out += "provider = \(tomlQuoted(provider))\n" }
            if let recipes = key.more.recipes { out += "recipes = \(list(recipes))\n" }
            if let project = key.project { out += "project = \(tomlQuoted(project))\n" }
            if let account = key.account { out += "account = \(tomlQuoted(account))\n" }
            out += "source = \(tomlQuoted(key.source))\n"
            if let field = key.field {
                // A book of every key keeps parts as a list; a book of the first version, as it always did.
                let parts = field.split(separator: "+", omittingEmptySubsequences: false).map(String.init)
                if schema >= 2, parts.count > 1, !parts.contains(where: \.isEmpty) {
                    out += "parts = \(list(parts))\n"
                } else {
                    out += "field = \(tomlQuoted(field))\n"
                }
            }
            if let auth = key.more.auth { out += "auth = \(tomlQuoted(auth))\n" }
            if let state = key.more.state { out += "state = \(tomlQuoted(state))\n" }
            if let variable = key.variable { out += "variable = \(tomlQuoted(variable))\n" }
            if let servers = key.servers { out += "servers = \(tomlQuoted(servers.joined(separator: " ")))\n" }
            if let level = key.more.level { out += "level = \(tomlQuoted(level))\n" }
            if let tags = key.more.tags { out += "tags = \(list(tags))\n" }
            if let host = key.more.host { out += "host = \(tomlQuoted(host))\n" }
            if let expires = key.more.expires { out += "expires = \(tomlQuoted(expires))\n" }
            if let criticality = key.more.criticality { out += "criticality = \(criticality)\n" }
            if key.more.archived { out += "archived = true\n" }
            if !offered { out += "offered = false\n" }
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

    /// A bare word, such as `true` or `2`, up to a space or a comment.
    mutating func word(_ bad: VaultError) throws -> String {
        skipSpace()
        let word = rest.prefix { !$0.isWhitespace && $0 != "#" }
        guard !word.isEmpty else { throw bad }
        rest = rest.dropFirst(word.count)
        return String(word)
    }

    mutating func end(_ bad: VaultError) throws {
        skipSpace()
        guard rest.isEmpty || rest.first == "#" else { throw bad }
    }
}
