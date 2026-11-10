import Foundation

/// The keys a project needs, by name, so they are asked for in one window. A set grants nothing on its own: using
/// one still shows every key and asks for the person's finger. `sets.toml` also keeps the permissions a person gave
/// "always, for this program in this folder", each with its own list of keys, so editing a set never widens one.
public struct KeySets: Equatable, Sendable {
    public struct Set: Equatable, Sendable, Identifiable {
        public var name: String
        public var keys: [String]
        /// The project's folder, if the set belongs to one.
        public var folder: String?
        public var id: String { name }

        public init(name: String, keys: [String], folder: String? = nil) {
            self.name = name
            self.keys = keys
            self.folder = folder
        }
    }

    /// A permission given with the person's finger for one program in one folder, that needs no finger again. It uses
    /// the copy sealed to the chip's key that asks nothing, as "always, no fingerprint" does, and only through the proxy.
    public struct Standing: Equatable, Sendable, Identifiable {
        public var keys: [String]
        /// The program's full path, and its SHA-256 when the person allowed it. A program that changed is asked again.
        public var program: String
        public var hash: String
        /// The script the program ran, for an interpreter such as python3, pinned the same way.
        public var script: String?
        public var scriptHash: String?
        public var folder: String
        public var since: Date
        /// The set it was given for, if any. A label only.
        public var set: String?
        public var id: String { program + "\u{0}" + (script ?? "") + "\u{0}" + folder }

        public init(
            keys: [String], program: String, hash: String, script: String? = nil, scriptHash: String? = nil, folder: String,
            since: Date, set: String? = nil
        ) {
            self.keys = keys
            self.program = program
            self.hash = hash
            self.script = script
            self.scriptHash = scriptHash
            self.folder = folder
            self.since = since
            self.set = set
        }

        /// Whether this covers `key` for this program, script and folder as they are on disk now.
        public func covers(
            key: String, program: String?, script: String?, folder: String?, fingerprint: (String) -> String?
        ) -> Bool {
            guard keys.contains(key), let program, program == self.program, let folder, folder == self.folder,
                script == self.script, fingerprint(program) == hash
            else { return false }
            guard let script else { return true }
            return scriptHash != nil && fingerprint(script) == scriptHash
        }
    }

    public var sets: [Set] = []
    public var standing: [Standing] = []

    public init(sets: [Set] = [], standing: [Standing] = []) {
        self.sets = sets
        self.standing = standing
    }

    public static let fileName = "sets.toml"
    public static let maxKeys = 40

    public func set(_ name: String) -> Set? { sets.first { $0.name == name } }

    /// A set's name follows the identifiers' rules: lower case, digits and hyphens.
    public static func isValid(name: String) -> Bool { KeyIndex.isValid(id: name) }

    /// Adds or replaces a set by its name.
    public mutating func save(_ set: Set) throws {
        guard Self.isValid(name: set.name) else { throw VaultError("a set's name is lower case letters, digits and hyphens") }
        var unique: [String] = []
        for key in set.keys where !unique.contains(key) { unique.append(key) }
        guard !unique.isEmpty, unique.count <= Self.maxKeys else { throw VaultError("a set holds from 1 to \(Self.maxKeys) keys") }
        var clean = set
        clean.keys = unique
        if let at = sets.firstIndex(where: { $0.name == set.name }) { sets[at] = clean } else { sets.append(clean) }
        sets.sort { $0.name < $1.name }
    }

    /// Keys whose standing permission still names them: their copy that asks nothing has to stay.
    public var standingKeys: Swift.Set<String> { Swift.Set(standing.flatMap(\.keys)) }

    // MARK: The file

    /// No file is no sets. A file that is there and cannot be read is an error, never empty.
    public static func loadStrict(from url: URL) throws -> KeySets {
        guard FileManager.default.fileExists(atPath: url.path) else { return KeySets() }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            throw VaultError("\(url.lastPathComponent) could not be read, so it was left as it is")
        }
        return try parse(text)
    }

    /// A file that cannot be read gives no sets and no standing permission, so a typo never widens anything.
    public static func load(from url: URL) -> KeySets { (try? loadStrict(from: url)) ?? KeySets() }

    /// Reads, changes and writes the file under one lock, as the permissions are.
    @discardableResult
    public static func update(at url: URL, _ change: (inout KeySets) throws -> Void) throws -> KeySets {
        try PrivateFile.folder(url.deletingLastPathComponent())
        let lockFile = open(url.path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lockFile >= 0 else { throw VaultError("the sets could not be locked") }
        defer { close(lockFile) }
        guard flock(lockFile, LOCK_EX) == 0 else { throw VaultError("the sets could not be locked") }
        defer { flock(lockFile, LOCK_UN) }
        let before = try loadStrict(from: url)
        var after = before
        try change(&after)
        if after != before { try PrivateFile.write(Data(after.toml.utf8), to: url) }
        return after
    }

    public static func parse(_ text: String) throws -> KeySets {
        var out = KeySets()
        var table: String?
        var fields: [String: String] = [:]
        var lists: [String: [String]] = [:]
        let format = ISO8601DateFormatter()
        func finish(_ bad: VaultError) throws {
            guard let table else { return }
            if table == "set" {
                guard let name = fields["name"], isValid(name: name), let keys = lists["keys"], !keys.isEmpty else { throw bad }
                guard out.set(name) == nil else { throw VaultError("sets.toml names the set \(name) twice") }
                out.sets.append(Set(name: name, keys: keys, folder: fields["folder"]))
            } else {
                guard let keys = lists["keys"], !keys.isEmpty, let program = fields["program"], let hash = fields["hash"],
                    let folder = fields["folder"], let since = fields["since"].flatMap(format.date(from:)),
                    (fields["script"] == nil) == (fields["script_hash"] == nil)
                else { throw bad }
                out.standing.append(Standing(
                    keys: keys, program: program, hash: hash, script: fields["script"], scriptHash: fields["script_hash"],
                    folder: folder, since: since, set: fields["set"]))
            }
        }
        for (index, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let bad = VaultError("sets.toml, line \(index + 1), is not something this reads")
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "[[set]]" || line == "[[always]]" {
                try finish(bad)
                table = line == "[[set]]" ? "set" : "always"
                fields = [:]
                lists = [:]
                continue
            }
            guard let current = table, let equals = line.firstIndex(of: "=") else { throw bad }
            let name = line[..<equals].trimmingCharacters(in: .whitespaces)
            var scanner = TomlScanner(text: String(line[line.index(after: equals)...]))
            let allowed: [String] = current == "set"
                ? ["name", "folder"] : ["program", "hash", "script", "script_hash", "folder", "since", "set"]
            if name == "keys" {
                guard lists[name] == nil else { throw bad }
                lists[name] = try scanner.list(bad)
            } else {
                guard allowed.contains(name), fields[name] == nil else { throw bad }
                fields[name] = try scanner.string(bad)
            }
            try scanner.end(bad)
        }
        try finish(VaultError("sets.toml does not hold together"))
        return out
    }

    public var toml: String {
        let quoted = { (text: String) in tomlQuoted(text) }
        let list = { (items: [String]) in "[" + items.map(quoted).joined(separator: ", ") + "]" }
        var out = """
            # Key sets: the keys a project needs, asked for in one window. A set grants nothing on its own.
            # [[always]] is a permission you gave with your finger for one program in one folder. Remove it in Keyreeve.

            """
        for set in sets {
            out += "\n[[set]]\nname = \(quoted(set.name))\nkeys = \(list(set.keys))\n"
            if let folder = set.folder { out += "folder = \(quoted(folder))\n" }
        }
        let format = ISO8601DateFormatter()
        for grant in standing {
            out += "\n[[always]]\nkeys = \(list(grant.keys))\nprogram = \(quoted(grant.program))\nhash = \(quoted(grant.hash))\n"
            if let script = grant.script, let hash = grant.scriptHash {
                out += "script = \(quoted(script))\nscript_hash = \(quoted(hash))\n"
            }
            out += "folder = \(quoted(grant.folder))\nsince = \(quoted(format.string(from: grant.since)))\n"
            if let set = grant.set { out += "set = \(quoted(set))\n" }
        }
        return out
    }

    // MARK: Suggestions

    /// What a project used lately, as a set to suggest: the keys used by one program in one folder within `window`,
    /// from the usage log. Only keys offered to agents, so a set never names one that is not.
    public struct Suggestion: Equatable, Sendable, Identifiable {
        public var folder: String
        public var program: String
        public var keys: [String]
        public var id: String { folder + "\u{0}" + program }
        public init(folder: String, program: String, keys: [String]) {
            self.folder = folder
            self.program = program
            self.keys = keys
        }
    }

    public static func suggestions(
        from entries: [AuditLog.Entry], offered: Swift.Set<String>, now: Date = Date(), window: TimeInterval = 3600
    ) -> [Suggestion] {
        var found: [String: Suggestion] = [:]
        var order: [String] = []
        for entry in entries where ["used", "granted"].contains(entry.event) && now.timeIntervalSince(entry.at) <= window {
            guard offered.contains(entry.key), let folder = entry.declared?.cwd, !folder.isEmpty,
                let program = entry.declared?.command.flatMap({ $0.split(separator: " ").first.map(String.init) })
            else { continue }
            let id = folder + "\u{0}" + program
            if found[id] == nil {
                found[id] = Suggestion(folder: folder, program: program, keys: [])
                order.append(id)
            }
            if !(found[id]?.keys.contains(entry.key) ?? true) { found[id]?.keys.append(entry.key) }
        }
        // One key is not worth a set.
        return order.compactMap { found[$0] }.filter { $0.keys.count > 1 }.map {
            var sorted = $0
            sorted.keys.sort()
            return sorted
        }
    }

    /// A name for a set from its folder, free among the sets there are.
    public func suggestedName(for folder: String) -> String {
        let base = KeyIndex().identifier(for: URL(fileURLWithPath: folder).lastPathComponent)
        var name = base
        var number = 2
        while set(name) != nil {
            name = "\(base)-\(number)"
            number += 1
        }
        return name
    }
}
