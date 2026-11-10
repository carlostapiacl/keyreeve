import Foundation

/// The person's projects: a folder, the keys it uses, the files on this Mac where they live, and its key set. So "the
/// keys this project needs" and "where they are" are one thing. `projects.toml` holds identifiers and paths, never a
/// value or a hash of one. Only the person writes it, in the app; agents read it through `list_projects`.
public struct Projects: Equatable, Sendable {
    public struct Project: Equatable, Sendable, Identifiable {
        public var name: String
        /// The project's folder, a full path.
        public var folder: String
        /// The identifiers of the keys it uses, as keys.toml gives them.
        public var keys: [String]
        /// The files under it that hold its keys, such as its `.env`, as full paths.
        public var places: [String]
        /// Its key set in sets.toml, once the person made one.
        public var set: String?
        public var id: String { folder }

        public init(name: String, folder: String, keys: [String] = [], places: [String] = [], set: String? = nil) {
            self.name = name
            self.folder = folder
            self.keys = keys
            self.places = places
            self.set = set
        }
    }

    public var projects: [Project] = []

    public init(projects: [Project] = []) { self.projects = projects }

    public static let fileName = "projects.toml"
    public static let maxProjects = 1000
    public static let maxKeys = 200
    public static let maxPlaces = 50

    public static func file(home: URL) -> URL { home.appendingPathComponent(fileName) }

    public func project(at folder: String) -> Project? { projects.first { $0.folder == folder } }

    /// Adds a project, or adds keys and places to the one in the same folder. Its name and set stay as they were.
    public mutating func merge(_ project: Project) throws {
        try Self.check(project)
        if let at = projects.firstIndex(where: { $0.folder == project.folder }) {
            var both = projects[at]
            for key in project.keys where !both.keys.contains(key) { both.keys.append(key) }
            for place in project.places where !both.places.contains(place) { both.places.append(place) }
            if both.set == nil { both.set = project.set }
            try Self.check(both)
            projects[at] = both
        } else {
            guard projects.count < Self.maxProjects else { throw VaultError("at most \(Self.maxProjects) projects") }
            var clean = project
            clean.keys = Self.unique(project.keys)
            clean.places = Self.unique(project.places)
            projects.append(clean)
        }
        projects.sort { $0.folder < $1.folder }
    }

    /// Replaces a project by its folder, as the person edited it.
    public mutating func save(_ project: Project) throws {
        try Self.check(project)
        var clean = project
        clean.keys = Self.unique(project.keys)
        clean.places = Self.unique(project.places)
        if let at = projects.firstIndex(where: { $0.folder == project.folder }) { projects[at] = clean } else { projects.append(clean) }
        projects.sort { $0.folder < $1.folder }
    }

    public mutating func remove(folder: String) { projects.removeAll { $0.folder == folder } }

    static func unique(_ list: [String]) -> [String] {
        var out: [String] = []
        for item in list where !out.contains(item) { out.append(item) }
        return out
    }

    static func check(_ project: Project) throws {
        guard KeyIndex.isValid(id: project.name) else { throw VaultError("a project's name is lower case letters, digits and hyphens") }
        guard isPath(project.folder) else { throw VaultError("a project's folder is a full path") }
        guard Set(project.keys).count <= maxKeys, project.keys.allSatisfy(KeyIndex.isValid(id:)) else {
            throw VaultError("a project names at most \(maxKeys) keys, by their identifiers")
        }
        guard Set(project.places).count <= maxPlaces, project.places.allSatisfy(isPath) else {
            throw VaultError("a project's places are at most \(maxPlaces) full paths")
        }
        if let set = project.set, !KeySets.isValid(name: set) { throw VaultError("\(set) is not a set's name") }
    }

    static func isPath(_ text: String) -> Bool {
        text.hasPrefix("/") && text.count <= 1024 && !text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    /// A name for a folder, free among the projects there are.
    public func suggestedName(for folder: String) -> String {
        let base = KeyIndex().identifier(for: URL(fileURLWithPath: folder).lastPathComponent)
        var name = base
        var number = 2
        while projects.contains(where: { $0.name == name && $0.folder != folder }) {
            name = "\(base)-\(number)"
            number += 1
        }
        return name
    }

    // MARK: The file

    /// No file is no projects. A file that is there and cannot be read is an error, never empty.
    public static func loadStrict(from url: URL) throws -> Projects {
        guard FileManager.default.fileExists(atPath: url.path) else { return Projects() }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            throw VaultError("\(url.lastPathComponent) could not be read, so it was left as it is")
        }
        return try parse(text)
    }

    public static func load(from url: URL) -> Projects { (try? loadStrict(from: url)) ?? Projects() }

    /// Reads, changes and writes the file under one lock.
    @discardableResult
    public static func update(at url: URL, _ change: (inout Projects) throws -> Void) throws -> Projects {
        try PrivateFile.folder(url.deletingLastPathComponent())
        let lockFile = open(url.path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lockFile >= 0 else { throw VaultError("the projects could not be locked") }
        defer { close(lockFile) }
        guard flock(lockFile, LOCK_EX) == 0 else { throw VaultError("the projects could not be locked") }
        defer { flock(lockFile, LOCK_UN) }
        let before = try loadStrict(from: url)
        var after = before
        try change(&after)
        if after != before { try PrivateFile.write(Data(after.toml.utf8), to: url) }
        return after
    }

    public static func parse(_ text: String) throws -> Projects {
        var out = Projects()
        var open = false
        var fields: [String: String] = [:]
        var lists: [String: [String]] = [:]
        func finish(_ bad: VaultError) throws {
            guard open else { return }
            guard let name = fields["name"], let folder = fields["folder"] else { throw bad }
            let project = Project(
                name: name, folder: folder, keys: lists["keys"] ?? [], places: lists["places"] ?? [], set: fields["set"])
            try check(project)
            guard out.project(at: folder) == nil else { throw VaultError("projects.toml names the folder \(folder) twice") }
            out.projects.append(project)
        }
        for (index, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let bad = VaultError("projects.toml, line \(index + 1), is not something this reads")
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "[[project]]" {
                try finish(bad)
                open = true
                fields = [:]
                lists = [:]
                continue
            }
            guard open, let equals = line.firstIndex(of: "=") else { throw bad }
            let name = line[..<equals].trimmingCharacters(in: .whitespaces)
            var scanner = TomlScanner(text: String(line[line.index(after: equals)...]))
            if name == "keys" || name == "places" {
                guard lists[name] == nil else { throw bad }
                lists[name] = try scanner.list(bad)
            } else {
                guard ["name", "folder", "set"].contains(name), fields[name] == nil else { throw bad }
                fields[name] = try scanner.string(bad)
            }
            try scanner.end(bad)
        }
        try finish(VaultError("projects.toml does not hold together"))
        guard out.projects.count <= maxProjects else { throw VaultError("projects.toml holds too many projects") }
        return out
    }

    public var toml: String {
        let list = { (items: [String]) in "[" + items.map(tomlQuoted).joined(separator: ", ") + "]" }
        var out = """
            # Projects: a folder, the keys it uses, where they live on this Mac, and its key set. No value is kept here.

            """
        for project in projects {
            out += "\n[[project]]\nname = \(tomlQuoted(project.name))\nfolder = \(tomlQuoted(project.folder))\n"
            out += "keys = \(list(project.keys))\nplaces = \(list(project.places))\n"
            if let set = project.set { out += "set = \(tomlQuoted(set))\n" }
        }
        return out
    }

    // MARK: For agents

    /// What `list_projects` answers: each project's name, folder and places' count, the identifiers of its keys that
    /// are offered to agents, and only a count of the rest.
    public func forAgents(offered: Set<String>, home: String = NSHomeDirectory()) -> String {
        let rows: [[String: Any]] = projects.map { project in
            let shown = project.keys.filter(offered.contains)
            var row: [String: Any] = ["name": project.name, "folder": AgentBringing.short(project.folder, home: home), "keys": shown]
            if shown.count < project.keys.count { row["other_keys"] = project.keys.count - shown.count }
            if !project.places.isEmpty { row["places"] = project.places.count }
            if let set = project.set { row["set"] = set }
            return row
        }
        let out: [String: Any] = [
            "projects": rows,
            "note":
                "Keys not offered to you are only counted. Projects are the person's: they make and change them in Keyreeve, under Projects, often from what find_keys found.",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}

/// The folders Bring in never looks in, in `bring.toml`, which the engine reads too: a full path (or `~/path`) leaves
/// out that folder and everything under it, and a name with no `/` every folder of that name.
public enum BringIgnore {
    public static let fileName = "bring.toml"
    public static let maxRules = 200

    public static func file(home: URL) -> URL { home.appendingPathComponent(fileName) }

    /// The list, or none without a file. A file that cannot be read is an error, never "look everywhere".
    public static func load(from url: URL) throws -> [String] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { throw VaultError("\(fileName) could not be read") }
        return try parse(text)
    }

    /// `ignore = [...]`, on one line or several, with comments, as the engine reads it.
    public static func parse(_ text: String) throws -> [String] {
        var joined = ""
        var seen = false
        for (index, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let bad = VaultError("\(fileName), line \(index + 1), is not something this reads")
            if !seen {
                guard line.hasPrefix("ignore"), let equals = line.firstIndex(of: "="),
                    line[line.index(line.startIndex, offsetBy: 6)..<equals].allSatisfy(\.isWhitespace)
                else { throw bad }
                seen = true
                joined = withoutComment(String(line[line.index(after: equals)...]))
            } else {
                joined += " " + withoutComment(line)
            }
        }
        guard seen else { return [] }
        let bad = VaultError("\(fileName) is not something this reads")
        // A comma before the end, as the engine writes the list.
        let trailing = try NSRegularExpression(pattern: #",\s*\]\s*$"#)
        let range = NSRange(joined.startIndex..., in: joined)
        var scanner = TomlScanner(text: trailing.stringByReplacingMatches(in: joined, range: range, withTemplate: "]"))
        let list = try scanner.list(bad)
        try scanner.end(bad)
        guard list.count <= maxRules else { throw bad }
        return list
    }

    /// The line up to a `#` that is not inside quotes.
    static func withoutComment(_ line: String) -> String {
        var quoted = false
        var escaped = false
        var out = ""
        for character in line {
            if character == "#", !quoted { break }
            if character == "\"", !escaped { quoted.toggle() }
            escaped = character == "\\" && !escaped
            out.append(character)
        }
        return out.trimmingCharacters(in: .whitespaces)
    }

    public static func render(_ rules: [String]) -> String {
        var out = "# Folders Bring in never looks in. A full path (or ~/path) leaves out that folder and all under it;\n"
        out += "# a name with no / leaves out every folder of that name.\nignore = [\n"
        for rule in rules {
            out += "  \"" + rule.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\",\n"
        }
        return out + "]\n"
    }

    /// Whether a rule can be kept: one line, a full path, `~/path` or a folder's name.
    public static func isValid(_ rule: String) -> Bool {
        let rule = rule.trimmingCharacters(in: .whitespaces)
        guard !rule.isEmpty, rule.count <= 1024, !rule.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return false }
        return rule.hasPrefix("/") || rule == "~" || rule.hasPrefix("~/") || !rule.contains("/")
    }

    /// Changes the list and writes it in one rename, private to this user.
    @discardableResult
    public static func update(at url: URL, _ change: (inout [String]) -> Void) throws -> [String] {
        var rules = try load(from: url)
        let before = rules
        change(&rules)
        var unique: [String] = []
        for rule in rules.map({ $0.trimmingCharacters(in: .whitespaces) }) where isValid(rule) && !unique.contains(rule) {
            unique.append(rule)
        }
        guard unique.count <= maxRules else { throw VaultError("at most \(maxRules) folders") }
        if unique != before {
            try PrivateFile.folder(url.deletingLastPathComponent())
            try PrivateFile.write(Data(render(unique).utf8), to: url)
        }
        return unique
    }

    /// A folder as the list writes it: `~/path` under the home folder.
    public static func rule(for folder: String, home: String = NSHomeDirectory()) -> String {
        AgentBringing.short(folder, home: home)
    }
}
