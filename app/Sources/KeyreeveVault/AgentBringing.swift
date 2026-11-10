import CryptoKit
import Foundation

/// An agent finding keys and proposing which to bring in. It reads what `keyreeve bring --dry-run --json`
/// says, which names files, the names inside them and where each value stands, and never a value. Nothing
/// is sent to a provider from here, and nothing is sealed: the person reviews the proposal in the app,
/// where the keys are checked and sealed with their fingerprint.
public enum AgentBringing {
    public static let kind = "bring"
    public static let maxItems = 500
    public static let defaultLimit = 100
    public static let maxLimit = 300
    /// Long enough for a home folder with a few large project folders.
    public static let engineSeconds: TimeInterval = 5 * 60

    /// Where to look, as the agent asked.
    public struct Scope: Codable, Equatable, Sendable {
        public var places: Bool
        public var projects: [String]
        public var folder: String?

        public init(places: Bool, projects: [String], folder: String?) {
            self.places = places
            self.projects = projects
            self.folder = folder
        }

        /// The engine's arguments, always without checks: `--dry-run`, and never `--check`.
        public var arguments: [String] {
            let scope = folder.map { ["--folder", $0] } ?? (["--places"] + projects.flatMap { ["--projects", $0] })
            return ["bring"] + scope + ["--dry-run", "--json"]
        }

        /// Reads the tool's arguments. Folders must be absolute, or start with `~`, and be there.
        public static func read(_ arguments: [String: Any], home: String = NSHomeDirectory()) throws -> Scope {
            func folder(_ text: String) throws -> String {
                let expanded = text == "~" ? home : text.hasPrefix("~/") ? home + text.dropFirst(1) : text
                guard expanded.hasPrefix("/") else { throw VaultError("\(text) is not a full path. Give folders as /path or ~/path") }
                var isFolder: ObjCBool = false
                guard FileManager.default.fileExists(atPath: expanded, isDirectory: &isFolder), isFolder.boolValue else {
                    throw VaultError("\(text) is not a folder on this Mac")
                }
                return URL(fileURLWithPath: expanded).standardizedFileURL.path
            }
            if arguments["projects"] != nil, !(arguments["projects"] is [String]) { throw VaultError("projects is a list of folders") }
            if arguments["folder"] != nil, !(arguments["folder"] is String) { throw VaultError("folder is one folder") }
            let projects = try (arguments["projects"] as? [String] ?? []).map(folder)
            guard projects.count <= 20 else { throw VaultError("at most 20 project folders at once") }
            if let one = arguments["folder"] as? String {
                guard projects.isEmpty, arguments["places"] as? Bool != true else {
                    throw VaultError("give folder alone, or places with projects, not both")
                }
                return Scope(places: false, projects: [], folder: try folder(one))
            }
            guard arguments["places"] as? Bool ?? true else {
                throw VaultError("nothing to look in: set places, or give a folder")
            }
            return Scope(places: true, projects: projects, folder: nil)
        }
    }

    /// One piece of a key as found: the name in the file, or its line.
    public struct Part: Equatable, Sendable {
        public var name: String?
        public var line: Int
        public var whole: Bool

        public init(name: String?, line: Int, whole: Bool) {
            self.name = name
            self.line = line
            self.whole = whole
        }

        /// How the part is told apart in a signature, the same in the app and here.
        public var label: String { name ?? (whole ? "(whole file)" : "line \(line)") }

        /// How it is shown to an agent: a name that reads as a name, or else its line.
        var shown: String {
            if let name, (1...64).contains(name.count),
                name.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || "_-.:/@".unicodeScalars.contains($0) })
            {
                return name
            }
            return whole ? "whole file" : "line \(line)"
        }
    }

    /// One place a key was found.
    public struct Origin: Equatable, Sendable {
        public var path: String
        public var parts: [Part]

        public init(path: String, parts: [Part]) {
            self.path = path
            self.parts = parts
        }

        /// A key's place: its file and the names of its parts. Numbers change from one search to the next,
        /// and this does not, so the app finds the agent's choice again in its own search.
        public var signature: String { AgentBringing.signature(path: path, parts: parts.map(\.label)) }
    }

    /// A digest, so the proposal keeps only what the agent was shown and the names stay as the engine gave them.
    public static func signature(path: String, parts: [String]) -> String {
        let text = path + "\u{0}" + parts.joined(separator: "\u{1}")
        return SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// One candidate, with only what an agent may read.
    public struct Found: Equatable, Sendable {
        public var number: Int
        /// `key`, `login`, `configuration`, `document` or `public`.
        public var kind: String
        public var why: String?
        public var provider: String?
        public var evidence: String?
        public var guessed: [String]
        public var origins: [Origin]
        public var duplicate: Bool
        public var fromProject: Bool

        public var isSecret: Bool { kind == "key" || kind == "login" }
    }

    /// A search, kept by the agent's server for the proposal that follows.
    public struct Scan: Equatable, Sendable {
        public var scope: Scope
        public var files: Int
        public var roots: [String]
        public var skipped: [String: Int]
        public var found: [Found]

        public func candidate(_ number: Int) -> Found? { found.first { $0.number == number } }
    }

    /// Reads the engine's report field by field. Whatever else it holds is never read, so nothing past these
    /// fields can reach an agent.
    public static func read(_ data: Data, scope: Scope) throws -> Scan {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let list = object["candidates"] as? [[String: Any]]
        else { throw VaultError("the list of keys found could not be read") }
        let found: [Found] = list.compactMap { row in
            guard let number = row["id"] as? Int, let kind = row["class"] as? String else { return nil }
            let origins: [Origin] = (row["origins"] as? [[String: Any]] ?? []).compactMap { origin in
                guard let path = origin["path"] as? String else { return nil }
                let parts = (origin["parts"] as? [[String: Any]] ?? []).map { part in
                    Part(name: part["name"] as? String, line: part["line"] as? Int ?? 0, whole: part["whole"] as? Bool ?? false)
                }
                return Origin(path: path, parts: parts)
            }
            guard !origins.isEmpty else { return nil }
            return Found(
                number: number, kind: kind, why: row["why"] as? String, provider: row["provider"] as? String,
                evidence: row["evidence"] as? String, guessed: row["guessed"] as? [String] ?? [], origins: origins,
                duplicate: row["duplicate"] as? Bool ?? false, fromProject: row["from_project"] as? Bool ?? false)
        }
        let skipped = (object["skipped"] as? [String: Any] ?? [:]).compactMapValues { $0 as? Int }.filter { $0.value > 0 }
        return Scan(
            scope: scope, files: object["files"] as? Int ?? 0, roots: object["roots"] as? [String] ?? [], skipped: skipped,
            found: found)
    }

    /// Whether a key looks sealed already: one of its files is the source of a key in keys.toml, or the
    /// name or recorded origin of a vault entry. By place only, never by value.
    public static func looksSealed(_ found: Found, sealed: Set<String>) -> Bool {
        found.origins.contains { sealed.contains($0.path) }
    }

    /// What `find_keys` answers: keys and logins in pages, and only counts for everything else.
    public static func report(_ scan: Scan, sealed: Set<String>, known: [String], offset: Int, limit: Int) -> String {
        let secrets = scan.found.filter(\.isSecret)
        let start = min(max(offset, 0), secrets.count)
        let end = min(start + max(1, min(limit, maxLimit)), secrets.count)
        func count(_ kind: String) -> Int { scan.found.filter { $0.kind == kind }.count }
        let rows: [[String: Any]] = secrets[start..<end].map { found in
            var row: [String: Any] = [
                "n": found.number, "class": found.kind,
                "names": found.origins[0].parts.map(\.shown).joined(separator: " + "),
                "from": found.origins.prefix(5).map { origin in
                    origin.path + (origin.parts.first.map { $0.whole ? "" : ":\($0.line)" } ?? "")
                },
            ]
            if found.origins.count > 5 { row["more_places"] = found.origins.count - 5 }
            if let provider = found.provider {
                row["provider"] = provider
                row["by"] = found.evidence ?? "evidence"
            }
            if !found.guessed.isEmpty { row["guess"] = found.guessed }
            if found.duplicate { row["duplicate"] = true }
            if found.fromProject { row["project_uses_it"] = true }
            if looksSealed(found, sealed: sealed) { row["looks_sealed"] = true }
            if let why = found.why { row["why"] = why }
            return row
        }
        var out: [String: Any] = [
            "scope": scan.scope.folder == nil ? "places" : "folder", "roots": scan.roots, "files": scan.files,
            "counts": [
                "keys": count("key"), "logins": count("login"), "configuration": count("configuration"),
                "documents": count("document"), "public": count("public"),
                "duplicates": secrets.filter(\.duplicate).count,
                "looks_sealed": secrets.filter { looksSealed($0, sealed: sealed) }.count,
            ],
            "offset": start, "keys": rows,
            "next":
                "Values are never shown. To bring keys in, call propose_bring with their n. Configuration, documents and public keys are counted only, and are not sealed.",
        ]
        if !scan.skipped.isEmpty { out["skipped"] = scan.skipped }
        if end < secrets.count { out["next_offset"] = end }
        if start == 0 { out["known_providers"] = known.sorted() }
        guard let data = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    /// An agent's proposal, kept for the app. Each item is one candidate, found again by its signatures.
    public struct Proposal: Codable, Equatable, Sendable {
        public struct Item: Codable, Equatable, Sendable {
            public var candidate: Int
            public var origins: [String]
            /// The names of its parts, to show one the app no longer finds.
            public var names: String
            public var seal: Bool
            public var id: String?
            public var provider: String?
            public var description: String?
            public var tags: [String]?
            /// Why the agent would skip it.
            public var reason: String?
        }

        public var scope: Scope
        public var items: [Item]

        public var sealCount: Int { items.filter(\.seal).count }
    }

    /// Checks an agent's choices against its latest search, and refuses the whole of it on any mistake, so
    /// a proposal is never half kept. Notes are what will not happen as asked.
    public static func check(
        seal: Any?, skip: Any?, scan: Scan, known: Set<String>, sealed: Set<String>
    ) throws -> (proposal: Proposal, notes: [String]) {
        if seal != nil, !(seal is [[String: Any]]) { throw VaultError("seal is a list of objects, each with candidates") }
        if skip != nil, !(skip is [[String: Any]]) { throw VaultError("skip is a list of objects, each with candidate and reason") }
        let toSeal = seal as? [[String: Any]] ?? []
        let toSkip = skip as? [[String: Any]] ?? []
        guard !toSeal.isEmpty || !toSkip.isEmpty else { throw VaultError("give seal, skip, or both") }
        var items: [Proposal.Item] = []
        var notes: [String] = []
        var seen: Set<Int> = []
        var ids: Set<String> = []
        func candidate(_ number: Int) throws -> Found {
            guard let found = scan.candidate(number) else {
                throw VaultError("there is no candidate \(number) in your last find_keys. Call find_keys again")
            }
            guard found.isSecret else {
                throw VaultError("candidate \(number) is \(found.kind), not a key or a login, and is not sealed")
            }
            guard seen.insert(number).inserted else { throw VaultError("candidate \(number) is named twice") }
            return found
        }
        func numbers(_ row: [String: Any]) throws -> [Int] {
            if let list = row["candidates"] as? [Int], !list.isEmpty { return list }
            if let one = row["candidate"] as? Int { return [one] }
            throw VaultError("each item needs candidates, a list of numbers from find_keys")
        }
        for row in toSeal {
            let list = try numbers(row)
            var id = (row["id"] as? String).map { $0.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 }
            if let wanted = id {
                guard list.count == 1 else { throw VaultError("id \(wanted) names one key, so give it with one candidate") }
                guard KeyIndex.isValid(id: wanted) else {
                    throw VaultError("\(wanted) is not an identifier: lower case letters, digits and dashes, at most 64")
                }
                guard ids.insert(wanted).inserted else { throw VaultError("id \(wanted) is given twice") }
                id = wanted
            }
            let provider = (row["provider"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            if let provider, !known.contains(provider) {
                throw VaultError("no provider \(provider) is known. Use one from known_providers in find_keys")
            }
            let description = (row["description"] as? String).map { String(AgentRequest.oneLine($0).prefix(200)) }
                .flatMap { $0.isEmpty ? nil : $0 }
            if row["tags"] != nil, !(row["tags"] is [String]) { throw VaultError("tags is a list of words") }
            let tags = (row["tags"] as? [String] ?? []).compactMap(cleanTag).prefix(10)
            for number in list {
                let found = try candidate(number)
                if let provider, let strong = found.provider, provider != strong {
                    notes.append("\(number): its \(found.evidence ?? "evidence") names \(strong), so it is saved as \(strong)")
                } else if let provider, found.provider == nil {
                    notes.append("\(number): \(provider) is shown to the person as your suggestion, and not saved with the key")
                }
                if looksSealed(found, sealed: sealed) { notes.append("\(number) looks sealed already") }
                items.append(Proposal.Item(
                    candidate: number, origins: found.origins.map(\.signature),
                    names: found.origins[0].parts.map(\.shown).joined(separator: " + "), seal: true, id: id,
                    provider: provider, description: description, tags: tags.isEmpty ? nil : Array(tags), reason: nil))
            }
        }
        for row in toSkip {
            let reason = (row["reason"] as? String).map { String(AgentRequest.oneLine($0).prefix(200)) } ?? ""
            guard !reason.isEmpty else { throw VaultError("each candidate to skip needs a reason") }
            for number in try numbers(row) {
                let found = try candidate(number)
                items.append(Proposal.Item(
                    candidate: number, origins: found.origins.map(\.signature),
                    names: found.origins[0].parts.map(\.shown).joined(separator: " + "), seal: false, id: nil, provider: nil,
                    description: nil, tags: nil, reason: reason))
            }
        }
        guard items.count <= maxItems else { throw VaultError("at most \(maxItems) candidates at once") }
        return (Proposal(scope: scan.scope, items: items), notes)
    }

    /// A tag as keys.toml keeps them: lower case, with no spaces.
    static func cleanTag(_ text: String) -> String? {
        let tag = text.lowercased().trimmingCharacters(in: .whitespaces)
        guard (1...40).contains(tag.count),
            tag.unicodeScalars.allSatisfy({ CharacterSet.lowercaseLetters.contains($0) || CharacterSet.decimalDigits.contains($0) || "-_:".unicodeScalars.contains($0) })
        else { return nil }
        return tag
    }

    public static func encode(_ proposal: Proposal) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(proposal)
    }

    public static func decode(_ data: Data) -> Proposal? { try? JSONDecoder().decode(Proposal.self, from: data) }

    /// Runs the engine and returns what it printed. Only the report is read; the engine prints no value.
    public static func runEngine(binary: URL, arguments: [String], environment: [String: String]? = nil) throws -> Data {
        guard FileManager.default.isExecutableFile(atPath: binary.path) else {
            throw VaultError("keyreeve's command is not beside this server, so keys cannot be looked for here")
        }
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        if let environment { process.environment = environment }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        try process.run()
        let timer = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + engineSeconds, execute: timer)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        timer.cancel()
        guard process.terminationReason == .exit else { throw VaultError("looking for keys took too long and was stopped") }
        guard process.terminationStatus == 0 else {
            throw VaultError("looking for keys ended with code \(process.terminationStatus)")
        }
        return data
    }
}
