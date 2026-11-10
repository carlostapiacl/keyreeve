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
        public enum Place: String, Codable, Sendable {
            /// The whole home folder, with the usual places, within a time budget.
            case everywhere
            /// The places tools keep keys, and `.env` files under `projects`.
            case places
            /// Only `folders`, walked as everywhere is.
            case folders
        }

        public var place: Place
        public var projects: [String]
        public var folders: [String]

        public init(place: Place, projects: [String] = [], folders: [String] = []) {
            self.place = place
            self.projects = projects
            self.folders = folders
        }

        /// The engine's arguments, always without checks: `--dry-run`, and never `--check`.
        public var arguments: [String] {
            let scope: [String]
            switch place {
            case .everywhere: scope = ["--everywhere"]
            case .folders: scope = ["--everywhere"] + folders.flatMap { ["--under", $0] }
            case .places: scope = ["--places"] + projects.flatMap { ["--projects", $0] }
            }
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
            func list(_ name: String) throws -> [String] {
                guard let value = arguments[name] else { return [] }
                guard let list = value as? [String] else { throw VaultError("\(name) is a list of folders") }
                guard list.count <= 50 else { throw VaultError("at most 50 \(name) at once") }
                return try list.map(folder)
            }
            let named = arguments["where"] as? String ?? Place.places.rawValue
            guard let place = Place(rawValue: named) else { throw VaultError("where is everywhere, places or folders") }
            let projects = try list("projects")
            let folders = try list("folders")
            switch place {
            case .everywhere:
                guard projects.isEmpty, folders.isEmpty else {
                    throw VaultError("everywhere is the whole home folder: give no projects or folders with it")
                }
            case .places:
                guard folders.isEmpty else { throw VaultError("folders go with where = folders") }
            case .folders:
                guard !folders.isEmpty else { throw VaultError("where = folders needs folders") }
                guard projects.isEmpty else { throw VaultError("projects go with where = places") }
            }
            return Scope(place: place, projects: projects, folders: folders)
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
        /// The project the file is in.
        public var project: String

        public init(path: String, parts: [Part], project: String? = nil) {
            self.path = path
            self.parts = parts
            self.project = project ?? URL(fileURLWithPath: path).deletingLastPathComponent().path
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
        /// Whether the vault holds it, by value, or nil when that could not be compared.
        public var sealed: Sealed?

        public var isSecret: Bool { kind == "key" || kind == "login" }
        /// The project of the first place it was found.
        public var project: String { origins.first?.project ?? "" }
    }

    /// What the vault holds of a key found, compared by keyed digest.
    public enum Sealed: Equatable, Sendable {
        /// In the vault now, under these keys. Agents see only those offered to them.
        case now([String])
        /// An earlier value of these keys, such as the one before a rotation.
        case earlier([String])
        /// Not in the vault: said only when every value in the vault was compared.
        case new
        /// Not found among the values compared, while some of the vault is not known yet.
        case unmatched
    }

    /// One project found: the nearest folder above a file where a project starts.
    public struct ProjectFound: Equatable, Sendable {
        public var path: String
        public var name: String
        public var marker: String?
    }

    /// Whether a search was compared with the vault, and how much of the vault was known.
    public enum Comparison: Equatable, Sendable {
        case compared(SealedMatcher.Coverage)
        case unavailable(SealedMatcher.Unavailable)
    }

    /// A search, kept by the agent's server for the proposal that follows.
    public struct Scan: Equatable, Sendable {
        public var scope: Scope
        public var files: Int
        public var roots: [String]
        public var skipped: [String: Int]
        /// Folders each rule left out: a built-in one, such as `tests`, or one of the person's.
        public var rules: [String: Int] = [:]
        /// Folders the engine did not finish before its budget ran out.
        public var unfinished: [String]
        public var found: [Found]
        public var projects: [ProjectFound] = []
        public var comparison = Comparison.unavailable(.nothingLearned)

        public func candidate(_ number: Int) -> Found? { found.first { $0.number == number } }
    }

    /// Reads the engine's report field by field. Whatever else it holds is never read, so nothing past these
    /// fields can reach an agent. Each key's hashes, read apart from the report, are compared with the vault's here
    /// and dropped: the scan keeps only what the comparison said.
    public static func read(
        _ data: Data, scope: Scope, hashes: [Int: [String]] = [:],
        matcher: Result<SealedMatcher, SealedMatcher.UnavailableError> = .failure(.init(.nothingLearned))
    ) throws -> Scan {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let list = object["candidates"] as? [[String: Any]]
        else { throw VaultError("the list of keys found could not be read") }
        let comparison: Comparison
        switch matcher {
        case .success(let matcher): comparison = .compared(matcher.coverage)
        case .failure(let why): comparison = .unavailable(why.reason)
        }
        let found: [Found] = list.compactMap { row in
            guard let number = row["id"] as? Int, let kind = row["class"] as? String else { return nil }
            let origins: [Origin] = (row["origins"] as? [[String: Any]] ?? []).compactMap { origin in
                guard let path = origin["path"] as? String else { return nil }
                let parts = (origin["parts"] as? [[String: Any]] ?? []).map { part in
                    Part(name: part["name"] as? String, line: part["line"] as? Int ?? 0, whole: part["whole"] as? Bool ?? false)
                }
                let project = origin["project"] as? String ?? URL(fileURLWithPath: path).deletingLastPathComponent().path
                return Origin(path: path, parts: parts, project: project)
            }
            guard !origins.isEmpty else { return nil }
            var sealed: Sealed?
            if case .success(let matcher) = matcher, kind == "key" || kind == "login", let mine = hashes[number] {
                if let hit = matcher.match(mine) {
                    sealed = hit.earlier ? .earlier(hit.ids) : .now(hit.ids)
                } else {
                    sealed = matcher.coverage.complete ? .new : .unmatched
                }
            }
            return Found(
                number: number, kind: kind, why: row["why"] as? String, provider: row["provider"] as? String,
                evidence: row["evidence"] as? String, guessed: row["guessed"] as? [String] ?? [], origins: origins,
                duplicate: row["duplicate"] as? Bool ?? false, fromProject: row["from_project"] as? Bool ?? false, sealed: sealed)
        }
        let skippedObject = object["skipped"] as? [String: Any] ?? [:]
        let skipped = skippedObject.compactMapValues { $0 as? Int }.filter { $0.value > 0 }
        let rules = (skippedObject["rules"] as? [String: Any] ?? [:]).compactMapValues { $0 as? Int }.filter { $0.value > 0 }
        let projects: [ProjectFound] = (object["projects"] as? [[String: Any]] ?? []).compactMap { row in
            guard let path = row["path"] as? String else { return nil }
            return ProjectFound(path: path, name: row["name"] as? String ?? URL(fileURLWithPath: path).lastPathComponent, marker: row["marker"] as? String)
        }
        return Scan(
            scope: scope, files: object["files"] as? Int ?? 0, roots: object["roots"] as? [String] ?? [], skipped: skipped,
            rules: rules, unfinished: object["unfinished"] as? [String] ?? [], found: found, projects: projects,
            comparison: comparison)
    }

    /// A path with the home folder written as `~`.
    public static func short(_ path: String, home: String = NSHomeDirectory()) -> String {
        path == home ? "~" : path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }

    /// A path an agent gave back, as written in a search: full, `~/…`, or under the folder the summary named.
    static func expand(_ text: String, under: String?, home: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed == "~" { return home }
        if trimmed.hasPrefix("~/") { return home + trimmed.dropFirst(1) }
        if trimmed.hasPrefix("/") { return trimmed }
        guard let under else { return trimmed }
        let base = under == "~" ? home : under.hasPrefix("~/") ? home + under.dropFirst(1) : under
        return base + "/" + trimmed
    }

    /// The folder every project is under, so each is named by what follows it.
    static func commonFolder(_ paths: [String]) -> String? {
        guard var common = paths.first.map({ $0.split(separator: "/", omittingEmptySubsequences: false).dropLast() }) else { return nil }
        for path in paths.dropFirst() {
            let parts = path.split(separator: "/", omittingEmptySubsequences: false)
            var same = 0
            while same < common.count, same < parts.count - 1, common[common.startIndex + same] == parts[same] { same += 1 }
            common = common.prefix(same)
        }
        let joined = common.joined(separator: "/")
        return joined.isEmpty ? nil : joined
    }

    /// What `find_keys` says of the comparison with the vault, so "new" is never said when it was not compared.
    static func sealedCheck(_ comparison: Comparison) -> String {
        switch comparison {
        case .compared(let coverage) where coverage.complete:
            return "compared: every key was compared with every value in the vault, by a keyed digest. new means the vault does not hold it."
        case .compared(let coverage):
            return "partly compared: Keyreeve knows \(coverage.known) of the \(coverage.total) values in the vault, so a key not marked sealed may still be in it. Ask the person to press Learn what the vault holds in Keyreeve, under Bring in."
        case .unavailable(.noVault):
            return "not compared: there is no vault yet."
        case .unavailable:
            return "not compared: Learn what the vault holds first. Keyreeve cannot tell which keys are already sealed until the person presses Learn what the vault holds in Keyreeve, under Bring in, with one fingerprint."
        }
    }

    struct Tally {
        var keys = 0, logins = 0, sealed = 0, earlier = 0, new = 0, duplicates = 0
        var providers: [String] = []

        mutating func add(_ found: Found) {
            if found.kind == "login" { logins += 1 } else { keys += 1 }
            switch found.sealed {
            case .now: sealed += 1
            case .earlier: earlier += 1
            case .new: new += 1
            case .unmatched, nil: break
            }
            if found.duplicate { duplicates += 1 }
            let named = found.provider ?? found.guessed.first.map { $0 + "?" }
            if let named, !providers.contains(named), !providers.contains(named.replacingOccurrences(of: "?", with: "")) {
                providers.append(named)
            }
        }

        /// The counts, with "new" only when every value in the vault was compared.
        func fields(_ comparison: Comparison) -> [String: Any] {
            var out: [String: Any] = ["keys": keys, "logins": logins, "duplicates": duplicates]
            if case .compared(let coverage) = comparison {
                out["already_sealed"] = sealed
                out["earlier_values"] = earlier
                if coverage.complete { out["new"] = new }
            }
            return out
        }
    }

    /// What `find_keys` answers. With no project, a summary by project: each one's path, counts and providers, and
    /// no key. With a project, its keys by number, compact. Numbers come from the one search and are the same in both,
    /// so `propose_bring` takes any of them. A key's identifier is shown only when it is offered to agents.
    public static func report(
        _ scan: Scan, offered: Set<String>, known: [String], project: String? = nil, offset: Int = 0,
        limit: Int = defaultLimit, home: String = NSHomeDirectory()
    ) throws -> String {
        let secrets = scan.found.filter(\.isSecret)
        let size = max(1, min(limit, maxLimit))
        // Each project with a key or a login in it, and its keys, a key counted in every project it is in.
        var byProject: [String: [Found]] = [:]
        for found in secrets {
            for path in Set(found.origins.map(\.project)) { byProject[path, default: []].append(found) }
        }
        let paths = byProject.keys.sorted()
        let under = commonFolder(paths)
        var out: [String: Any] = ["where": scan.scope.place.rawValue, "sealed_check": sealedCheck(scan.comparison)]
        if let project {
            let wanted = expand(project, under: under.map { short($0, home: home) }, home: home)
            guard let path = paths.first(where: { $0 == wanted || short($0, home: home) == project }) else {
                throw VaultError("no project \(project) has keys in your last find_keys. Use a path from its projects")
            }
            let members = byProject[path] ?? []
            let start = min(max(offset, 0), members.count)
            let end = min(start + size, members.count)
            var tally = Tally()
            members.forEach { tally.add($0) }
            out["project"] = short(path, home: home)
            out["counts"] = tally.fields(scan.comparison)
            out["keys"] = members[start..<end].map { row($0, in: path, offered: offered, comparison: scan.comparison) }
            out["offset"] = start
            if end < members.count { out["next_offset"] = end }
            out["next"] = "Values are never shown. To bring keys in, call propose_bring with their n, from this or any other list of the same search."
        } else {
            var all = Tally()
            secrets.forEach { all.add($0) }
            var counts = all.fields(scan.comparison)
            counts["projects"] = paths.count
            counts["other"] = scan.found.count - secrets.count
            if case .unavailable = scan.comparison { counts["not_compared"] = secrets.count }
            if case .compared(let coverage) = scan.comparison, !coverage.complete {
                counts["not_matched"] = secrets.filter { $0.sealed == .unmatched }.count
            }
            out["files"] = scan.files
            out["counts"] = counts
            let start = min(max(offset, 0), paths.count)
            let end = min(start + size, paths.count)
            if let under { out["under"] = short(under, home: home) }
            // One row per project, as a list in the order of columns, so a hundred projects stay a few kilobytes.
            out["columns"] = ["path", "keys", "logins", "duplicates", "sealed", "new", "providers"]
            var compared = false
            var complete = false
            if case .compared(let coverage) = scan.comparison {
                compared = true
                complete = coverage.complete
            }
            out["projects"] = paths[start..<end].map { path -> [Any] in
                var tally = Tally()
                (byProject[path] ?? []).forEach { tally.add($0) }
                let relative = under.map { path == $0 ? "." : String(path.dropFirst($0.count + 1)) } ?? short(path, home: home)
                return [
                    relative, tally.keys, tally.logins, tally.duplicates,
                    compared ? tally.sealed as Any : NSNull(), complete ? tally.new as Any : NSNull(),
                    tally.providers.prefix(5).joined(separator: " "),
                ]
            }
            out["offset"] = start
            if end < paths.count { out["next_offset"] = end }
            out["next"] =
                "Values are never shown. Each project is a row in the order of columns: its path under the folder in under (its name is the path's last part), its keys, logins and keys found twice, how many the vault already holds (sealed) and how many it does not (new); null where that was not compared. Call find_keys with project = a path from projects, as given or in full, to list its keys by n, then propose_bring with those numbers. Configuration, documents and public keys are counted in other, and never sealed."
            if !scan.rules.isEmpty { out["left_out"] = scan.rules }
            let skipped = scan.skipped.filter { $0.key != "rules" }
            if !skipped.isEmpty { out["skipped"] = skipped }
            if !scan.unfinished.isEmpty {
                out["unfinished"] = scan.unfinished.map { short($0, home: home) }
                out["budget"] =
                    "The search stopped before finishing the folders in unfinished, to keep it short. Call find_keys with where = folders and those folders to go on. Each search has its own numbers, so propose_bring takes those of your last one."
            }
            if start == 0 { out["known_providers"] = known.sorted() }
        }
        guard let data = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys, .withoutEscapingSlashes]) else {
            return "{}"
        }
        return String(decoding: data, as: UTF8.self)
    }

    /// One key in a project's list: its number, names, where in the project, provider or guess, and what the vault holds.
    static func row(_ found: Found, in project: String, offered: Set<String>, comparison: Comparison) -> [String: Any] {
        var row: [String: Any] = ["n": found.number, "names": found.origins[0].parts.map(\.shown).joined(separator: " + ")]
        if found.kind == "login" { row["class"] = "login" }
        let here = found.origins.filter { $0.project == project }
        row["at"] = here.prefix(5).map { origin -> String in
            let file = origin.path.hasPrefix(project + "/") ? String(origin.path.dropFirst(project.count + 1)) : origin.path
            return file + (origin.parts.first.map { $0.whole ? "" : ":\($0.line)" } ?? "")
        }
        if found.origins.count > here.count { row["elsewhere"] = found.origins.count - here.count }
        if let provider = found.provider {
            row["provider"] = provider
            row["by"] = found.evidence ?? "evidence"
        } else if !found.guessed.isEmpty {
            row["guess"] = found.guessed
        }
        switch found.sealed {
        case .now(let ids):
            let shown = ids.filter(offered.contains)
            if shown.isEmpty { row["sealed"] = true } else { row["sealed_as"] = shown }
        case .earlier(let ids):
            let shown = ids.filter(offered.contains)
            if shown.isEmpty { row["earlier_value"] = true } else { row["earlier_value_of"] = shown }
        case .new: row["new"] = true
        case .unmatched, nil: break
        }
        return row
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
        /// Folders the agent suggests never looking in again. Only the person adds them, in Bring in.
        public var ignore: [String]?

        public var sealCount: Int { items.filter(\.seal).count }
    }

    /// Checks an agent's choices against its latest search, and refuses the whole of it on any mistake, so
    /// a proposal is never half kept. Notes are what will not happen as asked.
    public static func check(
        seal: Any?, skip: Any?, ignore: Any? = nil, scan: Scan, known: Set<String>
    ) throws -> (proposal: Proposal, notes: [String]) {
        if seal != nil, !(seal is [[String: Any]]) { throw VaultError("seal is a list of objects, each with candidates") }
        if skip != nil, !(skip is [[String: Any]]) { throw VaultError("skip is a list of objects, each with candidate and reason") }
        if ignore != nil, !(ignore is [String]) { throw VaultError("ignore is a list of folders") }
        let toSeal = seal as? [[String: Any]] ?? []
        let toSkip = skip as? [[String: Any]] ?? []
        let toIgnore = (ignore as? [String] ?? []).map { $0.trimmingCharacters(in: .whitespaces) }
        guard toIgnore.count <= 20 else { throw VaultError("at most 20 folders to ignore at once") }
        if let bad = toIgnore.first(where: { !BringIgnore.isValid($0) }) {
            throw VaultError("\(bad) is not a folder to ignore: a full path, ~/path, or a folder's name with no /")
        }
        guard !toSeal.isEmpty || !toSkip.isEmpty || !toIgnore.isEmpty else { throw VaultError("give seal, skip, ignore, or some of them") }
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
                switch found.sealed {
                case .now: notes.append("\(number) is already in the vault")
                case .earlier: notes.append("\(number) is an earlier value of a key in the vault")
                default: break
                }
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
        var unique: [String] = []
        for folder in toIgnore where !unique.contains(folder) { unique.append(folder) }
        return (Proposal(scope: scan.scope, items: items, ignore: unique.isEmpty ? nil : unique), notes)
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

    /// Runs the engine, and has it hand each key's hashes over in a private file, read and removed at once.
    public static func runEngineHashed(
        binary: URL, arguments: [String], environment: [String: String]? = nil
    ) throws -> (report: Data, hashes: [Int: [String]]) {
        try EngineHashes.around { extra in try runEngine(binary: binary, arguments: arguments + extra, environment: environment) }
    }

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
