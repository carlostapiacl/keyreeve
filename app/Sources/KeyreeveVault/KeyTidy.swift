import Foundation

/// Agents tidy the list of keys; the person approves.
///
/// An agent reads each key's gaps and how it is used (`review`), proposes changes by identifier (`check`), and the
/// person applies the ones they want (`apply`). The rules are checked here, not left to the agent's judgment: a
/// change that breaks one comes back refused with the reason, so the agent learns the convention by using it.
public enum KeyTidy {
    /// What an agent may change of one key. Nil leaves a field as it is.
    public struct Change: Codable, Equatable, Sendable {
        public var key: String
        public var id: String?
        public var description: String?
        public var project: String?
        public var provider: String?
        public var variable: String?
        public var account: String?
        public var field: String?
        /// Tags to add. Tags are never taken away here.
        public var tags: [String]?
        public var archive: Bool?
        /// How the agent knows: what it read, where. Shown to the person beside the change.
        public var why: String

        public init(
            key: String, id: String? = nil, description: String? = nil, project: String? = nil, provider: String? = nil,
            variable: String? = nil, account: String? = nil, field: String? = nil, tags: [String]? = nil,
            archive: Bool? = nil, why: String
        ) {
            self.key = key
            self.id = id
            self.description = description
            self.project = project
            self.provider = provider
            self.variable = variable
            self.account = account
            self.field = field
            self.tags = tags
            self.archive = archive
            self.why = why
        }

        /// What it does, in one line, for the person and for the log.
        public func summary(from before: KeyIndex.Key?) -> String {
            var parts: [String] = []
            func show(_ name: String, _ old: String?, _ new: String?) {
                guard let new, new != old else { return }
                parts.append("\(name): \(old ?? "—") → \(new)")
            }
            show("id", before?.id ?? key, id)
            show("description", before?.description, description)
            show("project", before?.project, project)
            show("provider", before?.provider, provider)
            show("variable", before?.variable, variable)
            show("account", before?.account, account)
            show("field", before?.field, field)
            let added = (tags ?? []).filter { !(before?.more.tags ?? []).contains($0) }
            if !added.isEmpty { parts.append("tags + " + added.joined(separator: ", ")) }
            if archive == true { parts.append("archive") }
            return parts.isEmpty ? "no change" : parts.joined(separator: "; ")
        }
    }

    /// How a key was used lately, from the usage log: never a value.
    public struct Use: Equatable, Sendable {
        public var count = 0
        public var last: Date?
        public var agents: Set<String> = []
        public var folders: Set<String> = []
        public var hosts: Set<String> = []
        public init() {}
    }

    /// At most this many changes in one proposal, so the person can read them all.
    public static let maxChanges = 60
    /// A key used within these days is not dead: it is not archived from here.
    public static let recentDays = 30

    /// The convention, as the agent reads it in the tool's description and at the top of a review.
    public static let guide = """
        How keys are named and sorted (the tool refuses what breaks it, and says why):
        - id: lower case, digits and dashes, at most 40. A provider's key starts with the provider: resend-lh, \
        meta-hz, coolify-v2-deploy. A secret of the person's own software starts with its project: \
        restoiq-erp-jwt-secret, mesa-token. Then the account or project, then what it is for, only if needed to tell \
        two apart.
        - Renaming keeps the old id working (scripts and permissions that name it go on), so rename only to follow \
        this convention, never to taste.
        - project: one of the projects review_keys lists. A new one is allowed but the person sees it marked new.
        - description: at most 80 characters on what it is and where it is used. Never a value, a URL with a token, \
        or a password.
        - variable: the environment variable its programs read, UPPER_CASE.
        - archive: only a key that is dead (its check failed) or a copy of another (same value), and never one used in \
        the last 30 days.
        - why: say how you know, such as "read /opt/app/.env on VPS1: names RESEND_API_KEY". Leave a key out rather \
        than guess.
        """

    // MARK: Checking a proposal

    /// The changes that follow the rules, and why each other one was left out. `providers` are the provider ids
    /// keyreeve knows; `visible` the keys this agent may name.
    public static func check(
        _ raw: Any?, index: KeyIndex, providers: Set<String>, visible: Set<String>, usage: [String: Use],
        now: Date = Date()
    ) -> (accepted: [Change], refused: [String]) {
        guard let rows = raw as? [[String: Any]], !rows.isEmpty else { return ([], ["changes is a list of objects, one per key"]) }
        guard rows.count <= maxChanges else { return ([], ["at most \(maxChanges) changes at once, so the person can read them"]) }
        var accepted: [Change] = []
        var refused: [String] = []
        var seen = Set<String>()
        var newIDs = Set<String>()
        let all = index.keys + index.unoffered
        let prefixes = projectPrefixes(index)
        for row in rows {
            guard let data = try? JSONSerialization.data(withJSONObject: row),
                var change = try? JSONDecoder().decode(Change.self, from: data)
            else {
                refused.append("\(row["key"] as? String ?? "?"): key and why are needed; the rest are text, tags a list, archive true")
                continue
            }
            let asked = change.key
            change.key = index.current(asked)
            guard visible.contains(change.key), let before = all.first(where: { $0.id == change.key }) else {
                refused.append("\(asked): no key you can see is called that")
                continue
            }
            guard seen.insert(change.key).inserted else {
                refused.append("\(asked): one change per key; put everything for it in one")
                continue
            }
            if let problem = problem(change, before: before, all: all, prefixes: prefixes, providers: providers,
                                     taken: newIDs, use: usage[change.key], now: now) {
                refused.append("\(asked)\(change.id.map { " → \($0)" } ?? ""): \(problem)")
                continue
            }
            guard change.summary(from: before) != "no change" else {
                refused.append("\(asked): nothing would change")
                continue
            }
            if let id = change.id { newIDs.insert(id) }
            accepted.append(change)
        }
        return (accepted, refused)
    }

    static func problem(
        _ change: Change, before: KeyIndex.Key, all: [KeyIndex.Key], prefixes: [String: Set<String>], providers: Set<String>,
        taken: Set<String>, use: Use?, now: Date
    ) -> String? {
        let why = change.why.trimmingCharacters(in: .whitespacesAndNewlines)
        guard why.count >= 8 else { return "say in why how you know" }
        for text in [change.description, change.account, change.why] .compactMap({ $0 }) where looksLikeValue(text) {
            return "that text holds something shaped like a key or a password; write what it is, never the value"
        }
        if let project = change.project, !KeyIndex.isValid(id: project) {
            return "a project is lower case with dashes, like restoiq or liquidity-hunters"
        }
        let provider = change.provider ?? before.provider
        if let new = change.provider, !providers.contains(new) {
            return "\(new) is not a provider keyreeve knows; leave provider out or use one of its recipes"
        }
        if let id = change.id {
            guard KeyIndex.isValid(id: id), id.count <= 40 else { return "an id is lower case, digits and dashes, at most 40" }
            if id != before.id, all.contains(where: { ($0.id == id || $0.more.formerly?.contains(id) == true) && $0.id != before.id })
                || taken.contains(id) {
                return "\(id) is already taken"
            }
            let project = change.project ?? before.project
            let short = project.flatMap { prefixes[$0] } ?? []
            let allowed = ([provider, project].compactMap { $0 } + short.sorted())
            let starts = allowed.contains { id == $0 || id.hasPrefix($0 + "-") }
            if !starts {
                return allowed.isEmpty
                    ? "set provider or project too, and start the id with it"
                    : "start it with " + allowed.map { $0 + "-" }.joined(separator: " or ")
            }
        }
        if let variable = change.variable,
            !(variable.first.map { $0 == "_" || ($0.isASCII && $0.isUppercase) } ?? false)
                || !variable.allSatisfy({ $0 == "_" || ($0.isASCII && ($0.isUppercase || $0.isNumber)) }) || variable.count > 64 {
            return "a variable is UPPER_CASE, like RESEND_API_KEY"
        }
        if let description = change.description, description.count > 80 { return "a description is at most 80 characters" }
        if let tags = change.tags, tags.contains(where: { $0.isEmpty || $0.count > 40 || $0.contains(" ") }) {
            return "a tag is one word or kind:value, at most 40"
        }
        if change.archive == true, let last = use?.last, now.timeIntervalSince(last) < Double(recentDays) * 86400 {
            let who = use?.agents.sorted().prefix(3).joined(separator: ", ") ?? ""
            return "it was used on \(day(last))\(who.isEmpty ? "" : " by \(who)"): it is not dead, so it is not archived"
        }
        return nil
    }

    /// A long run of letters and digits with no space, or a URL carrying a token: what a value looks like.
    static func looksLikeValue(_ text: String) -> Bool {
        if text.range(of: #"[A-Za-z0-9_\-+/=]{28,}"#, options: .regularExpression) != nil { return true }
        if text.range(of: #"(?i)(token|key|secret|password|pass)=[^&\s]{6,}"#, options: .regularExpression) != nil { return true }
        if text.range(of: #"://[^/\s:@]+:[^/\s@]+@"#, options: .regularExpression) != nil { return true }
        return false
    }

    /// The short starts the person already uses for a project's keys, such as lh- for liquidity-hunters: a start
    /// that at least three of its keys share, and that is not a provider.
    public static func projectPrefixes(_ index: KeyIndex) -> [String: Set<String>] {
        let all = (index.keys + index.unoffered).filter { !$0.more.archived }
        let projects = knownProjects(index)
        let providers = Set(all.compactMap(\.provider))
        // Each start goes to the one project most of its keys belong to, and only if most of them do.
        var byStart: [String: [String: Int]] = [:]
        var total: [String: Int] = [:]
        for key in all {
            guard let start = key.id.split(separator: "-").first.map(String.init), !projects.contains(start),
                !providers.contains(start) else { continue }
            total[start, default: 0] += 1
            let owner = key.project ?? (key.more.tags ?? []).first { projects.contains($0) }
            if let owner { byStart[start, default: [:]][owner, default: 0] += 1 }
        }
        var out: [String: Set<String>] = [:]
        for (start, owners) in byStart {
            guard let best = owners.max(by: { $0.value < $1.value }), best.value >= 3,
                best.value * 2 > (total[start] ?? 0) else { continue }
            out[best.key, default: []].insert(start)
        }
        return out
    }

    /// Tags that say what a key is or where it runs, not whose it is.
    static let notProjects: Set<String> = [
        "untestable", "internal", "confirm", "public", "vps1", "vps2", "vps3", "kali", "kuma", "produccion", "production",
        "staging", "test", "prueba", "pruebas", "lab", "added", "personal",
    ]

    /// The projects keys already name, and project-like tags that several keys share.
    public static func knownProjects(_ index: KeyIndex) -> Set<String> {
        let all = (index.keys + index.unoffered).filter { !$0.more.archived }
        var found = Set(all.compactMap(\.project))
        var counts: [String: Int] = [:]
        for tag in all.flatMap({ $0.more.tags ?? [] })
        where !tag.contains(":") && KeyIndex.isValid(id: tag) && !notProjects.contains(tag) { counts[tag, default: 0] += 1 }
        for (tag, count) in counts where count >= 5 { found.insert(tag) }
        return found
    }

    // MARK: Applying

    /// Applies the changes the person kept to the list. A renamed key keeps its old id in `formerly`. Returns what
    /// changed, one line per key, and each rename, for the permissions and places to follow.
    @discardableResult
    public static func apply(_ changes: [Change], to index: inout KeyIndex) -> (done: [String], renamed: [(String, String)]) {
        var done: [String] = []
        var renamed: [(String, String)] = []
        for change in changes {
            let id = index.current(change.key)
            let offered = index.keys.contains { $0.id == id }
            guard var key = (offered ? index.keys : index.unoffered).first(where: { $0.id == id }) else { continue }
            let before = key
            if let new = change.id, new != key.id, !index.isTaken(new) {
                var formerly = key.more.formerly ?? []
                if !formerly.contains(key.id) { formerly.append(key.id) }
                key.more.formerly = formerly
                renamed.append((key.id, new))
                key.id = new
            }
            if let value = change.description { key.description = value }
            if let value = change.project { key.project = value }
            if let value = change.provider { key.provider = value }
            if let value = change.variable { key.variable = value }
            if let value = change.account { key.account = value }
            if let value = change.field { key.field = value }
            if let tags = change.tags {
                var kept = key.more.tags ?? []
                for tag in tags where !kept.contains(tag) { kept.append(tag) }
                key.more.tags = kept
            }
            if change.archive == true { key.more.archived = true }
            guard key != before else { continue }
            if offered {
                index.keys.removeAll { $0.id == before.id }
                index.keys.insert(key, at: index.keys.firstIndex { $0.id > key.id } ?? index.keys.endIndex)
            } else if let at = index.unoffered.firstIndex(where: { $0.id == before.id }) {
                index.unoffered[at] = key
            }
            done.append("\(before.id): \(change.summary(from: before))")
        }
        return (done, renamed)
    }

    /// Applies the changes in the person's files: keys.toml, then the permissions and places of renamed keys, each
    /// under its own lock, after a copy of keys.toml and agents.toml beside them.
    @discardableResult
    public static func apply(_ changes: [Change], home: URL, stamp: String) throws -> [String] {
        let keys = home.appendingPathComponent(KeyIndex.fileName)
        let agents = home.appendingPathComponent(AgentPolicy.fileName)
        for file in [keys, agents] where FileManager.default.fileExists(atPath: file.path) {
            let copy = home.appendingPathComponent("\(file.lastPathComponent).antes-tidy-\(stamp)")
            try? FileManager.default.removeItem(at: copy)
            try FileManager.default.copyItem(at: file, to: copy)
            chmod(copy.path, 0o600)
        }
        let result = try KeyIndex.change(at: keys) { index in apply(changes, to: &index) }.result
        if !result.renamed.isEmpty {
            if FileManager.default.fileExists(atPath: agents.path) {
                _ = try AgentPolicy.update(at: agents) { policy in for (old, new) in result.renamed { policy.rename(old, to: new) } }
            }
            let places = PlaceBook.file(home: home)
            if FileManager.default.fileExists(atPath: places.path) {
                try PlaceBook.update(at: places) { book in
                    for (old, new) in result.renamed {
                        for at in book.places.indices where book.places[at].key == old { book.places[at].key = new }
                    }
                }
            }
        }
        return result.done
    }

    // MARK: Reviewing

    /// The last lines of a usage log, read as they are, without walking its chain of hashes: for counting use, not
    /// for trusting the log. A line that does not read is skipped.
    public static func lastEntries(of url: URL, count: Int = 20000) -> [AuditLog.Entry] {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var lines: [Data] = []
        var end = data.endIndex
        var at = data.endIndex
        while at > data.startIndex, lines.count < count {
            at = data.index(before: at)
            if data[at] == 10 || at == data.startIndex {
                let start = data[at] == 10 ? data.index(after: at) : at
                if start < end { lines.append(data[start..<end]) }
                end = at
            }
        }
        return lines.reversed().compactMap { try? decoder.decode(AuditLog.Entry.self, from: $0) }
    }

    /// The usage log and the last part set aside, so a month of use is seen just after the log moves on to a new part.
    public static func recentEntries(home: URL, count: Int = 20000) -> [AuditLog.Entry] {
        let older = (try? FileManager.default.contentsOfDirectory(atPath: home.path))?
            .filter { $0.hasPrefix("audit-") && $0.hasSuffix(".jsonl") }.sorted().last
            .map { lastEntries(of: home.appendingPathComponent($0), count: count) } ?? []
        return older + lastEntries(of: home.appendingPathComponent("audit.jsonl"), count: count)
    }

    /// How each key was used, from the usage log, by the id it goes by now.
    public static func usage(_ entries: [AuditLog.Entry], index: KeyIndex) -> [String: Use] {
        // One table, built once: a log holds tens of thousands of lines.
        var name: [String: String] = [:]
        for key in index.keys + index.unoffered where name[key.source] == nil { name[key.source] = key.id }
        for key in index.keys + index.unoffered {
            for old in key.more.formerly ?? [] { name[old] = key.id }
        }
        for key in index.keys + index.unoffered { name[key.id] = key.id }
        var out: [String: Use] = [:]
        let counted: Set<String> = ["used", "granted", "request"]
        for entry in entries where counted.contains(entry.event) {
            let id = name[entry.key] ?? entry.key
            var use = out[id] ?? Use()
            if entry.event != "request" { use.count += 1 }
            if use.last.map({ entry.at > $0 }) ?? true { use.last = entry.at }
            if let agent = entry.declared?.agent, !agent.isEmpty { use.agents.insert(String(agent.split(separator: "/")[0])) }
            if let folder = entry.declared?.cwd, !folder.isEmpty { use.folders.insert(shortFolder(folder)) }
            if entry.event == "request", let host = host(in: entry.detail) { use.hosts.insert(host) }
            out[id] = use
        }
        return out
    }

    static func host(in detail: String?) -> String? {
        guard let detail else { return nil }
        let words = detail.split(separator: " ")
        guard words.count >= 2 else { return nil }
        let target = words[1]
        guard let host = target.split(separator: "/").first, host.contains("."), !host.contains("{") else { return nil }
        return String(host)
    }

    static let home = FileManager.default.homeDirectoryForCurrentUser.path

    static func shortFolder(_ path: String) -> String {
        if path.hasPrefix("/private/tmp/") || path.hasPrefix("/tmp/") || path.contains("/scratchpad") { return "a temporary folder" }
        let short = path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
        let parts = short.split(separator: "/")
        return parts.count > 4 ? "…/" + parts.suffix(3).joined(separator: "/") : short
    }

    /// What is missing or odd about a key, in short words.
    public static func gaps(
        _ key: KeyIndex.Key, use: Use?, twins: [String], projects: Set<String>, logSince: Date? = nil, now: Date = Date()
    ) -> [String] {
        var gaps: [String] = []
        if key.provider == nil && key.variable == nil { gaps.append("no provider or variable") }
        else if key.variable == nil && key.provider != nil { gaps.append("no variable") }
        if key.project == nil && !(key.more.tags ?? []).contains(where: projects.contains) { gaps.append("no project") }
        if (key.description ?? "").isEmpty { gaps.append("no description") }
        if let provider = key.provider, !(key.id == provider || key.id.hasPrefix(provider + "-")),
            !(key.project.map { key.id.hasPrefix($0 + "-") } ?? false) {
            gaps.append("id does not start with its provider or project")
        }
        if !twins.isEmpty { gaps.append("same value as " + twins.joined(separator: ", ")) }
        if use?.last == nil { gaps.append("not used" + (logSince.map { " since \(day($0))" } ?? "")) }
        else if let last = use?.last, now.timeIntervalSince(last) > 90 * 86400 { gaps.append("unused for 90 days") }
        return gaps
    }

    /// One line per key, for an agent: never a value or a digest.
    public static func line(_ key: KeyIndex.Key, use: Use?, gaps: [String]) -> String {
        var parts = [key.id]
        let about = [key.provider.map { "provider \($0)" }, key.project.map { "project \($0)" },
                     key.variable.map { "variable \($0)" }, key.account.map { "account \($0)" }].compactMap { $0 }
        if !about.isEmpty { parts.append(about.joined(separator: ", ")) }
        if let description = key.description, !description.isEmpty { parts.append("“\(description)”") }
        if let use, let last = use.last {
            var used = "used \(use.count)×, last \(day(last))"
            if !use.agents.isEmpty { used += " by " + use.agents.sorted().prefix(4).joined(separator: ", ") }
            if !use.folders.isEmpty { used += " in " + use.folders.sorted().prefix(3).joined(separator: ", ") }
            if !use.hosts.isEmpty { used += " → " + use.hosts.sorted().prefix(3).joined(separator: ", ") }
            parts.append(used)
        }
        if let formerly = key.more.formerly, !formerly.isEmpty { parts.append("formerly " + formerly.joined(separator: ", ")) }
        if !gaps.isEmpty { parts.append("needs: " + gaps.joined(separator: "; ")) }
        return parts.joined(separator: " · ")
    }

    static func day(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }

    /// Keys that hold the same value, by vault digest, comparing only the newest sealing of each file.
    public static func twins(_ index: KeyIndex, digests: ValueDigests) -> [String: [String]] {
        var byDigest: [String: [String]] = [:]
        for key in (index.keys + index.unoffered) where !key.more.archived {
            guard let sealings = digests.entries[key.source], let newest = sealings.keys.max(),
                let digest = sealings[newest]?[key.field ?? ""] ?? (key.field == nil ? sealings[newest]?.values.first : nil)
            else { continue }
            byDigest[digest, default: []].append(key.id)
        }
        var out: [String: [String]] = [:]
        for ids in byDigest.values where ids.count > 1 {
            for id in ids { out[id] = ids.filter { $0 != id } }
        }
        return out
    }
}

extension AgentPolicy {
    /// Moves every permission of a key to its new identifier.
    public mutating func rename(_ old: String, to new: String) {
        if let value = commands.removeValue(forKey: old) { commands[new] = value }
        if let value = levels.removeValue(forKey: old) { levels[new] = value }
        if let value = agents.removeValue(forKey: old) { agents[new] = value }
        if let value = hashes.removeValue(forKey: old) { hashes[new] = value }
        if let value = until.removeValue(forKey: old) { until[new] = value }
    }
}
