import Foundation

/// The rules a proposal is checked against, and what the rules learn from the list as it is.
extension KeyTidy {

    /// The changes that follow the rules, and why each other one was left out. `providers` are the provider ids
    /// keyreeve knows; `visible` the keys this agent may name; `logSince` the oldest moment of the usage log read.
    public static func check(
        _ raw: Any?, index: KeyIndex, providers: Set<String>, visible: Set<String>, usage: [String: Use],
        logSince: Date? = nil, now: Date = Date()
    ) -> (accepted: [Change], refused: [String]) {
        guard let rows = raw as? [[String: Any]], !rows.isEmpty else { return ([], ["changes is a list of objects, one per key"]) }
        guard rows.count <= maxChanges else { return ([], ["at most \(maxChanges) changes at once, so the person can read them"]) }
        var accepted: [Change] = []
        var refused: [String] = []
        var seen = Set<String>()
        var newIDs = Set<String>()
        let all = index.all
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
                                     taken: newIDs, use: usage[change.key], logSince: logSince, now: now) {
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
        taken: Set<String>, use: Use?, logSince: Date?, now: Date
    ) -> String? {
        let why = change.why.trimmingCharacters(in: .whitespacesAndNewlines)
        guard why.count >= 8 else { return "say in why how you know" }
        for text in [change.description, change.account, change.why] .compactMap({ $0 }) where looksLikeValue(text) {
            return "that text holds something shaped like a key or a password; write what it is, never the value"
        }
        if let project = change.project, !KeyIndex.isValid(id: project) {
            return "a project is lower case with dashes, like shop or acme-labs"
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
        if change.archive == true, let alive = stillAlive(use, logSince: logSince, now: now) { return alive }
        return nil
    }

    /// Why a key is not archived for being unused: it was used within `recentDays`, or the log read does not reach
    /// that far back, and no use seen in a short log is not the same as no use. Nil when it may be archived.
    static func stillAlive(_ use: Use?, logSince: Date?, now: Date) -> String? {
        if let last = use?.last {
            guard now.timeIntervalSince(last) < recent else { return nil }
            let who = use?.agents.sorted().prefix(3).joined(separator: ", ") ?? ""
            return "it was used on \(day(last))\(who.isEmpty ? "" : " by \(who)"): it is not dead, so it is not archived"
        }
        guard let logSince, now.timeIntervalSince(logSince) >= recent else {
            let start = logSince.map { "starts on \(day($0))" } ?? "is empty"
            return "the usage log read here \(start), under \(recentDays) days: unused cannot be told, so it is not archived"
        }
        return nil
    }

    /// A long run of letters and digits with no space, or a URL carrying a token: what a value looks like.
    static func looksLikeValue(_ text: String) -> Bool {
        // A long run is a value unless it reads as a name: a path or an environment variable, as a why cites them.
        let runs = try! NSRegularExpression(pattern: #"[A-Za-z0-9_\-+/=]{28,}"#)
        for match in runs.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            if let range = Range(match.range, in: text), !isName(String(text[range])) { return true }
        }
        if text.range(of: #"(?i)(token|key|secret|password|pass)=[^&\s]{6,}"#, options: .regularExpression) != nil { return true }
        if text.range(of: #"://[^/\s:@]+:[^/\s@]+@"#, options: .regularExpression) != nil { return true }
        return false
    }

    /// A path such as mesa-de-ventas/cmd/mesa/ficha or a variable such as GOOGLE_APPLICATION_CREDENTIALS: one case only,
    /// and words joined by dashes, underscores or slashes, none long enough to be a value on its own.
    static func isName(_ run: String) -> Bool {
        let oneCase = run.range(of: #"^[a-z0-9_/\-]+$"#, options: .regularExpression) != nil
            || run.range(of: #"^[A-Z0-9_/\-]+$"#, options: .regularExpression) != nil
        return oneCase && run.split(whereSeparator: { "-_/".contains($0) }).allSatisfy { $0.count < 20 }
    }

    /// The short starts the person already uses for a project's keys, such as acme- for acme-labs: a start
    /// that at least three of its keys share, and that is not a provider.
    public static func projectPrefixes(_ index: KeyIndex) -> [String: Set<String>] {
        let all = index.all.filter { !$0.more.archived }
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
        let all = index.all.filter { !$0.more.archived }
        var found = Set(all.compactMap(\.project))
        var counts: [String: Int] = [:]
        for tag in all.flatMap({ $0.more.tags ?? [] })
        where !tag.contains(":") && KeyIndex.isValid(id: tag) && !notProjects.contains(tag) { counts[tag, default: 0] += 1 }
        for (tag, count) in counts where count >= 5 { found.insert(tag) }
        return found
    }
}
