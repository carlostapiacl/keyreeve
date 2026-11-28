import Foundation

extension AgentBridge {
    static let tidyOff = "tidying is not set up in this Keyreeve"

    /// The keys an agent may name here: those offered to it, and with `all` (after the person's finger, once an
    /// hour) every key.
    func tidyVisible(_ context: KeyTidy.Context, all: Bool, reason: String?) throws -> [KeyIndex.Key] {
        // Behind the same switch as sorting files: tidying shows folders and hosts that keys were used from and to.
        guard inventory() != nil else { throw VaultError(Self.sortingOff) }
        if all { try openEveryName(reason: reason) }
        let keys = all ? context.index.all : context.index.keys
        return keys.filter { !$0.more.archived }
    }

    /// Every key, what it lacks and how it is used, so an agent can propose a tidier list.
    func reviewKeys(_ arguments: [String: Any]) throws -> String {
        guard let context = tidyContext?() ?? nil else { throw VaultError(Self.tidyOff) }
        let all = arguments["all"] as? Bool == true
        let visible = try tidyVisible(context, all: all, reason: arguments["reason"] as? String)
        let usage = KeyTidy.usage(context.entries, index: context.index)
        let twins = KeyTidy.twins(context.index, digests: context.digests)
        // Projects and their short starts from the keys this agent may see, so a key not offered says nothing.
        var scope = context.index
        if !all { scope.unoffered = [] }
        let projects = KeyTidy.knownProjects(scope)
        let names = Set(visible.map(\.id))
        let since = context.entries.map(\.at).min()
        let onlyGaps = (arguments["only"] as? String ?? "gaps") != "all"
        let matching = (arguments["matching"] as? String)?.lowercased()
        var rows: [String] = []
        for key in visible.sorted(by: { $0.id < $1.id }) {
            if let matching, !([key.id, key.provider, key.project, key.description].compactMap { $0 }
                .contains { $0.lowercased().contains(matching) }) { continue }
            // A twin the agent cannot see is said as "another key", not by name.
            let seen = (twins[key.id] ?? []).map { names.contains($0) ? $0 : "a key not offered to you" }
            let gaps = KeyTidy.gaps(key, use: usage[key.id], twins: seen, projects: projects, logSince: since, now: now())
            if onlyGaps && gaps.isEmpty { continue }
            rows.append(KeyTidy.line(key, use: usage[key.id], gaps: gaps))
        }
        let offset = max(arguments["offset"] as? Int ?? 0, 0)
        let limit = min(max(arguments["limit"] as? Int ?? 60, 1), 120)
        let page = rows.dropFirst(offset).prefix(limit)
        log("listed", "every key", "review: \(page.count) of \(rows.count)", arguments["reason"] as? String)
        let prefixes = KeyTidy.projectPrefixes(scope)
        let named = projects.sorted().map { project in
            prefixes[project].map { "\(project) (or " + $0.sorted().map { $0 + "-" }.joined(separator: ", ") + ")" } ?? project
        }
        var out = [KeyTidy.guide, "", "Projects: " + named.joined(separator: ", "), ""]
        out.append("\(rows.count) keys\(onlyGaps ? " with something to fix" : ""), showing \(offset + 1)–\(offset + page.count):")
        out.append(contentsOf: page)
        if offset + page.count < rows.count { out.append("More: review_keys with offset \(offset + page.count).") }
        if !all { out.append("Keys not offered to you are left out: review_keys with all and a reason asks the person to show them.") }
        out.append("Then propose_tidy with the changes. The person approves them in Keyreeve.")
        return out.joined(separator: "\n")
    }

    /// Leaves changes by identifier for the person, checked against the convention first.
    func proposeTidy(_ arguments: [String: Any]) throws -> String {
        guard let context = tidyContext?() ?? nil, let saveTidy else { throw VaultError(Self.tidyOff) }
        guard let reason = arguments["reason"] as? String, !reason.isEmpty else { throw VaultError("this needs reason and changes") }
        let all = arguments["all"] as? Bool == true
        let visible = Set(try tidyVisible(context, all: all, reason: reason).map(\.id))
        let providers = Set(offered()).union((context.index.all).compactMap(\.provider))
        let usage = KeyTidy.usage(context.entries, index: context.index)
        let checked = KeyTidy.check(
            arguments["changes"], index: context.index, providers: providers, visible: visible, usage: usage,
            logSince: context.entries.map(\.at).min(), now: now())
        let refused = checked.refused.isEmpty ? "" : " Left out: " + checked.refused.prefix(40).joined(separator: "; ") + "."
        guard !checked.accepted.isEmpty else { throw VaultError("nothing to propose." + refused) }
        // One proposal at a time from each agent, so the person is not asked twice about the same keys.
        let requests = requests()
        let waiting = requests.filter { $0.kind == KeyTidy.requestKind && $0.agent == agent }
        if let last = waiting.last, !requests.contains(where: { $0.id == last.id && $0.event != .asked }) {
            return "Still waiting: the person has not answered your last tidy proposal. Call review_keys later to see what changed."
        }
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: now(), event: .asked, agent: agent, provider: "keyreeve",
            reason: reason, key: nil, kind: KeyTidy.requestKind)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try saveTidy(entry.id, try encoder.encode(checked.accepted))
        try addRequest(entry)
        log("requested", "\(checked.accepted.count) keys", "tidy", reason)
        switch announce(entry) {
        case .deny:
            try addRequest(AccessRequests.Entry(
                id: entry.id, at: now(), event: .declined, agent: agent, provider: "keyreeve", kind: KeyTidy.requestKind))
            throw VaultError("the person said no to these changes")
        case .open, .later:
            return "\(checked.accepted.count) changes wait in Keyreeve for the person. Renamed keys keep their old id working."
                + refused
        }
    }
}
