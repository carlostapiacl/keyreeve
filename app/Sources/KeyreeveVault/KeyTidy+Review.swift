import Foundation

/// What an agent reads of each key when it reviews the list.
extension KeyTidy {
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
        for key in index.all where !key.more.archived {
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
