import Foundation

/// How keys were used, read from the usage log: counts, days, agents, folders and hosts, never a value.
extension KeyTidy {

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
        for key in index.all where name[key.source] == nil { name[key.source] = key.id }
        for key in index.all {
            for old in key.more.formerly ?? [] { name[old] = key.id }
        }
        for key in index.all { name[key.id] = key.id }
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
}
