import Foundation

/// The usage log as a person reads it: a bot that polls every thirty seconds writes the same request hundreds of
/// times, and those become one row with a count. Only what the log shows is grouped; `audit.jsonl` keeps every line,
/// since each carries the hash of the one before.
public enum LogGroups {
    public struct Group: Equatable, Sendable, Identifiable {
        /// The newest line of the group, which the row shows.
        public var entry: AuditLog.Entry
        public var count: Int
        /// When the oldest line of the group happened.
        public var since: Date
        public var id: String { entry.hash }
    }

    /// Lines that repeat on their own. A decision, a refusal or an end is always a row of its own.
    public static let repeating: Set<String> = ["request", "used", "signed", "checked"]

    /// What makes two lines the same for a reader: what happened, to which key, by whom, and where, without a query.
    static func signature(_ entry: AuditLog.Entry) -> [String] {
        let detail = entry.detail.map { text in
            text.split(separator: " ").map { word in word.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "" }
                .joined(separator: " ")
        }
        return [
            entry.event, entry.key, detail ?? "", entry.declared?.agent ?? "", entry.declared?.reason ?? "",
            entry.observed.map { URL(fileURLWithPath: $0.program).lastPathComponent } ?? "",
        ]
    }

    /// Groups lines given newest first. A line joins a group among the last few rows, so a use and its request that
    /// alternate still fold into two rows, and anything else in between starts new ones.
    public static func collapse(_ entries: [AuditLog.Entry], lookBack: Int = 4) -> [Group] {
        var groups: [Group] = []
        var signatures: [[String]] = []
        for entry in entries {
            if repeating.contains(entry.event) {
                let signature = signature(entry)
                let start = max(0, groups.count - lookBack)
                if let at = (start..<groups.count).last(where: { signatures[$0] == signature }) {
                    groups[at].count += 1
                    groups[at].since = min(groups[at].since, entry.at)
                    continue
                }
                signatures.append(signature)
            } else {
                signatures.append([])
            }
            groups.append(Group(entry: entry, count: 1, since: entry.at))
        }
        return groups
    }
}
