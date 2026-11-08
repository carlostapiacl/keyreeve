import Foundation

/// The last check of each file, from the app's history of checks: what a provider said of the key, never the key.
public enum CheckHistory {
    public struct Last: Equatable, Sendable {
        public let result: String
        public let at: Date
    }

    public static func fileName() -> String { "history.jsonl" }

    /// The latest check of each file. With several providers checked at the same moment, a pass from any counts,
    /// as the app's list counts it: a check against the wrong provider says nothing about the key.
    public static func latest(in url: URL) -> [String: Last] {
        guard let data = try? Data(contentsOf: url) else { return [:] }
        var found: [String: Last] = [:]
        for line in data.split(separator: 10) {
            guard let row = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                let file = row["file"] as? String, let result = row["result"] as? String, let seconds = row["at"] as? Double
            else { continue }
            let at = Date(timeIntervalSince1970: seconds)
            if let known = found[file], known.at > at || (known.at == at && known.result == "works") { continue }
            found[file] = Last(result: result, at: at)
        }
        return found
    }

    /// What an agent should know before using a key: nothing for one that works or was never checked, and the
    /// day and result for one a provider turned down, so it does not try a dead key blind.
    public static func warning(_ last: Last?) -> String? {
        guard let last, last.result != "works", last.result != "no_result" else { return nil }
        let day = ISO8601DateFormatter.string(from: last.at, timeZone: .gmt, formatOptions: [.withFullDate])
        return "last check \(last.result) on \(day): it may not work"
    }
}
