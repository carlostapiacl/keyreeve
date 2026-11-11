import Foundation

/// Every log keyreeve keeps, as one list in time order: who used which key, what agents ran, what was
/// asked and decided, and how each check went. Names, times and outcomes only, never a value, so it can
/// be read, exported and analysed freely.
public enum Timeline {
    public struct Row: Codable, Equatable, Sendable {
        public var at: Date
        /// Which log it came from: audit, agents, checks or terminal.
        public var source: String
        public var event: String
        public var key: String
        public var agent: String?
        public var program: String?
        public var detail: String?
        public var reason: String?

        public init(
            at: Date, source: String, event: String, key: String, agent: String? = nil, program: String? = nil,
            detail: String? = nil, reason: String? = nil
        ) {
            self.at = at
            self.source = source
            self.event = event
            self.key = key
            self.agent = agent
            self.program = program
            self.detail = detail
            self.reason = reason
        }
    }

    public static let columns = ["at", "source", "event", "key", "agent", "program", "detail", "reason"]

    /// Reads the logs in `home`. A file path is shown by its identifier when it has one.
    public static func read(home: URL, index: KeyIndex = KeyIndex(), since: Date? = nil) -> [Row] {
        let name = { (path: String) in index.keys(forSource: path).first?.id ?? path }
        var rows: [Row] = []
        let audit = (try? AuditLog(url: home.appendingPathComponent("audit.jsonl")).entries()) ?? []
        for entry in audit {
            rows.append(Row(
                at: entry.at, source: "audit", event: entry.event, key: name(entry.key),
                agent: entry.declared?.agent,
                program: (entry.observed?.program).map { URL(fileURLWithPath: $0).lastPathComponent } ?? entry.declared?.command,
                detail: entry.detail, reason: entry.declared?.reason))
        }
        let runs = AgentTranscript(url: home.appendingPathComponent(AgentTranscript.fileName)).entries(limit: .max)
        for run in runs {
            rows.append(Row(
                at: run.at, source: "agents", event: "ran", key: run.key, agent: run.agent,
                program: run.command.split(separator: " ").first.map(String.init),
                detail: "exit \(run.exit), \(run.milliseconds) ms", reason: run.reason))
        }
        for line in lines(home.appendingPathComponent("history.jsonl")) {
            guard let at = date(line["at"]), let file = line["file"] as? String else { continue }
            rows.append(Row(
                at: at, source: "checks", event: "checked", key: name(file), program: line["recipe"] as? String,
                detail: line["result"] as? String))
        }
        for line in lines(home.appendingPathComponent("usage.jsonl")) {
            guard let at = date(line["at"]), let key = line["name"] as? String else { continue }
            let event = line["event"] as? String ?? "used"
            rows.append(Row(at: at, source: "terminal", event: event, key: name(key), program: line["command"] as? String))
        }
        return rows.filter { row in since.map { row.at >= $0 } ?? true }.sorted { $0.at < $1.at }
    }

    /// `7d`, `24h` or `30m` back from now.
    public static func start(from text: String, now: Date = Date()) -> Date? {
        guard let unit = text.last, let number = Double(text.dropLast()), number > 0 else { return nil }
        let seconds: Double
        switch unit {
        case "d": seconds = number * 86400
        case "h": seconds = number * 3600
        case "m": seconds = number * 60
        default: return nil
        }
        return now.addingTimeInterval(-seconds)
    }

    public static func csv(_ rows: [Row]) -> String {
        let format = ISO8601DateFormatter()
        func cell(_ text: String?) -> String {
            guard var text, !text.isEmpty else { return "" }
            text = AgentRequest.oneLine(text)
            // A cell a spreadsheet would run as a formula is kept as text.
            if let first = text.first, "=+-@".contains(first) { text = "'" + text }
            return text.contains(where: { ",\"".contains($0) }) ? "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : text
        }
        var out = columns.joined(separator: ",") + "\n"
        for row in rows {
            out += [format.string(from: row.at), row.source, row.event, row.key, row.agent, row.program, row.detail, row.reason]
                .map(cell).joined(separator: ",") + "\n"
        }
        return out
    }

    public static func jsonl(_ rows: [Row]) -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return rows.compactMap { try? encoder.encode($0) }.map { String(decoding: $0, as: UTF8.self) + "\n" }.joined()
    }

    private static func lines(_ url: URL) -> [[String: Any]] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").compactMap {
            try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
        }
    }

    /// Seconds since 1970, as the older logs write it, or ISO 8601.
    private static func date(_ value: Any?) -> Date? {
        if let seconds = value as? NSNumber { return Date(timeIntervalSince1970: seconds.doubleValue) }
        guard let text = value as? String else { return nil }
        let precise = ISO8601DateFormatter()
        precise.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return ISO8601DateFormatter().date(from: text) ?? precise.date(from: text)
    }
}
