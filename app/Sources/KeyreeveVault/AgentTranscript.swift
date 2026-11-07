import Foundation

/// What agents ran with a key and what came back, for the person to read. The key and its stand-in
/// are taken out before a line is written. It is a record to look at, and the usage log is the one
/// that holds together.
public struct AgentTranscript: Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var at: Date
        public var agent: String
        public var key: String
        public var command: String
        public var reason: String
        public var exit: Int32
        public var output: String
        public var milliseconds: Int

        public init(
            at: Date, agent: String, key: String, command: String, reason: String, exit: Int32, output: String, milliseconds: Int
        ) {
            self.at = at
            self.agent = agent
            self.key = key
            self.command = String(command.prefix(Self.commandLimit))
            self.reason = String(reason.prefix(200))
            self.exit = exit
            self.output = String(output.prefix(Self.outputLimit))
            self.milliseconds = milliseconds
        }

        public static let commandLimit = 1000
        public static let outputLimit = 2000
    }

    public static let fileName = "agent-runs.jsonl"
    /// Past this size, only the newest lines are kept.
    static let sizeLimit = 512 * 1024
    static let keptLines = 300

    public let url: URL
    public init(url: URL) { self.url = url }

    /// One line, appended. A failure stops nothing: this is for reading, not for proof.
    public func append(_ entry: Entry) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let line = try? encoder.encode(entry) else { return }
        let descriptor = open(url.path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { return }
        let size = (line + Data("\n".utf8)).withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
        var info = stat()
        let total = fstat(descriptor, &info) == 0 ? Int(info.st_size) : 0
        close(descriptor)
        if size > 0, total > Self.sizeLimit { trim() }
    }

    private func trim() {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        // Down to half the limit, so the next trim is far off and a write almost never pays for one.
        var budget = Self.sizeLimit / 2
        var lines: [Substring] = []
        for line in text.split(separator: "\n").reversed() {
            budget -= line.utf8.count + 1
            if budget < 0 || lines.count >= Self.keptLines { break }
            lines.append(line)
        }
        let kept = lines.reversed().joined(separator: "\n") + "\n"
        let temp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: temp.path, contents: Data(kept.utf8), attributes: [.posixPermissions: 0o600]) else { return }
        _ = rename(temp.path, url.path)
    }

    /// The newest first.
    public func entries(limit: Int = 100) -> [Entry] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return text.split(separator: "\n").suffix(limit).reversed().compactMap { try? decoder.decode(Entry.self, from: Data($0.utf8)) }
    }
}
