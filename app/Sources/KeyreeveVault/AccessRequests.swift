import Foundation

/// Agents asking for a key that is not in the vault yet. The agent server writes the request, the app
/// shows it, and the person saves a file and allows it in one step. One line per event, never a value.
public enum AccessRequests {
    public static let fileName = "access-requests.jsonl"
    /// Providers the app can save a key for, written by the app, which knows the keys folder. Agents see
    /// these names and nothing about the files.
    public static let offeredFileName = "offered.json"

    public struct Entry: Codable, Equatable, Sendable {
        public enum Event: String, Codable, Sendable {
            case asked, allowed, declined
        }

        public var id: String
        public var at: Date
        public var event: Event
        public var agent: String
        public var provider: String
        /// The agent's words, cleaned and cut. Only on `asked`.
        public var reason: String?
        /// For how long the agent suggests, or the person chose. Missing is always.
        public var hours: Int?
        /// The identifier the key was saved as. Only on `allowed`.
        public var key: String?
        /// The account, organization or project the agent says the key should belong to, if it knows.
        public var account: String?
        /// `rotate` for an agent asking to rotate a key it names in `key`. Missing is a request for access.
        public var kind: String?
        /// How a rotation went, in words, on the answer to a `rotate` request. Never a value.
        public var result: String?

        public init(
            id: String, at: Date, event: Event, agent: String, provider: String, reason: String? = nil, hours: Int? = nil,
            key: String? = nil, account: String? = nil, kind: String? = nil, result: String? = nil
        ) {
            self.id = id
            self.at = at
            self.event = event
            self.agent = agent
            self.provider = provider
            self.reason = reason.map { String(AgentRequest.oneLine($0).prefix(200)) }
            self.hours = hours
            self.key = key
            self.account = account.map { String(AgentRequest.oneLine($0).prefix(80)) }.flatMap { $0.isEmpty ? nil : $0 }
            self.kind = kind
            self.result = result.map { String(AgentRequest.oneLine($0).prefix(400)) }
        }

        public var isRotation: Bool { kind == "rotate" }
    }

    public static func read(from url: URL) -> [Entry] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        // A line that does not read is skipped, so one bad line cannot hide the others.
        return text.split(separator: "\n").compactMap { try? decoder.decode(Entry.self, from: Data($0.utf8)) }
    }

    public static func append(_ entry: Entry, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let line = try encoder.encode(entry) + Data("\n".utf8)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // O_APPEND puts each line at the end in one write, so the app and several agents never overwrite
        // each other; O_CREAT with 0600 makes it private from the first byte.
        let descriptor = open(url.path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw VaultError("the requests could not be written") }
        defer { close(descriptor) }
        let written = line.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
        guard written == line.count else { throw VaultError("the requests could not be written") }
    }

    /// Requests with no answer yet, oldest first.
    public static func pending(_ entries: [Entry]) -> [Entry] {
        let answered = Set(entries.filter { $0.event != .asked }.map(\.id))
        return entries.filter { $0.event == .asked && !answered.contains($0.id) }
    }

    /// The newest request from this agent to rotate this key, and its answer if there is one.
    public static func latestRotation(agent: String, key: String, in entries: [Entry]) -> (asked: Entry, answer: Entry?)? {
        guard let asked = entries.last(where: { $0.event == .asked && $0.isRotation && $0.agent == agent && $0.key == key }) else {
            return nil
        }
        return (asked, entries.last { $0.id == asked.id && $0.event != .asked })
    }

    /// The newest request from this agent for this provider, and its answer if there is one.
    public static func latest(agent: String, provider: String, in entries: [Entry]) -> (asked: Entry, answer: Entry?)? {
        guard let asked = entries.last(where: { $0.event == .asked && !$0.isRotation && $0.agent == agent && $0.provider == provider }) else {
            return nil
        }
        return (asked, entries.last { $0.id == asked.id && $0.event != .asked })
    }

    public static func readOffered(from url: URL) -> [String] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    /// The whole UUID: answers are matched to requests by it, and eight characters repeat in a long log.
    public static func newID() -> String { "r-" + UUID().uuidString.lowercased() }
}
