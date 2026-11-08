import CryptoKit
import Foundation

/// Who used which key. Each line carries the hash of the one before, so an edit shows. It holds no
/// value, no request body and no arguments, which can carry anything. Another program running as you
/// could rewrite the whole chain, so this detects changes and does not prevent them.
public struct AuditLog: Sendable {
    public struct Observed: Codable, Equatable, Sendable {
        /// From the system, through the socket, so the caller cannot simply claim them.
        public var pid: Int32
        public var program: String
        public var chain: [String]
        public init(pid: Int32, program: String, chain: [String]) {
            self.pid = pid
            self.program = program
            self.chain = chain
        }
    }

    public struct Declared: Codable, Equatable, Sendable {
        /// What the caller says about itself, which it could get wrong on purpose.
        public var agent: String?
        public var reason: String?
        public var command: String?
        public var cwd: String?
        public init(agent: String? = nil, reason: String? = nil, command: String? = nil, cwd: String? = nil) {
            self.agent = agent.map { String($0.prefix(80)) }
            self.reason = reason.map { String($0.prefix(200)) }
            // A line has to fit where the next one looks for the last hash.
            self.command = command.map { String($0.prefix(1024)) }
            self.cwd = cwd.map { String($0.prefix(1024)) }
        }
    }

    public struct Entry: Codable, Equatable, Sendable {
        public var at: Date
        public var event: String
        public var key: String
        public var grant: String?
        public var observed: Observed?
        public var declared: Declared?
        public var detail: String?
        public var prev: String
        public var hash: String
    }

    public let url: URL

    public init(url: URL) { self.url = url }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func hash(of entry: Entry) throws -> String {
        var unhashed = entry
        unhashed.hash = ""
        let data = try encoder().encode(unhashed)
        return SHA256.hash(data: Data(entry.prev.utf8) + data).map { String(format: "%02x", $0) }.joined()
    }

    /// Adds a line. Any process can call this, so the lock covers reading the last hash and writing.
    public func append(
        event: String, key: String, grant: String? = nil, observed: Observed? = nil, declared: Declared? = nil,
        detail: String? = nil, now: Date = Date()
    ) throws {
        let descriptor = open(url.path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw VaultError("the usage log could not be opened") }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw VaultError("the usage log could not be locked") }
        var entry = Entry(
            at: now, event: event, key: key, grant: grant, observed: observed, declared: declared, detail: detail,
            prev: try lastHash(descriptor: descriptor), hash: "")
        entry.hash = try Self.hash(of: entry)
        let line = try Self.encoder().encode(entry) + Data("\n".utf8)
        let written = line.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
        guard written == line.count, fsync(descriptor) == 0 else { throw VaultError("the usage log could not be written") }
    }

    private func lastHash(descriptor: Int32) throws -> String {
        let size = lseek(descriptor, 0, SEEK_END)
        guard size > 0 else { return "" }
        let wanted = min(Int(size), 64 * 1024)
        var buffer = Data(count: wanted)
        let got = buffer.withUnsafeMutableBytes { pread(descriptor, $0.baseAddress, wanted, off_t(Int(size) - wanted)) }
        guard got == wanted else { throw VaultError("the usage log could not be read") }
        let lines = buffer.split(separator: 10)
        guard let last = lines.last, let entry = try? Self.decoder().decode(Entry.self, from: Data(last)) else {
            throw VaultError("the usage log's last line is damaged")
        }
        return entry.hash
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    public func entries() throws -> [Entry] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        let decoder = Self.decoder()
        return try data.split(separator: 10).map { try decoder.decode(Entry.self, from: Data($0)) }
    }

    /// The first line that does not follow from the one before, or nil if the chain holds or there is no
    /// log yet. A log that is there and cannot be read is line 0: it cannot be said to hold.
    public func firstBrokenLine() -> Int? { recent(0).brokenLine }

    /// The newest `count` entries, newest last, and whether the chain holds, from one reading of the file.
    /// What the app shows on each refresh, so a log that grows all day is read and decoded once, not twice.
    public func recent(_ count: Int) -> (entries: [Entry], brokenLine: Int?) {
        guard FileManager.default.fileExists(atPath: url.path) else { return ([], nil) }
        guard let data = try? Data(contentsOf: url) else { return ([], 0) }
        let decoder = Self.decoder()
        var kept: [Entry] = []
        var broken: Int?
        var previous = ""
        for (index, line) in data.split(separator: 10).enumerated() {
            guard let entry = try? decoder.decode(Entry.self, from: Data(line)) else {
                // A line that is not an entry ends what can be shown; what came before still is.
                if broken == nil { broken = index + 1 }
                break
            }
            if broken == nil, entry.prev != previous || (try? Self.hash(of: entry)) != entry.hash { broken = index + 1 }
            previous = entry.hash
            if count > 0 {
                kept.append(entry)
                if kept.count > count * 2 { kept.removeFirst(kept.count - count) }
            }
        }
        return (Array(kept.suffix(count)), broken)
    }
}
