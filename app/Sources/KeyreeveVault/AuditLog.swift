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
    /// Past this size the log is set aside under a dated name and a new one goes on from it, so what is read
    /// on each refresh stays small. The new one's first line holds the last hash of the one before.
    public let segmentLimit: Int

    public init(url: URL, segmentLimit: Int = 16 << 20) {
        self.url = url
        self.segmentLimit = segmentLimit
    }

    /// The event that opens a log continuing one set aside. Its `prev` is the last hash of that one.
    public static let continued = "continued"

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    /// A reader of the whole log passes one encoder for every line: making one per line was most of the time
    /// it took to open the app.
    private static func hash(of entry: Entry, encoder: JSONEncoder = encoder()) throws -> String {
        var unhashed = entry
        unhashed.hash = ""
        var hasher = SHA256()
        hasher.update(data: Data(entry.prev.utf8))
        hasher.update(data: try encoder.encode(unhashed))
        return hex(hasher.finalize())
    }

    private static let hexDigits = Array("0123456789abcdef".utf8)

    /// Lowercase hex, as `String(format: "%02x")` gave, without formatting each byte on its own.
    public static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        var out: [UInt8] = []
        out.reserveCapacity(64)
        for byte in digest {
            out.append(hexDigits[Int(byte >> 4)])
            out.append(hexDigits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Adds a line. Any process can call this, so the lock covers reading the last hash and writing.
    public func append(
        event: String, key: String, grant: String? = nil, observed: Observed? = nil, declared: Declared? = nil,
        detail: String? = nil, now: Date = Date()
    ) throws {
        // The file can be set aside while this waits for the lock: then it opens the new one and waits again.
        var descriptor: Int32 = -1
        for _ in 0..<20 {
            descriptor = open(url.path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw VaultError("the usage log could not be opened") }
            guard flock(descriptor, LOCK_EX) == 0 else {
                close(descriptor)
                throw VaultError("the usage log could not be locked")
            }
            if isCurrent(descriptor) { break }
            close(descriptor)
            descriptor = -1
        }
        guard descriptor >= 0 else { throw VaultError("the usage log kept moving and could not be written") }
        if lseek(descriptor, 0, SEEK_END) > segmentLimit {
            // Closed once, here: a second close could end a file another thread just opened under the same number.
            defer { close(descriptor) }
            try setAside(descriptor: descriptor, now: now)
            return try append(event: event, key: key, grant: grant, observed: observed, declared: declared, detail: detail, now: now)
        }
        defer { close(descriptor) }
        var entry = Entry(
            at: now, event: event, key: key, grant: grant, observed: observed, declared: declared, detail: detail,
            prev: try lastHash(descriptor: descriptor), hash: "")
        entry.hash = try Self.hash(of: entry)
        let line = try Self.encoder().encode(entry) + Data("\n".utf8)
        let written = line.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
        guard written == line.count, fsync(descriptor) == 0 else { throw VaultError("the usage log could not be written") }
    }

    /// Whether this open file is still the one at the log's path.
    private func isCurrent(_ descriptor: Int32) -> Bool {
        var open = stat()
        var named = stat()
        guard fstat(descriptor, &open) == 0, stat(url.path, &named) == 0 else { return false }
        return open.st_ino == named.st_ino && open.st_dev == named.st_dev
    }

    /// Under the lock: the full log gets a dated name, and in its place, in one step, a new one whose first line
    /// says where it goes on from. Anyone waiting on the old file's lock sees it moved and writes to the new.
    private func setAside(descriptor: Int32, now: Date) throws {
        // Numbered in the order they were set aside, which is the chain's order whatever the clocks said; the day
        // is there for people.
        let day = ISO8601DateFormatter.string(from: now, timeZone: .gmt, formatOptions: [.withYear, .withMonth, .withDay])
        let archive = Self.segmentURL(for: url, number: segments().count, day: day)
        var first = Entry(
            at: now, event: Self.continued, key: "-", detail: archive.lastPathComponent, prev: try lastHash(descriptor: descriptor), hash: "")
        first.hash = try Self.hash(of: first)
        let temp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        try PrivateFile.write(try Self.encoder().encode(first) + Data("\n".utf8), to: temp)
        guard link(url.path, archive.path) == 0 else {
            unlink(temp.path)
            throw VaultError("the usage log could not be set aside")
        }
        guard rename(temp.path, url.path) == 0 else {
            unlink(archive.path)
            unlink(temp.path)
            throw VaultError("the usage log could not be set aside")
        }
    }

    static func segmentURL(for url: URL, number: Int, day: String) -> URL {
        url.deletingLastPathComponent().appendingPathComponent(
            url.deletingPathExtension().lastPathComponent + "-" + String(format: "%06d", number) + "-" + day + ".jsonl")
    }

    /// The logs set aside, oldest first, then this one.
    public func segments() -> [URL] {
        let folder = url.deletingLastPathComponent()
        let stem = url.deletingPathExtension().lastPathComponent + "-"
        let names = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        return names.filter { $0.hasPrefix(stem) && $0.hasSuffix(".jsonl") }.sorted().map(folder.appendingPathComponent) + [url]
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

    /// Every entry, from the logs set aside too, oldest first. The lines that only join them are left out.
    public func entries() throws -> [Entry] {
        let decoder = Self.decoder()
        return try segments().flatMap { segment -> [Entry] in
            guard let data = try? Data(contentsOf: segment) else { return [] }
            return try data.split(separator: 10).map { try decoder.decode(Entry.self, from: Data($0)) }
                .filter { $0.event != Self.continued }
        }
    }

    /// Where the whole history, the logs set aside included, stops holding together: the file and its line,
    /// or nil. A log that goes on from another must start from that one's last hash.
    public func firstBreak() -> (file: String, line: Int)? {
        var last: String?
        for segment in segments() {
            let part = AuditLog(url: segment, segmentLimit: segmentLimit)
            if let line = part.firstBrokenLine() { return (segment.lastPathComponent, line) }
            guard let data = try? Data(contentsOf: segment) else { continue }
            let lines = data.split(separator: 10)
            let decoder = Self.decoder()
            if let last, let first = lines.first.flatMap({ try? decoder.decode(Entry.self, from: Data($0)) }),
                first.event != Self.continued || first.prev != last
            {
                return (segment.lastPathComponent, 1)
            }
            last = lines.last.flatMap { try? decoder.decode(Entry.self, from: Data($0)) }?.hash ?? last
        }
        return nil
    }

    /// The first line that does not follow from the one before, or nil if the chain holds or there is no
    /// log yet. A log that is there and cannot be read is line 0: it cannot be said to hold.
    public func firstBrokenLine() -> Int? { recent(0).brokenLine }

    /// The newest `count` entries, newest last, and whether the chain holds, from one reading of the file.
    /// What the app shows on each refresh. The chain is checked from where the last reading in this process
    /// left it, when the bytes up to there are the same, so a log of many thousand lines is not decoded and
    /// hashed again each time; any change to those bytes checks it all again. Only the newest lines are
    /// decoded to be shown, from the end.
    public func recent(_ count: Int) -> (entries: [Entry], brokenLine: Int?) {
        guard FileManager.default.fileExists(atPath: url.path) else { return ([], nil) }
        guard let read = try? Data(contentsOf: url) else { return ([], 0) }
        let data = Data(read)
        let decoder = Self.decoder()
        let checked = Self.check(data, path: url.path, decoder: decoder)
        guard count > 0 else { return ([], checked.broken) }
        // A line that is not an entry ends what can be shown; what came before still is.
        var end = checked.undecodableAt ?? data.endIndex
        var entries: [Entry] = []
        while entries.count < count {
            while end > data.startIndex, data[end - 1] == 10 { end -= 1 }
            guard end > data.startIndex else { break }
            let start = data[data.startIndex..<end].lastIndex(of: 10).map { $0 + 1 } ?? data.startIndex
            guard let entry = try? decoder.decode(Entry.self, from: data[start..<end]) else { break }
            entries.append(entry)
            end = start
        }
        return (entries.reversed(), checked.broken)
    }

    /// How far the chain was checked: through the end of a complete line, with the digest of the bytes up to
    /// there, the last hash, the lines counted and the first that did not hold.
    struct Checked: Sendable {
        var length = 0
        var digest = SHA256.hash(data: Data())
        var previous = ""
        var lines = 0
        var broken: Int?
    }

    final class CheckedCache: @unchecked Sendable {
        private let lock = NSLock()
        private var byPath: [String: Checked] = [:]
        subscript(path: String) -> Checked? {
            get { lock.lock(); defer { lock.unlock() }; return byPath[path] }
            set { lock.lock(); defer { lock.unlock() }; byPath[path] = newValue }
        }
    }

    static let checkedCache = CheckedCache()

    /// The first line that does not hold, numbered from 1 as the lines that are not empty, and where the first
    /// line that is not an entry starts, if any. Checking stops at that line.
    static func check(_ data: Data, path: String, decoder: JSONDecoder) -> (broken: Int?, undecodableAt: Int?) {
        var state = Checked()
        if let cached = checkedCache[path], cached.length <= data.count,
            SHA256.hash(data: data[data.startIndex..<data.startIndex + cached.length]) == cached.digest
        {
            state = cached
        }
        let encoder = encoder()
        var good = state
        var position = data.startIndex + state.length
        var undecodable: Int?
        while position < data.endIndex {
            let newline = data[position...].firstIndex(of: 10)
            let lineEnd = newline ?? data.endIndex
            let next = newline.map { $0 + 1 } ?? data.endIndex
            defer { position = next }
            guard lineEnd > position else {
                if newline != nil { good.length = next - data.startIndex }
                continue
            }
            guard let entry = try? decoder.decode(Entry.self, from: data[position..<lineEnd]) else {
                if state.broken == nil { state.broken = state.lines + 1 }
                undecodable = position
                break
            }
            // A log that goes on from one set aside starts from that one's last hash, which its first line holds.
            if state.lines == 0, entry.event == Self.continued { state.previous = entry.prev }
            if state.broken == nil, entry.prev != state.previous || (try? Self.hash(of: entry, encoder: encoder)) != entry.hash {
                state.broken = state.lines + 1
            }
            state.previous = entry.hash
            state.lines += 1
            // Only a complete line is kept as checked: a line still being written is read again next time.
            if newline != nil {
                state.length = next - data.startIndex
                good = state
            }
        }
        good.digest = SHA256.hash(data: data[data.startIndex..<data.startIndex + good.length])
        checkedCache[path] = good
        return (state.broken, undecodable)
    }
}
