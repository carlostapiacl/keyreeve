import Foundation

/// What a provider last said of a key's OAuth credential, by key id: `key-state.json` beside keys.toml. Only
/// the key service writes it, whole and at once, so no edit the app makes to keys.toml can be lost to it.
/// The app reads it to show a key its provider no longer accepts like one that expired.
public enum KeyStates {
    public static let fileName = "key-state.json"
    public static let reauthorize = "reauthorize"

    public struct Entry: Codable, Equatable, Sendable {
        public var state: String
        public var since: Date
        public init(state: String, since: Date) {
            self.state = state
            self.since = since
        }
    }

    /// One writer at a time in this process. The service is the only process that writes the file.
    private static let lock = NSLock()

    /// What the file says, or nothing when it is missing or cannot be read: a mark is a hint, never a reason to stop.
    public static func load(from url: URL) -> [String: Entry] {
        guard let data = try? Data(contentsOf: url) else { return [:] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([String: Entry].self, from: data)) ?? [:]
    }

    /// The ids of the keys that need authorizing again.
    public static func needingReauthorization(in url: URL) -> Set<String> {
        Set(load(from: url).filter { $0.value.state == reauthorize }.keys)
    }

    /// Marks a key whose provider no longer accepts its credential, or takes the mark off once a token comes again.
    /// A mark already there keeps the day it was first made, and an unchanged file is not written.
    public static func mark(id: String, active: Bool, in url: URL, now: Date = Date()) throws {
        lock.lock()
        defer { lock.unlock() }
        var all = load(from: url)
        if active {
            guard all.removeValue(forKey: id) != nil else { return }
        } else {
            guard all[id]?.state != reauthorize else { return }
            all[id] = Entry(state: reauthorize, since: now)
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try PrivateFile.write(try encoder.encode(all), to: url)
    }
}
