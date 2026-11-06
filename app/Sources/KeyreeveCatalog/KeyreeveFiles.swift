import Foundation

/// Where keyreeve keeps its private files. The defaults are those the README uses.
public struct KeyreeveFiles: Sendable {
    public let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keyreeve")
    }

    public var catalog: URL { directory.appendingPathComponent("catalog.csv") }
    public var inventory: URL { directory.appendingPathComponent("inventory.json") }
    public var rules: URL { directory.appendingPathComponent("rules.yaml") }
    public var history: URL { directory.appendingPathComponent("history.jsonl") }
    public var usage: URL { directory.appendingPathComponent("usage.jsonl") }
    public var details: URL { directory.appendingPathComponent("details.json") }
    public var edits: URL { directory.appendingPathComponent("edits.json") }
    public var ignored: URL { directory.appendingPathComponent("ignored.json") }
    public var words: URL { directory.appendingPathComponent("words.txt") }
    public var keyIndex: URL { directory.appendingPathComponent("keys.toml") }
    public var audit: URL { directory.appendingPathComponent("audit.jsonl") }
    public var keySocket: URL { directory.appendingPathComponent("run/keys.sock") }
    public var agents: URL { directory.appendingPathComponent("agents.toml") }
    public var moved: URL { directory.appendingPathComponent("moved.json") }
    public var originals: URL { directory.appendingPathComponent("originals") }
    public var rotations: URL { directory.appendingPathComponent("rotations.jsonl") }
    public var places: URL { directory.appendingPathComponent("places.json") }
    var rotationPlan: URL { directory.appendingPathComponent(".rotation-plan.json") }
    var plan: URL { directory.appendingPathComponent(".check-plan.json") }
    var settings: URL { directory.appendingPathComponent("app-settings.json") }

    public func activity() -> [ActivityItem] {
        ActivityItem.parse(history: Self.tail(of: history), usage: Self.tail(of: usage))
    }

    /// The end of a log, whole lines only. The screen shows a few recent lines, and a log only grows.
    static func tail(of url: URL, bytes: UInt64 = 128 * 1024) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        guard let size = try? handle.seekToEnd() else { return "" }
        let start = size > bytes ? size - bytes : 0
        guard (try? handle.seek(toOffset: start)) != nil, let data = try? handle.readToEnd() else { return "" }
        let text = String(decoding: data, as: UTF8.self)
        guard start > 0, let line = text.firstIndex(of: "\n") else { return text }
        return String(text[text.index(after: line)...])
    }

    /// Closes this folder and the one with your own programs, which can name your servers.
    public func tightenFolders() {
        for folder in [directory, directory.appendingPathComponent("providers")] {
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        }
    }

    public func keysFolder() -> URL? {
        guard let data = try? Data(contentsOf: settings),
            let values = try? JSONDecoder().decode([String: String].self, from: data),
            let path = values["keys_folder"]
        else { return nil }
        return URL(fileURLWithPath: path)
    }

    public func saveKeysFolder(_ url: URL) throws {
        try writePrivate(try JSONEncoder().encode(["keys_folder": url.path]), to: settings)
    }

    public func writePrivate(_ data: Data, to url: URL) throws {
        let previous = umask(0o077)
        defer { umask(previous) }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
