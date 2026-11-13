import Foundation

/// Where keyreeve keeps its private files. The defaults are those the README uses.
public struct KeyreeveFiles: Sendable {
    public let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory ?? Self.defaultDirectory()
    }

    /// `KEYREEVE_HOME` when it is set, as the command line reads it, and `~/.keyreeve` otherwise. It lets a second
    /// Keyreeve run over a folder of its own, such as one with made-up keys for a demo.
    public static func defaultDirectory(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let home = environment["KEYREEVE_HOME"], !home.isEmpty { return URL(fileURLWithPath: home, isDirectory: true) }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keyreeve")
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
    /// The local services you approved keys for, with your fingerprint. Holds addresses, never a value.
    public var localServices: URL { directory.appendingPathComponent("local-services.json") }
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

    /// Written beside the target at 0600 from the first byte, then put in its place, with no change to
    /// the process's umask, which every thread shares.
    public func writePrivate(_ data: Data, to url: URL) throws {
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            guard chmod(directory.path, 0o700) == 0 else { throw CheckError(T("%@ could not be saved", url.lastPathComponent)) }
        }
        let temp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        let descriptor = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw CheckError(T("%@ could not be saved", url.lastPathComponent)) }
        var saved = false
        defer {
            close(descriptor)
            if !saved { unlink(temp.path) }
        }
        guard fchmod(descriptor, 0o600) == 0 else { throw CheckError(T("%@ could not be saved", url.lastPathComponent)) }
        try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(descriptor, bytes.baseAddress! + offset, bytes.count - offset)
                guard written > 0 else { throw CheckError(T("%@ could not be saved", url.lastPathComponent)) }
                offset += written
            }
        }
        guard fsync(descriptor) == 0, rename(temp.path, url.path) == 0 else {
            throw CheckError(T("%@ could not be saved", url.lastPathComponent))
        }
        saved = true
        // The new name reaches the disk too, so a power cut right after cannot bring the old file back. The file
        // is already in place, so a folder that cannot be synced does not make this a failure.
        let parent = open(url.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        if parent >= 0 {
            _ = fsync(parent)
            close(parent)
        }
    }

    /// The last check of each of these keys, from the history of checks: its result and its day.
    public func lastResults(for names: Set<String>) -> [String: (result: String, day: String)] {
        guard let text = try? String(contentsOf: history, encoding: .utf8) else { return [:] }
        let day = DateFormatter()
        day.locale = Locale(identifier: "en_US_POSIX")
        day.timeZone = TimeZone(identifier: "UTC")
        day.dateFormat = "yyyy-MM-dd"
        var found: [String: (result: String, day: String)] = [:]
        for line in text.split(separator: "\n") {
            guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                let file = row["file"] as? String, names.contains(file), let result = row["result"] as? String
            else { continue }
            let at = (row["at"] as? Double).map { day.string(from: Date(timeIntervalSince1970: $0)) } ?? ""
            found[file] = (result, at)
        }
        return found
    }
}

