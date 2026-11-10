import Foundation

/// keys.toml has several writers: the app, `keyreeve-vault add` and `put` from an agent, `reseal`. Each one reads the
/// file as it is now under one lock, applies only its own change and writes it back whole, so a record another
/// writer added a moment ago is never lost to a copy read earlier.
extension KeyIndex {
    /// The lock every writer of this keys.toml takes, beside it.
    public static func lockURL(for url: URL) -> URL {
        url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).lock")
    }

    /// Runs `body` with no other writer of this keys.toml in the middle. Not reentrant: never call it inside itself.
    public static func withLock<T>(at url: URL, _ body: () throws -> T) throws -> T {
        try PrivateFile.folder(url.deletingLastPathComponent())
        // Close on exec: a child that inherited this would hold the lock for as long as it runs.
        let descriptor = open(lockURL(for: url).path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw VaultError("keys.toml could not be locked") }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw VaultError("keys.toml could not be locked") }
        return try body()
    }

    /// Reads keys.toml under the lock, lets `change` edit it, and writes it if anything changed. Returns the file as
    /// it now is. A keys.toml that is there and cannot be read stops the change.
    @discardableResult
    public static func change<T>(at url: URL, _ change: (inout KeyIndex) throws -> T) throws -> (index: KeyIndex, result: T) {
        try withLock(at: url) {
            var index = try load(from: url)
            let before = index
            let result = try change(&index)
            if index != before { try PrivateFile.write(Data(index.toml.utf8), to: url) }
            return (index, result)
        }
    }

    /// Writes what changed between `base`, the copy an edit started from, and `edited`, onto the file as it is now.
    /// Records nobody touched in this edit, such as one an agent added since `base` was read, stay as they are.
    @discardableResult
    public static func save(_ edited: KeyIndex, from base: KeyIndex, at url: URL) throws -> KeyIndex {
        func byID(_ index: KeyIndex) -> [String: (key: Key, offered: Bool)] {
            var all: [String: (key: Key, offered: Bool)] = [:]
            for key in index.keys { all[key.id] = (key, true) }
            for key in index.unoffered { all[key.id] = (key, false) }
            return all
        }
        let before = byID(base)
        let after = byID(edited)
        return try change(at: url) { disk in
            for id in Set(before.keys).union(after.keys).sorted() {
                guard before[id]?.key != after[id]?.key || before[id]?.offered != after[id]?.offered else { continue }
                // A new identifier another writer took meanwhile is theirs: this edit stops rather than replace it.
                if before[id] == nil, let mine = after[id]?.key,
                    let theirs = (disk.keys + disk.unoffered).first(where: { $0.id == id }), theirs != mine
                {
                    throw VaultError("\(id) is already in use")
                }
                disk.remove(id: id)
                guard let (key, offered) = after[id] else { continue }
                if offered {
                    disk.keys.insert(key, at: disk.keys.firstIndex { $0.id > key.id } ?? disk.keys.endIndex)
                } else {
                    disk.unoffered.insert(key, at: disk.unoffered.firstIndex { $0.id > key.id } ?? disk.unoffered.endIndex)
                }
            }
            if edited.schema != base.schema { disk.schema = edited.schema }
        }.index
    }

    /// When keys.toml last changed, as a stamp: equal stamps, same file.
    public static func stamp(of url: URL) -> String {
        guard let values = try? FileManager.default.attributesOfItem(atPath: url.path) else { return "none" }
        let date = (values[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        return "\(date)-\(values[.size] as? Int ?? 0)-\(values[.systemFileNumber] as? Int ?? 0)"
    }
}
