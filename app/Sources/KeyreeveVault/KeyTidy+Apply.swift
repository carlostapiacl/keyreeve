import Foundation

/// Applying what the person kept, to keys.toml and to every file that names a key by its identifier.
extension KeyTidy {
    /// Why a change checked when it was proposed no longer holds, against the list and the log as they are now:
    /// the key is gone, its new id was taken since, or it was used since and so is not dead. Nil when it still holds.
    public static func noLongerHolds(
        _ change: Change, in index: KeyIndex, use: Use?, logSince: Date? = nil, now: Date = Date()
    ) -> String? {
        let id = index.current(change.key)
        guard let before = index.all.first(where: { $0.id == id }) else { return "the key is gone" }
        // An old name of this same key may be taken back; another key's name may not.
        if let new = change.id, new != before.id, index.isTaken(new), index.current(new) != before.id {
            return "\(new) was taken since"
        }
        if change.archives(before), let alive = stillAlive(use, logSince: logSince, now: now) { return alive }
        return nil
    }

    /// Applies the changes the person kept to the list. A renamed key keeps its old id in `formerly`. Returns what
    /// changed, one line per key, each rename, for the files that name keys to follow, and what was left out
    /// because it no longer holds.
    @discardableResult
    public static func apply(
        _ changes: [Change], to index: inout KeyIndex, usage: [String: Use] = [:], logSince: Date? = nil,
        now: Date = Date()
    ) -> (done: [String], renamed: [(String, String)], skipped: [String]) {
        var done: [String] = []
        var renamed: [(String, String)] = []
        var skipped: [String] = []
        for change in changes {
            let id = index.current(change.key)
            if let why = noLongerHolds(change, in: index, use: usage[id], logSince: logSince, now: now) {
                skipped.append("\(change.key): \(why)")
                continue
            }
            let offered = index.keys.contains { $0.id == id }
            guard var key = (offered ? index.keys : index.unoffered).first(where: { $0.id == id }) else { continue }
            let before = key
            if let new = change.id, new != key.id {
                var formerly = (key.more.formerly ?? []).filter { $0 != new }
                if !formerly.contains(key.id) { formerly.append(key.id) }
                key.more.formerly = formerly
                renamed.append((key.id, new))
                key.id = new
            }
            if let value = change.description { key.description = value }
            if let value = change.project { key.project = value }
            if let value = change.provider { key.provider = value }
            if let value = change.variable { key.variable = value }
            if let value = change.account { key.account = value }
            if let value = change.field { key.field = value }
            if let tags = change.tags {
                var kept = key.more.tags ?? []
                for tag in tags where !kept.contains(tag) { kept.append(tag) }
                key.more.tags = kept
            }
            if change.archive == true { key.more.archived = true }
            guard key != before else { continue }
            if offered {
                index.keys.removeAll { $0.id == before.id }
                index.keys.insert(key, at: index.keys.firstIndex { $0.id > key.id } ?? index.keys.endIndex)
            } else if let at = index.unoffered.firstIndex(where: { $0.id == before.id }) {
                index.unoffered[at] = key
            }
            done.append("\(before.id): \(change.summary(from: before))")
        }
        return (done, renamed, skipped)
    }

    /// Applies the changes in the person's files: keys.toml, then everything else that names a renamed key by its
    /// identifier (permissions, standing permissions and sets, places, local services), each under its own lock, after
    /// a copy of keys.toml and agents.toml beside them. `key-state.json` is left to the service, its only writer: it
    /// marks the key again under its new name the next time its provider refuses it.
    @discardableResult
    public static func apply(
        _ changes: [Change], home: URL, stamp: String, usage: [String: Use] = [:], logSince: Date? = nil
    ) throws -> (done: [String], skipped: [String]) {
        let keys = home.appendingPathComponent(KeyIndex.fileName)
        let agents = home.appendingPathComponent(AgentPolicy.fileName)
        let exists = { (url: URL) in FileManager.default.fileExists(atPath: url.path) }
        for file in [keys, agents] where exists(file) {
            let copy = home.appendingPathComponent("\(file.lastPathComponent).antes-tidy-\(stamp)")
            // A copy already there is from before this same second's first apply: it is the one worth keeping.
            guard !exists(copy) else { continue }
            try FileManager.default.copyItem(at: file, to: copy)
            chmod(copy.path, 0o600)
        }
        let result = try KeyIndex.change(at: keys) { index in
            apply(changes, to: &index, usage: usage, logSince: logSince)
        }.result
        let renamed = result.renamed
        guard !renamed.isEmpty else { return (result.done, result.skipped) }
        let rename = { (id: String) in renamed.first { $0.0 == id }?.1 ?? id }
        if exists(agents) {
            _ = try AgentPolicy.update(at: agents) { policy in for (old, new) in renamed { policy.rename(old, to: new) } }
        }
        let places = PlaceBook.file(home: home)
        if exists(places) {
            try PlaceBook.update(at: places) { book in
                for at in book.places.indices { book.places[at].key = rename(book.places[at].key) }
            }
        }
        let sets = home.appendingPathComponent(KeySets.fileName)
        if exists(sets) {
            try KeySets.update(at: sets) { all in
                for at in all.sets.indices { all.sets[at].keys = all.sets[at].keys.map(rename) }
                for at in all.standing.indices { all.standing[at].keys = all.standing[at].keys.map(rename) }
            }
        }
        let local = home.appendingPathComponent(LocalServices.fileName)
        if exists(local) { try LocalServices.rename(renamed, at: local) }
        return (result.done, result.skipped)
    }
}

extension AgentPolicy {
    /// Moves every permission of a key to its new identifier.
    public mutating func rename(_ old: String, to new: String) {
        if let value = commands.removeValue(forKey: old) { commands[new] = value }
        if let value = levels.removeValue(forKey: old) { levels[new] = value }
        if let value = agents.removeValue(forKey: old) { agents[new] = value }
        if let value = hashes.removeValue(forKey: old) { hashes[new] = value }
        if let value = until.removeValue(forKey: old) { until[new] = value }
    }
}
