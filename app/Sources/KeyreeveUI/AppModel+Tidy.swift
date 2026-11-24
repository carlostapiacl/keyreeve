import Foundation
import KeyreeveCatalog
import KeyreeveVault

extension AppModel {
    /// The changes an agent proposed to tidy keys, as it left them.
    public func tidyChanges(for request: AccessRequests.Entry) -> [KeyTidy.Change] {
        guard let data = AgentSorting.load(id: request.id, home: files.directory) else { return [] }
        return (try? JSONDecoder().decode([KeyTidy.Change].self, from: data)) ?? []
    }

    /// Projects the keys already name, to mark a proposed one that is new.
    public var knownProjects: Set<String> { KeyTidy.knownProjects(keyIndex) }

    /// The key as it is now, to show each change beside what it replaces.
    public func tidyKey(_ id: String) -> KeyIndex.Key? {
        let current = keyIndex.current(id)
        return keyIndex.all.first { $0.id == current }
    }

    /// Applies the chosen changes: names, descriptions, projects and archiving. Only words about keys change, never a
    /// value, so it takes a click and no fingerprint. keys.toml and agents.toml are copied beside them first.
    public func applyTidy(_ changes: [KeyTidy.Change], for request: AccessRequests.Entry) {
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "")
        let done: [String]
        let skipped: [String]
        do {
            // Checked again against the list and the log as they are now: a proposal may be hours old.
            let read = UsageCache.read(home: files.directory, index: keyIndex)
            (done, skipped) = try KeyTidy.apply(
                changes, home: files.directory, stamp: stamp, usage: read.usage, logSince: read.since)
        } catch {
            message = T("The changes could not be applied: %@", "\(error)")
            return
        }
        audit([("\(done.count) keys", "tidy \(request.id) from \(request.agent)")], event: "allowed")
        try? AccessRequests.append(
            AccessRequests.Entry(
                id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider,
                kind: KeyTidy.requestKind,
                result: "applied \(done.count): " + done.prefix(20).joined(separator: " | ")
                    + (skipped.isEmpty ? "" : "; left out \(skipped.count): " + skipped.prefix(20).joined(separator: " | "))),
            to: requestsFile)
        message = skipped.isEmpty
            ? T("%d keys tidied. A copy of the list from before is beside it.", done.count)
            : T("%d keys tidied, %d left out because they changed since: %@", done.count, skipped.count,
                skipped.prefix(3).joined(separator: "; "))
        reloadRequests()
        load()
    }
}

/// A key used lately: who used it, from where and to which hosts. Words from the usage log, never a value.
public struct KeyInUse: Identifiable, Equatable, Sendable {
    public var id: String
    /// The file or vault name the list knows it by, to open it there.
    public var source: String
    public var project: String?
    public var provider: String?
    public var description: String?
    public var use: KeyTidy.Use

    public static let days = 30

    /// Read off the screen. The log is read again only when it changed, since the window loads often.
    static func read(home: URL, index: KeyIndex, now: Date = Date()) -> [KeyInUse] {
        let usage = UsageCache.usage(home: home, index: index)
        let since = now.addingTimeInterval(-Double(days) * 86400)
        return index.all.compactMap { key -> KeyInUse? in
            guard !key.more.archived, let use = usage[key.id], let last = use.last, last >= since else { return nil }
            return KeyInUse(id: key.id, source: key.source, project: key.project, provider: key.provider, description: key.description, use: use)
        }
        .sorted { ($0.use.last ?? .distantPast) > ($1.use.last ?? .distantPast) }
    }
}

/// The usage worked out from the log, and the oldest moment the log read reaches, kept until the log or keys.toml
/// changes. By home, so two homes (the tests have many) never share it.
enum UsageCache {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var stamp = ""
    nonisolated(unsafe) private static var kept: (usage: [String: KeyTidy.Use], since: Date?) = ([:], nil)

    static func usage(home: URL, index: KeyIndex) -> [String: KeyTidy.Use] { read(home: home, index: index).usage }

    static func read(home: URL, index: KeyIndex) -> (usage: [String: KeyTidy.Use], since: Date?) {
        let files = ["audit.jsonl", KeyIndex.fileName].map { home.appendingPathComponent($0).path }
        let now = home.path + "|" + files.map { path -> String in
            let attributes = try? FileManager.default.attributesOfItem(atPath: path)
            return "\((attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)-\((attributes?[.size] as? Int) ?? 0)"
        }.joined(separator: "|")
        lock.lock()
        if now == stamp {
            defer { lock.unlock() }
            return kept
        }
        lock.unlock()
        let entries = KeyTidy.recentEntries(home: home)
        let fresh = (usage: KeyTidy.usage(entries, index: index), since: entries.map(\.at).min())
        lock.lock()
        stamp = now
        kept = fresh
        lock.unlock()
        return fresh
    }
}
