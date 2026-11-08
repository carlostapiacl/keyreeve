import Foundation

/// Where an agent reads the list of key files it may help sort, and leaves its proposals. The app writes
/// the list, and only while the person lets agents sort: names, field names, providers and states, never a
/// value. A proposal is only words about those files; the app checks it and the person applies it.
public enum AgentSorting {
    public static let inventoryFileName = "agent-inventory.json"
    public static let proposalsFolderName = "proposals"
    public static let maxChanges = 500
    public static let maxBytes = 512 * 1024

    public static func inventoryFile(home: URL) -> URL { home.appendingPathComponent(inventoryFileName) }

    /// The paths an inventory lists.
    public static func paths(inInventory data: Data) -> Set<String> {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keys = object["keys"] as? [[String: Any]]
        else { return [] }
        return Set(keys.compactMap { $0["path"] as? String })
    }

    /// A proposal's changes, each an object naming a file the inventory lists, as JSON to keep. Anything
    /// else is refused whole, so a proposal is never half kept.
    public static func check(_ changes: Any?, paths: Set<String>) throws -> (data: Data, count: Int) {
        guard let list = changes as? [[String: Any]], !list.isEmpty else {
            throw VaultError("changes must be a list of objects, each with a path")
        }
        guard list.count <= maxChanges else { throw VaultError("at most \(maxChanges) changes at once") }
        for change in list {
            guard let path = change["path"] as? String else { throw VaultError("each change needs a path") }
            guard paths.contains(path) else { throw VaultError("\(path) is not in the inventory") }
        }
        let data = try JSONSerialization.data(withJSONObject: list, options: [.sortedKeys])
        guard data.count <= maxBytes else { throw VaultError("the changes are too long") }
        return (data, list.count)
    }

    /// A key that still needs something: not archived, a secret with something to check, and with no
    /// provider, no passing check, no seal, or a field or split pending.
    static func isPending(_ row: [String: Any]) -> Bool {
        if row["archived"] as? Bool == true || row["level"] as? String == "none" { return false }
        if row["untestable"] as? Bool == true || row["internal"] as? Bool == true { return row["sealed"] as? Bool != true }
        return row["provider"] == nil || row["result"] as? String != "works" || row["sealed"] as? Bool != true
            || row["needs"] != nil
    }

    /// Part of the inventory, so a few hundred keys fit in an agent's answer: only pending ones, only paths
    /// holding some text, a page of them, with the totals and the providers.
    public static func page(_ data: Data, pending: Bool, matching: String?, offset: Int, limit: Int) -> Data? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keys = object["keys"] as? [[String: Any]]
        else { return nil }
        let needle = matching?.lowercased().trimmingCharacters(in: .whitespaces) ?? ""
        let chosen = keys.filter { row in
            (!pending || isPending(row))
                && (needle.isEmpty || ((row["path"] as? String)?.lowercased().contains(needle) ?? false))
        }
        let start = min(max(offset, 0), chosen.count)
        let end = min(start + max(min(limit, 200), 1), chosen.count)
        var out: [String: Any] = [
            "total": keys.count, "matching": chosen.count, "offset": start, "keys": Array(chosen[start..<end]),
            "providers": object["providers"] ?? [],
        ]
        if end < chosen.count { out["next_offset"] = end }
        return try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
    }

    /// What a proposal asks that will not happen, told to the agent at once instead of left undone in silence.
    public static func notes(for changes: [[String: Any]], inventory data: Data) -> [String] {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keys = object["keys"] as? [[String: Any]]
        else { return [] }
        let rows = Dictionary(keys.compactMap { row in (row["path"] as? String).map { ($0, row) } }, uniquingKeysWith: { a, _ in a })
        let known = Set(((object["providers"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String })
        var notes: [String] = []
        for change in changes {
            guard let path = change["path"] as? String, let row = rows[path] else { continue }
            let provider = change["provider"] as? String ?? row["provider"] as? String
            if change["kind"] as? String == "provider", let id = change["provider"] as? String, !known.contains(id) {
                notes.append("\(path): no provider \(id) is known, so it stays as it was")
            }
            if let field = change["field"] as? String, !((row["fields"] as? [String]) ?? []).contains(field) {
                notes.append("\(path): the file has no field \(field)")
            }
            if change["check"] as? Bool == true {
                switch row["level"] as? String {
                case "never"?: notes.append("\(path): set to Only me, so it is not checked without the person")
                case "none"?: notes.append("\(path): not a secret, so there is nothing to check")
                default:
                    if provider == nil { notes.append("\(path): no provider, so it cannot be checked") }
                    if row["needs_host"] as? Bool == true, change["host"] == nil {
                        notes.append("\(path): its provider runs on the person's own server; give host to check it")
                    }
                }
            }
            if let host = change["host"] as? String, !host.hasPrefix("https://") {
                notes.append("\(path): host must start with https://")
            }
        }
        return notes
    }

    public static func proposalFile(id: String, home: URL) -> URL {
        home.appendingPathComponent(proposalsFolderName).appendingPathComponent("\(id).json")
    }

    public static func save(_ data: Data, id: String, home: URL) throws {
        try PrivateFile.write(data, to: proposalFile(id: id, home: home))
    }

    public static func load(id: String, home: URL) -> Data? {
        // Ids come from the requests file; only one of keyreeve's own names is read.
        guard id.hasPrefix("r-"), id.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else { return nil }
        return try? Data(contentsOf: proposalFile(id: id, home: home))
    }
}
