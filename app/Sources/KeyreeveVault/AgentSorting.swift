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
