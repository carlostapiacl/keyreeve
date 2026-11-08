import Foundation

/// An agent's proposal to sort many keys, read with the same rules as an assistant's answer in Sort keys:
/// only files the list has, providers keyreeve knows and fields the file holds. Seal, check and archive
/// are asked per file, and only for files in the list.
public struct SortProposal: Sendable {
    public var suggestions: [Suggestion] = []
    public var seal: Set<String> = []
    public var check: Set<String> = []
    public var archive: Set<String> = []
    public var split: Set<String> = []
    /// The server of a provider that runs on the person's own, only over https.
    public var hosts: [String: String] = [:]
    /// Every file it touches, in the order the agent gave them.
    public var paths: [String] = []

    public init() {}

    public static func read(_ data: Data, items: [CatalogItem], providers: ProviderDirectory) -> SortProposal {
        var proposal = SortProposal()
        guard let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return proposal }
        let known = Set(items.map(\.path))
        proposal.suggestions = Suggester.read(String(decoding: data, as: UTF8.self), items: items, providers: providers)
        for row in rows {
            guard let path = row["path"] as? String, known.contains(path) else { continue }
            if row["seal"] as? Bool == true { proposal.seal.insert(path) }
            if row["check"] as? Bool == true { proposal.check.insert(path) }
            if row["archive"] as? Bool == true { proposal.archive.insert(path) }
            if row["split"] as? Bool == true { proposal.split.insert(path) }
            if let host = row["host"] as? String, let url = URL(string: host), url.scheme == "https", url.host != nil {
                proposal.hosts[path] = host
            }
        }
        let touched = Set(proposal.suggestions.map(\.path)).union(proposal.seal).union(proposal.check).union(proposal.archive)
            .union(proposal.split).union(proposal.hosts.keys)
        var seen = Set<String>()
        proposal.paths = rows.compactMap { $0["path"] as? String }.filter { touched.contains($0) && seen.insert($0).inserted }
        return proposal
    }

    public func suggestion(for path: String) -> Suggestion? { suggestions.first { $0.path == path } }
}

extension CatalogItem {
    /// This key as an edit would leave it, for work that follows the edit before the list is read again.
    public func applying(_ edit: KeyEdit) -> CatalogItem {
        var item = self
        if let tags = edit.tags { item.tags = tags }
        if let level = edit.level { item.level = level }
        if let recipes = edit.recipes { item.recipes = recipes }
        if let field = edit.field { item.field = field }
        if let description = edit.description { item.description = description }
        if let host = edit.host { item.host = host }
        return item
    }
}
