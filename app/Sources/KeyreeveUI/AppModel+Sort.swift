import Foundation
import KeyreeveCatalog

@MainActor
extension AppModel {
    /// What keyreeve can propose for keys it cannot check yet, from tags and field names alone.
    public var sortSuggestions: [Suggestion] { Suggester.suggest(items, providers: providers) }

    /// Keys still with nothing to propose, which an assistant may be asked about.
    public var unsortedKeys: [CatalogItem] {
        let proposed = Set(sortSuggestions.map(\.path))
        return items.filter { $0.recipes.isEmpty && !$0.isArchived && !$0.isInternal && !$0.isUntestable && $0.isSecret && !proposed.contains($0.path) }
    }

    /// Saves the chosen suggestions in one write, then rebuilds the list once.
    public func apply(_ suggestions: [Suggestion]) {
        let byPath = Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var edits: [String: KeyEdit] = [:]
        for suggestion in suggestions {
            guard let item = byPath[suggestion.path] else { continue }
            edits[suggestion.path] = suggestion.edit(for: item)
        }
        guard !edits.isEmpty else { return }
        do {
            try files.saveEdits(edits)
        } catch {
            message = (error as? CheckError)?.description ?? T("%@ could not be saved", files.edits.lastPathComponent)
            return
        }
        message = edits.count == 1 ? T("1 key sorted") : T("%d keys sorted", edits.count)
        rebuildCatalog()
    }

    /// Gives several chosen keys one provider at once.
    public func assign(provider id: String, to chosen: [CatalogItem]) {
        apply(chosen.map { item in
            let field = providers.all.first { $0.id == id }.flatMap { Suggester.field(in: item, for: $0) }
            return Suggestion(path: item.path, kind: .provider(id, field: field), why: "chosen")
        })
    }

    public func markUntestable(_ chosen: [CatalogItem]) {
        apply(chosen.map { Suggestion(path: $0.path, kind: .untestable, why: "chosen") })
    }
}
