import AppKit
import KeyreeveCatalog

@MainActor
extension AppModel {
    public func actionsFor(_ item: CatalogItem) -> [KeyAction] { actions(for: item, providers: providers) }

    public func perform(_ action: KeyAction, on item: CatalogItem) {
        switch action {
        case .openProvider(let url):
            NSWorkspace.shared.open(url)
        case .confirmRevoked:
            check([item]) { self.finishRevocation(of: item) }
        case .markRevoked:
            setDone(item, tag: "status:revoked")
            message = T("You marked it as revoked")
        case .checkAgain:
            check([item])
        case .notInUse:
            setDone(item, tag: "status:retired")
        case .fixPermissions:
            guard let folder = keysFolder else { return }
            do {
                try files.fixPermissions(of: item.path, in: folder)
                message = T("Permissions fixed")
                refresh()
            } catch {
                message = T("The scan did not finish")
            }
        case .ignore:
            do {
                try files.ignore(item.path, until: Date().addingTimeInterval(30 * 86_400))
            } catch {
                message = (error as? CheckError)?.description ?? T("%@ could not be saved", files.ignored.lastPathComponent)
                return
            }
            load()
        }
    }

    public func archive(_ item: CatalogItem) {
        save(KeyEdit(tags: item.tags + ["status:archived"]), for: item)
    }

    public func restore(_ item: CatalogItem) {
        save(KeyEdit(tags: item.tags.filter { $0 != "status:archived" }), for: item)
    }

    func finishRevocation(of item: CatalogItem) {
        guard let fresh = items.first(where: { $0.path == item.path }) else { return }
        if fresh.lastResult == "rejected" {
            setDone(fresh, tag: "status:revoked")
            message = T("Revoked: the provider rejects it now")
        } else {
            message = T("It still works: revoke it at the provider")
        }
    }

    func setDone(_ item: CatalogItem, tag: String) {
        let tags = item.tags.filter { $0 != "revoke" } + [tag]
        save(KeyEdit(tags: tags), for: item)
    }

    /// The list changes only once the change is on disk; a failure says why and changes nothing.
    public func save(_ edit: KeyEdit, for item: CatalogItem) {
        do {
            try files.saveEdit(edit, for: item.path)
        } catch {
            message = (error as? CheckError)?.description ?? T("%@ could not be saved", files.edits.lastPathComponent)
            return
        }
        rebuildCatalog()
    }
}
