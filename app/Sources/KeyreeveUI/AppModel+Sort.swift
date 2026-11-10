import Foundation
import KeyreeveCatalog
import KeyreeveVault

@MainActor
extension AppModel {
    /// What keyreeve can propose for keys it cannot check yet, from tags and field names alone.
    public var sortSuggestions: [Suggestion] { Suggester.suggest(items, providers: providers) }

    /// Keys still with nothing to propose, which an assistant may be asked about.
    public var unsortedKeys: [CatalogItem] {
        let proposed = Set(sortSuggestions.map(\.path))
        return items.filter { $0.recipes.isEmpty && !$0.isArchived && !$0.isInternal && !$0.isUntestable && $0.isSecret && !proposed.contains($0.path) }
    }

    /// Saves the chosen suggestions in one write, then rebuilds the list once. `fillingOnly` is for suggestions
    /// the person did not write, an assistant's or keyreeve's own: they only fill what a key lacks.
    public func apply(_ suggestions: [Suggestion], fillingOnly: Bool = false) {
        let byPath = Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var edits: [String: KeyEdit] = [:]
        for suggestion in suggestions {
            guard let item = byPath[suggestion.path] else { continue }
            let edit = suggestion.edit(for: item, fillingOnly: fillingOnly)
            if edit != KeyEdit() { edits[suggestion.path] = edit }
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

extension AppModel {
    /// Names the field that holds the key, in a file with several. The next check reads that one.
    public func setField(_ field: String, for item: CatalogItem) {
        save(KeyEdit(field: field), for: item)
        message = T("Field saved: %@. Check the key to see if it works.", field)
    }

    /// Gives each key of a file of notes a file of its own beside it, private and with the same provider and
    /// tags, and moves the old file to keyreeve's originals folder. Nothing is deleted. Returns the new files'
    /// names, or nil when nothing was split.
    @discardableResult
    public func split(_ item: CatalogItem) -> [String]? {
        guard let folder = keysFolder, let provider = item.recipes.first,
            let prefixes = providers.all.first(where: { $0.id == provider })?.prefixes, !prefixes.isEmpty
        else {
            message = T("Only a provider whose keys have a known start can be split")
            return nil
        }
        let source = folder.appendingPathComponent(item.path)
        // Splitting writes one file per key from the file itself; a key kept only in the vault has none here.
        guard FileManager.default.fileExists(atPath: source.path) else {
            message = T("%@ is not in the keys folder, so it cannot be split", item.path)
            return nil
        }
        guard let size = (try? FileManager.default.attributesOfItem(atPath: source.path))?[.size] as? Int, size < 1_048_576,
            let text = try? String(contentsOf: source, encoding: .utf8)
        else {
            message = T("That file could not be read as text, so it was not saved")
            return nil
        }
        let others = providers.all.filter { $0.id != provider }.flatMap { $0.prefixes ?? [] }
        let keys = KeySplit.keys(in: text, prefixes: prefixes, others: others)
        guard keys.count > 1 else {
            message = T("This file holds one key, so there is nothing to split")
            return nil
        }
        let names = KeySplit.names(for: item.path, count: keys.count) {
            FileManager.default.fileExists(atPath: folder.appendingPathComponent($0).path)
        }
        let day = DateFormatter()
        day.locale = Locale(identifier: "en_US_POSIX")
        day.dateFormat = "yyyy-MM-dd"
        let target = files.originals.appendingPathComponent("\(day.string(from: Date()))-split").appendingPathComponent(item.path)
        do {
            try Self.splitFiles(source: source, keys: keys, into: names.map(folder.appendingPathComponent), movingTo: target, originals: files.originals)
        } catch {
            message = (error as? VaultError)?.description ?? T("The files could not be moved")
            refresh()
            return nil
        }
        // The files are made and the original moved: what is left is the list's tags, which can be set again.
        var edits: [String: KeyEdit] = [:]
        for name in names {
            edits[name] = KeyEdit(tags: item.tags, recipes: [provider], description: item.description.isEmpty ? nil : item.description)
        }
        note("split", path: item.path, detail: names.joined(separator: ", "))
        do {
            try files.saveEdits(edits)
            message = T("%d files made. The old one is in %@", names.count, target.deletingLastPathComponent().path)
        } catch {
            message = T("%d files made, but their tags could not be saved. The old one is in %@", names.count, target.deletingLastPathComponent().path)
        }
        refresh()
        return names
    }

    /// Writes one file per key and moves the original away, all or nothing: if a file cannot be written or the
    /// original cannot be moved, the new files are taken out again and the original stays where it was.
    nonisolated static func splitFiles(source: URL, keys: [String], into outputs: [URL], movingTo target: URL, originals: URL) throws {
        var made: [URL] = []
        func undo() { for url in made { try? FileManager.default.removeItem(at: url) } }
        do {
            for (url, key) in zip(outputs, keys) {
                guard !FileManager.default.fileExists(atPath: url.path) else {
                    throw VaultError("\(url.lastPathComponent) is already there, so nothing was split")
                }
                try PrivateFile.write(Data((key + "\n").utf8), to: url)
                made.append(url)
            }
            guard !FileManager.default.fileExists(atPath: target.path) else {
                throw VaultError("\(target.path) is already there, so nothing was split")
            }
            try PrivateFile.folder(originals)
            try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.moveItem(at: source, to: target)
        } catch {
            undo()
            throw error as? VaultError ?? VaultError("the files could not be made or moved, so nothing was split and the file is where it was")
        }
    }
}
