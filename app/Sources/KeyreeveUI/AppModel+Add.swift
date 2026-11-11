import AppKit
import KeyreeveCatalog
import KeyreeveVault

/// A key pasted from the clipboard: it goes straight into the vault, with no file in the keys folder.
public struct AddKeyDraft: Identifiable {
    public let id = UUID()
    /// When an agent asked for this provider and no file had one.
    public var request: AccessRequests.Entry?
    /// Nil is a key of no known provider, such as a secret of your own app. It is kept and can be used,
    /// and cannot be checked or go through the proxy until a provider is set.
    public var provider: String?
    /// The person's own words, kept as the key's description. The identifier is made from it.
    public var name = ""
    /// Held only while the sheet is open, and never shown.
    var value: String?
    /// A whole file chosen instead, such as a keystore or a certificate, sealed byte for byte. Never shown.
    var file: Data?
    /// The chosen file's name, shown so the person sees which one goes in.
    public var fileName: String?
    /// Whether there is something to save, pasted or chosen.
    public var hasValue: Bool { value != nil || file != nil }
    public var hint: String?
    /// What went wrong, shown in the sheet itself, next to what caused it.
    public var error: String?
}

@MainActor
extension AppModel {
    /// Keys pasted in the app live in the vault under this folder name, which no keys folder uses.
    nonisolated static let addedFolder = "added/"

    public func startAddingKey(for request: AccessRequests.Entry? = nil) {
        var draft = AddKeyDraft(request: request, provider: request?.provider)
        if let provider = request?.provider { draft.name = providerName(provider) }
        addingKey = draft
    }

    /// Reads the clipboard into the draft, and names the provider if the key's start says which.
    public func pasteKey() {
        guard var draft = addingKey else { return }
        let text = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !text.isEmpty else {
            draft.error = T("The clipboard holds no text")
            addingKey = draft
            return
        }
        let found = providers.recognize(text)
        if draft.request == nil, let found {
            draft.provider = found.id
            if draft.name.isEmpty { draft.name = found.name }
        }
        draft.error = nil
        draft.value = text
        draft.file = nil
        draft.fileName = nil
        draft.hint = ProviderDirectory.hint(of: text, provider: found)
        addingKey = draft
    }

    /// Reads a whole file into the draft, for a key that is a file and lives outside the keys folder, such as a
    /// `.jks` keystore or a `.pfx` certificate. It is sealed as it is; the file is only read, never moved.
    public func chooseKeyFile() {
        guard var draft = addingKey else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = T("Choose the file to seal, such as a keystore or a certificate. It stays where it is.")
        panel.prompt = T("Seal this file")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        switch VaultKeeper.readFile(at: url) {
        case .success(let data):
            draft.file = data
            draft.fileName = url.lastPathComponent
            draft.value = nil
            draft.error = nil
            draft.hint = T("%@, %@", url.lastPathComponent, ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file))
            if draft.name.isEmpty { draft.name = url.deletingPathExtension().lastPathComponent }
        case .failure(.tooLarge): draft.error = T("That file is larger than 1 MB")
        case .failure(.empty): draft.error = T("That file is empty")
        case .failure: draft.error = T("That file could not be read")
        }
        addingKey = draft
    }

    /// How a provider is called, from its recipe.
    public func providerName(_ id: String) -> String { providers.all.first { $0.id == id }?.name ?? id }

    /// The identifier a name will be saved under: free, valid, and shown before saving.
    public func identifier(for name: String) -> String { keyIndex.identifier(for: name) }

    /// Seals the pasted key, gives it its identifier, and, when an agent asked, opens it to that agent.
    public func saveAddedKey(hours: Int?) {
        guard var draft = addingKey, let data = draft.file ?? draft.value.map({ Data($0.utf8) }) else { return }
        let name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            draft.error = T("Give it a name")
            addingKey = draft
            return
        }
        let provider = draft.provider
        do {
            // A keys.toml that is there and cannot be read stops this: written from memory, it could lose keys.
            var index = FileManager.default.fileExists(atPath: files.keyIndex.path) ? try KeyIndex.load(from: files.keyIndex) : keyIndex
            let base = index
            let id = index.identifier(for: name)
            let entry = Self.addedFolder + id
            // The name is checked before anything is sealed, so a bad one leaves nothing behind.
            var key = KeyIndex.Key(
                id: id, source: entry, provider: provider, description: name == id ? nil : name,
                variable: provider.flatMap { provider in providers.all.first { $0.id == provider }?.env_var })
            key.more.addedBy = KeyArrival.byPerson
            key.more.addedAt = KeyArrival.stamp()
            try index.add(key)
            var saved = index
            // Only this key is written, onto keys.toml as it is now, under the lock keyreeve-vault takes too.
            try Self.savePasted(data, as: entry, index: index, store: vaultStore) { _ in
                saved = try KeyIndex.save(index, from: base, at: self.files.keyIndex)
            }
            keyIndex = saved
            audit([(id, draft.fileName.map { "from the file \($0)" } ?? "pasted, \(provider ?? "no provider")")], event: "sealed")
            if let request = draft.request { try openToAgent(id, for: request, hours: hours) }
            // The clipboard keeps nothing that was a key.
            if let value = draft.value,
                NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines) == value
            {
                NSPasteboard.general.clearContents()
            }
            addingKey = nil
            message = draft.request == nil ? T("%@ is saved", id) : T("%@ is saved and open to %@", id, draft.request!.agent)
        } catch {
            // Said in the sheet, which stays open with the key, so it can be tried again.
            draft.error = (error as? VaultError)?.description ?? T("The vault could not be saved")
            addingKey = draft
            return
        }
        load()
    }

    /// Seals a pasted key and writes keys.toml as one step. If keys.toml cannot be written, the copy just sealed
    /// is taken out again, so the key is not left in the vault with no name and trying again starts clean.
    nonisolated static func savePasted(
        _ value: Data, as entry: String, index: KeyIndex, store: VaultStore, writeIndex: (Data) throws -> Void
    ) throws {
        try store.update { vault in try vault.add(name: entry, value: value) }
        do {
            try writeIndex(Data(index.toml.utf8))
        } catch {
            do {
                try store.update { vault in vault.entries[entry] = nil }
            } catch {
                throw VaultError("\(entry) was sealed but keys.toml could not be written, and it could not be taken out again")
            }
            throw VaultError("keys.toml could not be written, so the key was not saved. Nothing was left behind: try again")
        }
    }

    /// Drops the pasted key, and clears the clipboard if it still holds it.
    public func cancelAddingKey() {
        if let value = addingKey?.value,
            NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines) == value
        {
            NSPasteboard.general.clearContents()
        }
        addingKey = nil
    }

    /// The page where this provider's keys are made, from its recipe.
    public func dashboard(of provider: String?) -> URL? {
        providers.all.first { $0.id == provider }?.dashboard.flatMap(URL.init(string:))
    }
}
