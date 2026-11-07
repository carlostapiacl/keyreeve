import AppKit
import KeyreeveCatalog
import KeyreeveVault

/// A key pasted from the clipboard: it goes straight into the vault, with no file in the keys folder.
public struct AddKeyDraft: Identifiable {
    public let id = UUID()
    /// When an agent asked for this provider and no file had one.
    public var request: AccessRequests.Entry?
    public var provider: String?
    public var name = ""
    /// Held only while the sheet is open, and never shown.
    var value: String?
    public var hint: String?
}

@MainActor
extension AppModel {
    /// Keys pasted in the app live in the vault under this folder name, which no keys folder uses.
    nonisolated static let addedFolder = "added/"

    public func startAddingKey(for request: AccessRequests.Entry? = nil) {
        var draft = AddKeyDraft(request: request, provider: request?.provider)
        if let provider = request?.provider { draft.name = freeIdentifier(provider) }
        addingKey = draft
    }

    /// Reads the clipboard into the draft, and names the provider if the key's start says which.
    public func pasteKey() {
        guard var draft = addingKey else { return }
        let text = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !text.isEmpty else {
            message = T("The clipboard holds no text")
            return
        }
        let found = providers.recognize(text)
        if draft.request == nil, let found {
            draft.provider = found.id
            if draft.name.isEmpty { draft.name = freeIdentifier(found.id) }
        }
        draft.value = text
        draft.hint = ProviderDirectory.hint(of: text, provider: found)
        addingKey = draft
    }

    /// A provider's name, or the same with a number when that identifier is taken.
    public func freeIdentifier(_ base: String) -> String {
        let taken = Set(keyIndex.keys.map(\.id))
        if !taken.contains(base) { return base }
        return (2...).lazy.map { "\(base)-\($0)" }.first { !taken.contains($0) }!
    }

    /// Seals the pasted key, gives it its identifier, and, when an agent asked, opens it to that agent.
    public func saveAddedKey(hours: Int?) {
        guard let draft = addingKey, let value = draft.value, let provider = draft.provider else { return }
        let id = draft.name.trimmingCharacters(in: .whitespaces)
        guard !id.isEmpty else { return }
        let entry = Self.addedFolder + id
        do {
            var index = (try? KeyIndex.load(from: files.keyIndex)) ?? keyIndex
            guard index.key(id) == nil else {
                message = T("%@ is taken. Choose another name.", id)
                return
            }
            // The name is checked before anything is sealed, so a bad one leaves nothing behind.
            try index.add(KeyIndex.Key(
                id: id, source: entry, provider: provider,
                variable: providers.all.first { $0.id == provider }?.env_var))
            try vaultStore.update { vault in try vault.add(name: entry, value: Data(value.utf8)) }
            try files.writePrivate(Data(index.toml.utf8), to: files.keyIndex)
            keyIndex = index
            audit([(id, "pasted, \(provider)")], event: "sealed")
            if let request = draft.request { try openToAgent(id, for: request, hours: hours) }
            // The clipboard keeps nothing that was a key.
            if NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines) == value {
                NSPasteboard.general.clearContents()
            }
            addingKey = nil
            message = draft.request == nil ? T("%@ is saved", id) : T("%@ is saved and open to %@", id, draft.request!.agent)
        } catch {
            message = (error as? VaultError)?.description ?? T("The vault could not be saved")
        }
        load()
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
