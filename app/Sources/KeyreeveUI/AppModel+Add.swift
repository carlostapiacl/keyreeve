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
        draft.hint = ProviderDirectory.hint(of: text, provider: found)
        addingKey = draft
    }

    /// How a provider is called, from its recipe.
    public func providerName(_ id: String) -> String { providers.all.first { $0.id == id }?.name ?? id }

    /// The identifier a name will be saved under: free, valid, and shown before saving.
    public func identifier(for name: String) -> String { keyIndex.identifier(for: name) }

    /// Seals the pasted key, gives it its identifier, and, when an agent asked, opens it to that agent.
    public func saveAddedKey(hours: Int?) {
        guard var draft = addingKey, let value = draft.value else { return }
        let name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            draft.error = T("Give it a name")
            addingKey = draft
            return
        }
        let provider = draft.provider
        do {
            var index = (try? KeyIndex.load(from: files.keyIndex)) ?? keyIndex
            let id = index.identifier(for: name)
            let entry = Self.addedFolder + id
            // The name is checked before anything is sealed, so a bad one leaves nothing behind.
            try index.add(KeyIndex.Key(
                id: id, source: entry, provider: provider, description: name == id ? nil : name,
                variable: provider.flatMap { provider in providers.all.first { $0.id == provider }?.env_var }))
            try vaultStore.update { vault in try vault.add(name: entry, value: Data(value.utf8)) }
            try files.writePrivate(Data(index.toml.utf8), to: files.keyIndex)
            keyIndex = index
            audit([(id, "pasted, \(provider ?? "no provider")")], event: "sealed")
            if let request = draft.request { try openToAgent(id, for: request, hours: hours) }
            // The clipboard keeps nothing that was a key.
            if NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines) == value {
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
