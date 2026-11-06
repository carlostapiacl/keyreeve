import AppKit
import KeyreeveCatalog
import KeyreeveVault

/// A person taking a key out by hand, and what agents may do with one.
@MainActor
extension AppModel {
    /// `field` nil means the file's one value, and `wholeFile` the file as it is.
    public func copyKey(_ item: CatalogItem, field: String?, wholeFile: Bool = false) {
        guard !busy, item.vault == .sealed || item.vault == .outdated else { return }
        openVault(reason: T("copy a key to the clipboard")) { unlocked in
            guard let unlocked else {
                self.message = T("Not copied: it was not confirmed")
                return
            }
            let store = self.vaultStore
            let epoch = self.lockEpoch
            let name = item.path
            self.busy = true
            Task.detached {
                let result = Result { () throws -> String in
                    let sealed = try store.load().open(name: name, with: try unlocked.recipient(store))
                    store.recordUse(of: name, by: "copy")
                    return wholeFile
                        ? String(decoding: sealed, as: UTF8.self)
                        : try EnvReferences.value(in: sealed, field: field)
                }
                await MainActor.run {
                    self.busy = false
                    guard epoch == self.lockEpoch else { return }
                    switch result {
                    case .success(let value):
                        self.clipboard.copy(value)
                        self.message = T("Copied. It leaves the clipboard in %d seconds.", KeyClipboard.seconds)
                        let copied = self.clipboard.ours
                        Task {
                            try? await Task.sleep(for: .seconds(KeyClipboard.seconds))
                            if self.clipboard.ours == copied { self.clearClipboardNow() }
                        }
                    case .failure:
                        self.message =
                            field != nil
                            ? T("That field was not found. Try the whole file.")
                            : T("This file has several lines, so choose what to copy.")
                    }
                }
            }
        }
    }

    func clearClipboardNow() { clipboard.clear() }

    /// Locking the app ends what the key service holds too. If it is not running, nothing is lost.
    func closeServicePermissions() {
        let path = files.keySocket.path
        Task.detached { _ = try? KeySocket.send(KeyService.Request(op: "revoke"), path: path, timeout: 2) }
    }

    private func provider(of item: CatalogItem) -> ProviderInfo? {
        item.recipes.first.flatMap { id in providers.all.first { $0.id == id } }
    }

    private func project(of item: CatalogItem) -> String? {
        item.tags.first { !$0.contains(":") && !["confirm", "internal", "revoke", "compartido", "infra"].contains($0) }
            ?? item.tags.first { !$0.contains(":") && !["confirm", "internal", "revoke", "compartido"].contains($0) }
    }

    /// What the provider said when asked whose key this is.
    public func account(of item: CatalogItem) -> String? {
        item.details?.fields["account"] ?? item.details?.fields["email"]
    }

    public func suggestedIdentifier(for item: CatalogItem) -> String {
        keyIndex.suggestion(provider: item.recipes.first, project: project(of: item), account: account(of: item), source: item.path)
    }

    public func setAccount(_ text: String, of id: String) {
        var index = keyIndex
        guard let at = index.keys.firstIndex(where: { $0.id == id }) else { return }
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        index.keys[at].account = clean.isEmpty ? nil : clean
        try? saveIndex(index)
    }

    public func addIdentifier(_ id: String, for item: CatalogItem, field: String?) {
        var index = keyIndex
        let provider = provider(of: item)
        do {
            try index.add(
                KeyIndex.Key(
                    id: id, source: item.path, field: field ?? (item.field.isEmpty ? nil : item.field),
                    provider: item.recipes.first, project: project(of: item), account: account(of: item),
                    description: item.description.isEmpty ? nil : item.description, variable: provider?.env_var))
            try saveIndex(index)
        } catch {
            message = (error as? VaultError)?.description ?? T("That identifier could not be saved")
        }
    }

    public func removeIdentifier(_ id: String) {
        var index = keyIndex
        index.remove(id: id)
        try? saveIndex(index)
    }

    /// Gives one to each sealed key that has none, which a person can change afterwards.
    public func assignIdentifiers() {
        var index = keyIndex
        var added = 0
        for item in items where item.vault == .sealed || item.vault == .outdated {
            // A key that got its identifier before its account was known picks it up here.
            for existing in index.keys(forSource: item.path) where existing.account == nil {
                if let found = account(of: item), let at = index.keys.firstIndex(where: { $0.id == existing.id }) {
                    index.keys[at].account = found
                }
            }
            guard index.keys(forSource: item.path).isEmpty else { continue }
            let id = index.suggestion(
                provider: item.recipes.first, project: project(of: item), account: account(of: item), source: item.path)
            try? index.add(
                KeyIndex.Key(
                    id: id, source: item.path, field: item.field.isEmpty ? nil : item.field, provider: item.recipes.first,
                    project: project(of: item), account: account(of: item),
                    description: item.description.isEmpty ? nil : item.description, variable: provider(of: item)?.env_var))
            added += 1
        }
        do {
            try saveIndex(index)
            message = added == 1 ? T("1 identifier added") : T("%d identifiers added", added)
        } catch {
            message = T("That identifier could not be saved")
        }
    }

    private func saveIndex(_ index: KeyIndex) throws {
        try files.writePrivate(Data(index.toml.utf8), to: files.keyIndex)
        keyIndex = index
    }

    public func allow(program: String, for item: CatalogItem) {
        guard !AgentPolicy.isNeverAllowed(program) else {
            message = T("%@ can print or send whatever it gets, so it cannot be allowed.", URL(fileURLWithPath: program).lastPathComponent)
            return
        }
        guard let id = keyIndex.keys(forSource: item.path).first?.id else { return }
        var policy = agentPolicy
        if !(policy.commands[id] ?? []).contains(program) { policy.commands[id, default: []].append(program) }
        savePolicy(policy)
    }

    public func disallow(program: String, for item: CatalogItem) {
        var policy = agentPolicy
        for key in keyIndex.keys(forSource: item.path) { policy.commands[key.id]?.removeAll { $0 == program } }
        savePolicy(policy)
    }

    private func savePolicy(_ policy: AgentPolicy) {
        do {
            try files.writePrivate(Data(policy.toml.utf8), to: files.agents)
            agentPolicy = policy
        } catch {
            message = T("The permissions could not be saved")
        }
    }

    public func chooseProgram(then: (String) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        panel.message = T("Choose the program an agent may run with this key")
        panel.prompt = T("Choose")
        if panel.runModal() == .OK, let url = panel.url { then(url.path) }
    }

    /// The command that connects Claude Code, on the clipboard. It holds a path and no key.
    public func copyAgentCommand() {
        let tool = (binary?.deletingLastPathComponent().appendingPathComponent("keyreeve-vault").path ?? "keyreeve-vault")
        let board = NSPasteboard.general
        board.clearContents()
        board.setString("claude mcp add keyreeve -- \"\(tool)\" mcp", forType: .string)
        message = T("The command to connect Claude Code is copied. Run it in a terminal.")
    }
}
