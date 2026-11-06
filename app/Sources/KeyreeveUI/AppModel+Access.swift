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

    public func allow(program: String, for item: CatalogItem) {
        guard !AgentPolicy.isNeverAllowed(program) else {
            message = T("%@ can print or send whatever it gets, so it cannot be allowed.", URL(fileURLWithPath: program).lastPathComponent)
            return
        }
        var policy = agentPolicy
        if !(policy.commands[item.path] ?? []).contains(program) { policy.commands[item.path, default: []].append(program) }
        savePolicy(policy)
    }

    public func disallow(program: String, for item: CatalogItem) {
        var policy = agentPolicy
        policy.commands[item.path]?.removeAll { $0 == program }
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
