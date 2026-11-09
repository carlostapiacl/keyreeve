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
                        self.note("copied", path: name, detail: "to the clipboard")
                        self.reloadUsage()
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

    // MARK: Usage

    /// Names a file by its identifier when it has one, so the log reads the same from every side.
    func auditName(of path: String) -> String { keyIndex.keys(forSource: path).first?.id ?? path }

    func note(_ event: String, path: String, detail: String? = nil) {
        try? AuditLog(url: files.audit).append(event: event, key: auditName(of: path), detail: detail)
    }

    public func reloadUsage() {
        guard unlocked else { return }
        let files = self.files
        let epoch = lockEpoch
        Task.detached {
            let usage = UsageSnapshot(files: files)
            await MainActor.run {
                guard epoch == self.lockEpoch else { return }
                self.usage = usage
            }
        }
    }

    /// Opens a permission through the same command an agent would use, so the service asks for your finger.
    public func grant(_ key: KeyIndex.Key, program: String?, duration: String) {
        guard let tool = vaultTool else { return }
        offerIfWaiting(key.id)
        var arguments = ["grant", key.id, "--for", duration]
        if let program { arguments += ["--program", URL(fileURLWithPath: program).lastPathComponent] }
        message = T("Touch the sensor to give this permission.")
        Task.detached {
            let process = Process()
            process.executableURL = tool
            process.arguments = arguments
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            let started = (try? process.run()) != nil
            if started { process.waitUntilExit() }
            let done = started && process.terminationStatus == 0
            await MainActor.run {
                self.message = done ? T("Permission given.") : T("No permission was given.")
                self.reloadUsage()
            }
        }
    }

    /// Ends one permission, or with no grant every permission for the key.
    public func endPermissions(of key: String, grant: String? = nil) {
        revoke(key: key, grant: grant)
    }

    /// Ends permissions in the key service and waits for its word. Sent is not done: until the service says
    /// so, a permission may still be in force, and the window says that rather than showing it ended.
    func revoke(key: String? = nil, grant: String? = nil) {
        let path = files.keySocket.path
        Task.detached {
            let confirmed = Self.revokeConfirmed(key: key, grant: grant, socket: path)
            await MainActor.run {
                if !confirmed {
                    self.message = T("Keyreeve could not confirm that the permissions ended. Quitting Keyreeve ends them all.")
                }
                self.reloadUsage()
            }
        }
    }

    /// True once the service said the permissions ended, or when no service runs and so none can be in force.
    nonisolated static func revokeConfirmed(
        key: String?, grant: String?, socket: String, tries: Int = 3, send: (KeyService.Request) throws -> KeyService.Response? = { _ in nil }
    ) -> Bool {
        guard FileManager.default.fileExists(atPath: socket) else { return true }
        let request = KeyService.Request(op: "revoke", key: key, grant: grant)
        for attempt in 0..<tries {
            if attempt > 0 { usleep(500_000) }
            if let answer = (try? send(request)) ?? (try? KeySocket.send(request, path: socket, timeout: 2)), answer.ok { return true }
        }
        return false
    }

    /// Locking the app ends what the key service holds too. If it is not running, nothing is lost.
    func closeServicePermissions() {
        AgentBridge.endAll(home: files.directory)
        revoke()
    }

    /// Writes what the person decided, so the usage log has every side of it.
    func audit(_ changes: [(key: String, detail: String)], event: String = "policy") {
        let log = AuditLog(url: files.audit)
        for change in changes { try? log.append(event: event, key: change.key, detail: change.detail) }
    }

    /// The emergency stop: ends every permission, pauses every agent and locks the window.
    /// It waits for the service's answer, at most two seconds, and says so if anything did not take: an
    /// emergency stop that only looks done is worse than one that says it failed.
    public func lockEverything() {
        AgentBridge.setPaused(true, home: files.directory)
        let paused = AgentBridge.isPaused(home: files.directory)
        agentsPaused = paused
        AgentBridge.endAll(home: files.directory)
        let socket = files.keySocket.path
        // No service running means no permission is open.
        let revoked = !KeySocket.isListening(path: socket)
            || (try? KeySocket.send(KeyService.Request(op: "revoke"), path: socket, timeout: 2))?.ok == true
        audit([("-", paused && revoked ? "every permission ended and agents paused"
            : "incomplete: paused \(paused), permissions ended \(revoked)")], event: "paused")
        lock()
        message = paused && revoked
            ? T("Everything is locked and agents are paused")
            : T("Lock everything did not finish. Quit Keyreeve to end every permission.")
    }

    public func resumeAgents() {
        audit([("-", "agents may ask again")], event: "resumed")
        AgentBridge.setPaused(false, home: files.directory)
        agentsPaused = false
        message = T("Agents may ask again")
    }

    /// Quitting ends them. It waits, since the app is gone once this returns.
    public func closeServicePermissionsBeforeQuitting() {
        AgentBridge.endAll(home: files.directory)
        _ = try? KeySocket.send(KeyService.Request(op: "revoke"), path: files.keySocket.path, timeout: 2)
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
        guard index.isTaken(id) else { return }
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        index.update(id: id) { $0.account = clean.isEmpty ? nil : clean }
        do {
            try saveIndex(index)
        } catch {
            message = T("That identifier could not be saved")
        }
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
        do {
            try saveIndex(index)
        } catch {
            message = T("That identifier could not be saved")
        }
    }

    /// Gives one to each sealed key that has none, which a person can change afterwards. None of them is offered
    /// to agents: a click for every key is not a person choosing which keys agents may see.
    public func assignIdentifiers() {
        var index = keyIndex
        var added = 0
        for item in items where item.vault == .sealed || item.vault == .outdated {
            // A key that got its identifier before its account was known picks it up here.
            if let found = account(of: item) {
                for existing in index.allKeys(forSource: item.path) where existing.account == nil {
                    index.update(id: existing.id) { $0.account = found }
                }
            }
            guard index.allKeys(forSource: item.path).isEmpty else { continue }
            let id = index.suggestion(
                provider: item.recipes.first, project: project(of: item), account: account(of: item), source: item.path)
            try? index.addUnoffered(
                KeyIndex.Key(
                    id: id, source: item.path, field: item.field.isEmpty ? nil : item.field, provider: item.recipes.first,
                    project: project(of: item), account: account(of: item),
                    description: item.description.isEmpty ? nil : item.description, variable: provider(of: item)?.env_var))
            added += 1
        }
        do {
            try saveIndex(index)
            message = added == 1
                ? T("1 identifier added, not offered to agents")
                : T("%d identifiers added, not offered to agents", added)
        } catch {
            message = T("That identifier could not be saved")
        }
    }

    /// Offers a key to agents, so they can see it and ask for it, or takes it out of their sight. Taken out,
    /// it also closes: its level, the agents it was open to and the programs allowed with it go.
    public func setOffered(_ offered: Bool, id: String) {
        var index = keyIndex
        if offered {
            guard !index.isOffered(id), index.isTaken(id) else { return }
            index.offer(id: id)
        } else {
            guard index.isOffered(id) else { return }
            index.withdraw(id: id)
        }
        do {
            try saveIndex(index)
        } catch {
            message = T("That identifier could not be saved")
            return
        }
        guard !offered else { return }
        let policy = agentPolicy
        if policy.levels[id] != nil || policy.agents[id] != nil || policy.until[id] != nil || policy.commands[id] != nil {
            if policy.levels[id] == .always, let key = index.unoffered.first(where: { $0.id == id }) {
                try? vaultStore.update { $0.dropUnattended(name: key.source) }
            }
            updatePolicy { policy in
                policy.levels[id] = nil
                policy.until[id] = nil
                policy.agents[id] = nil
                policy.commands[id] = nil
                policy.hashes[id] = nil
            }
        }
        revoke(key: id)
    }

    /// A person giving a key a level, a program or a permission offers it to agents, if it was not.
    func offerIfWaiting(_ id: String) {
        guard !keyIndex.isOffered(id), keyIndex.isTaken(id) else { return }
        setOffered(true, id: id)
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
        guard let id = (keyIndex.keys(forSource: item.path).first ?? keyIndex.allKeys(forSource: item.path).first)?.id else { return }
        allow(program: program, keyID: id)
    }

    /// Lets agents run `program` with the key called `keyID`. Each use still asks for your finger.
    public func allow(program: String, keyID id: String) {
        guard !AgentPolicy.isNeverAllowed(program) else {
            message = T("%@ can print or send whatever it gets, so it cannot be allowed.", URL(fileURLWithPath: program).lastPathComponent)
            return
        }
        guard let hash = AgentPolicy.fingerprint(of: program) else {
            message = T("That program could not be read")
            return
        }
        offerIfWaiting(id)
        updatePolicy { policy in
            if !(policy.commands[id] ?? []).contains(program) { policy.commands[id, default: []].append(program) }
            // Pinned as it is now: if it changes, agents cannot run it until you allow it again.
            policy.hashes[id, default: [:]][program] = hash
        }
    }

    /// How agents may use a key: nil keeps it yours alone.
    public func setAgentLevel(_ level: AgentPolicy.Level?, for id: String) {
        if level != nil { offerIfWaiting(id) }
        // "Always" needs a copy sealed to the chip's key that asks nothing, made with this fingerprint once.
        if level == .always { return markAlways(id) }
        // Off "always", the copy goes: nothing can open the key with no fingerprint any more.
        if agentPolicy.levels[id] == .always, let key = keyIndex.key(id) {
            try? vaultStore.update { $0.dropUnattended(name: key.source) }
        }
        applyLevel(level, for: id)
    }

    private func applyLevel(_ level: AgentPolicy.Level?, for id: String) {
        updatePolicy { policy in
            policy.levels[id] = level
            // A level you choose here has no end, even if an agent's request had given it one.
            policy.until[id] = nil
            if level == nil { policy.agents[id] = nil }
        }
    }

    /// Opens the key with the person's fingerprint, seals a copy to the chip's key that asks nothing, and only then
    /// sets the level, so "always" is never set for a key that would still ask.
    func markAlways(_ id: String) {
        guard let key = keyIndex.key(id) else {
            message = T("%@ is not in the vault", id)
            return
        }
        let store = vaultStore
        openVault(reason: T("Let agents use %@ with no fingerprint, through the proxy only", id)) { unlocked in
            guard let unlocked else { return }
            Task.detached {
                let result = Result {
                    _ = try store.ensureUnattended()
                    let value = try store.load().open(name: key.source, with: try unlocked.recipient(store))
                    try store.update { try $0.sealUnattended(name: key.source, value: value) }
                }
                await MainActor.run {
                    switch result {
                    case .success:
                        self.applyLevel(.always, for: id)
                        self.message = T("%@ is open to agents with no fingerprint, through the proxy only", id)
                    case .failure(let error):
                        self.message = T("%@ could not be set to need no fingerprint: %@", id, "\(error)")
                    }
                }
            }
        }
    }

    /// The agents a key can be opened to: those the usage log has seen and those already named in the permissions,
    /// besides Claude and Codex, so a bot that runs at login can be chosen like any agent.
    public var knownAgents: [String] {
        let seen = usage.entries.compactMap { $0.declared?.agent }
        let named = agentPolicy.agents.values.flatMap { $0 }
        // Remembered across refreshes, so a bot that has been quiet for a while is still offered.
        let names = Self.agentNames(seen + named + Self.rememberedAgents())
        Self.rememberAgents(names)
        return names
    }

    nonisolated static let agentsSeenKey = "keyreeve.agentsSeen"

    nonisolated static func rememberedAgents(_ defaults: UserDefaults = .standard) -> [String] {
        defaults.stringArray(forKey: agentsSeenKey) ?? []
    }

    nonisolated static func rememberAgents(_ names: [String], _ defaults: UserDefaults = .standard) {
        // A short list, cleaned like the rest: what an agent calls itself is never trusted beyond a name.
        let kept = Array(agentNames(names).prefix(40))
        if kept != rememberedAgents(defaults) { defaults.set(kept, forKey: agentsSeenKey) }
    }

    nonisolated static func agentNames(_ names: [String]) -> [String] {
        // A program, or a program and the name a session gave itself, such as "claude/sales".
        let cleaned = names.compactMap { name -> String? in
            let parts = name.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard (1...2).contains(parts.count) else { return nil }
            let clean = parts.compactMap(AgentPolicy.cleanAgentName)
            return clean.count == parts.count ? clean.joined(separator: "/") : nil
        }
        return Array(Set(cleaned + ["claude", "codex"])).sorted()
    }

    /// Whether a key at "always" has the copy that lets it open with no fingerprint.
    public func hasUnattendedCopy(_ id: String) -> Bool {
        guard let key = keyIndex.key(id) else { return false }
        return unattendedSources.contains(key.source)
    }

    /// Which agents may use a key. Empty means any.
    public func setAgents(_ agents: [String], for id: String) {
        updatePolicy { policy in
            policy.agents[id] = agents.isEmpty ? nil : agents
        }
    }

    /// Ends what agents were approved for a while, and every permission the key service holds.
    public func endAgentApprovals() {
        audit([("-", "every agent permission ended")], event: "closed all")
        closeServicePermissions()
        message = T("Agents must ask again")
    }

    public func disallow(program: String, keyID id: String) {
        updatePolicy { policy in
            policy.commands[id]?.removeAll { $0 == program }
            if policy.commands[id]?.isEmpty == true { policy.commands[id] = nil }
            policy.hashes[id]?[program] = nil
        }
    }

    /// Keys an agent could be allowed: sealed, with an identifier.
    public var agentKeys: [KeyIndex.Key] {
        let sealed = Set(items.filter { $0.vault == .sealed || $0.vault == .outdated || $0.originalMoved }.map(\.path))
        return keyIndex.keys.filter { sealed.contains($0.source) }.sorted { $0.id < $1.id }
    }

    /// Sealed keys that still need an identifier before an agent can be allowed.
    public var sealedWithoutIdentifier: Int {
        items.filter { ($0.vault == .sealed || $0.vault == .outdated) && keyIndex.allKeys(forSource: $0.path).isEmpty }.count
    }

    /// Sealed keys with an identifier that no agent sees, since no person offered them yet.
    public var sealedNotOffered: Int {
        items.filter { item in
            (item.vault == .sealed || item.vault == .outdated) && keyIndex.keys(forSource: item.path).isEmpty
                && !keyIndex.allKeys(forSource: item.path).isEmpty
        }.count
    }

    public func disallow(program: String, for item: CatalogItem) {
        updatePolicy { policy in
            for key in keyIndex.keys(forSource: item.path) {
                policy.commands[key.id]?.removeAll { $0 == program }
                policy.hashes[key.id]?[program] = nil
            }
        }
    }

    /// Changes the permissions under the file's lock, writes what changed in the usage log, and shows it.
    func updatePolicy(_ change: (inout AgentPolicy) -> Void) {
        do {
            let (before, after) = try AgentPolicy.update(at: files.agents, change)
            let changed = after.changes(from: before)
            audit(changed)
            agentPolicy = after
            // What is already open follows the new terms too: a permission given under the old ones ends,
            // and the next use asks under the new.
            for key in Set(changed.map(\.key)) { revoke(key: key) }
        } catch {
            message = T("The permissions could not be saved") + ": \(error)"
        }
    }

    public func chooseProgram(then: (String) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        panel.message = T("Choose the program an agent may run with this key")
        let tools = files.directory.appendingPathComponent("agent-tools")
        if FileManager.default.fileExists(atPath: tools.path) { panel.directoryURL = tools }
        panel.prompt = T("Choose")
        if panel.runModal() == .OK, let url = panel.url { then(url.path) }
    }

    /// The command that connects Claude Code, on the clipboard. It holds a path and no key.
    public func copyAgentCommand() {
        let tool = (binary?.deletingLastPathComponent().appendingPathComponent("keyreeve-vault").path ?? "keyreeve-vault")
        let board = NSPasteboard.general
        board.clearContents()
        board.setString("claude mcp add --scope user keyreeve -- \"\(tool)\" mcp", forType: .string)
        message = T("The command to connect Claude Code is copied. Run it in a terminal.")
    }
}
