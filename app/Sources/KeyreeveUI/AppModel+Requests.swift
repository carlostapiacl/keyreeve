import Foundation
import KeyreeveCatalog
import KeyreeveVault

/// Agents asking for a key that is not saved yet. The person picks the file, and saving, naming and
/// allowing it happen in one step.
@MainActor
extension AppModel {
    var requestsFile: URL { files.directory.appendingPathComponent(AccessRequests.fileName) }
    var offeredFile: URL { files.directory.appendingPathComponent(AccessRequests.offeredFileName) }

    /// A file that could answer a request: it has a provider, it is not internal or marked Only me, and it
    /// is not yet a sealed key with an identifier.
    func canBeOffered(_ item: CatalogItem) -> Bool {
        guard !item.isInternal, item.level != "never", let provider = item.recipes.first, providers.all.contains(where: { $0.id == provider }) else {
            return false
        }
        // A copy sealed from another folder, or one whose file changed since, is not the file shown.
        return item.vault == .none || (item.vault == .sealed && keyIndex.keys(forSource: item.path).isEmpty)
    }

    /// Reads the requests and the pause. Cheap, so the menu bar can do it often.
    public func reloadRequests() {
        let paused = AgentBridge.isPaused(home: files.directory)
        if paused != agentsPaused { agentsPaused = paused }
        // Read again only when the file changed, since this runs every few seconds.
        let attributes = try? FileManager.default.attributesOfItem(atPath: requestsFile.path)
        let stamp = "\((attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)-\((attributes?[.size] as? Int) ?? 0)"
        guard stamp != requestsStamp else { return }
        requestsStamp = stamp
        let pending = AccessRequests.pending(AccessRequests.read(from: requestsFile))
        if pending != pendingRequests { pendingRequests = pending }
    }

    /// Tells agents which providers can be asked for, when the list of keys changes. Only provider
    /// names leave the app.
    func publishOffered() {
        // Only from a loaded list: a locked window has none, and would tell agents there is nothing to ask for.
        guard unlocked else { return }
        // Every provider keyreeve knows can be asked for: one with no file is answered by pasting a new key.
        let known = providers.all.filter { $0.problem == nil && $0.approved }.map(\.id)
        let offered = Array(Set(items.filter(canBeOffered).compactMap(\.recipes.first) + known)).sorted()
        if AccessRequests.readOffered(from: offeredFile) != offered, let data = try? JSONEncoder().encode(offered) {
            try? files.writePrivate(data, to: offeredFile)
        }
    }

    /// The files that could answer a request: those that fit the account the agent named first, then
    /// those whose last check passed, rejected ones last.
    public func candidates(for request: AccessRequests.Entry) -> [CatalogItem] {
        func rank(_ item: CatalogItem) -> Int { item.lastResult == "works" ? 0 : item.lastResult == "rejected" ? 2 : 1 }
        return items.filter { $0.recipes.first == request.provider && canBeOffered($0) }
            .sorted { (-$0.fit(account: request.account), rank($0), $0.path) < (-$1.fit(account: request.account), rank($1), $1.path) }
    }

    /// Seals the file if it is not sealed yet, gives it an identifier, and opens it to the agent that asked.
    public func allow(_ request: AccessRequests.Entry, with item: CatalogItem, hours: Int?) {
        guard let folder = keysFolder else { return }
        do {
            if item.vault == .none {
                let report = try VaultKeeper.seal(paths: [item.path], folder: folder, store: vaultStore)
                guard report.skipped.isEmpty else {
                    message = T("That file could not be read as text, so it was not saved")
                    return
                }
                for path in report.sealed { note("sealed", path: path, detail: "requested by \(request.agent)") }
            }
            var index = (try? KeyIndex.load(from: files.keyIndex)) ?? keyIndex
            let id: String
            if let existing = index.keys(forSource: item.path).first {
                id = existing.id
            } else {
                id = suggestedIdentifier(for: item)
                let provider = providers.all.first { $0.id == request.provider }
                try index.add(
                    KeyIndex.Key(
                        id: id, source: item.path, field: item.field.isEmpty ? nil : item.field, provider: request.provider,
                        account: account(of: item), description: item.description.isEmpty ? nil : item.description,
                        variable: provider?.env_var))
                try files.writePrivate(Data(index.toml.utf8), to: files.keyIndex)
                keyIndex = index
            }
            try openToAgent(id, for: request, hours: hours)
            message = T("%@ is saved and open to %@", id, request.agent)
        } catch {
            message = (error as? VaultError)?.description ?? T("The request could not be answered")
        }
        load()
    }

    /// Opens a saved key to the agent that asked, for the hours chosen or always, and answers its request.
    func openToAgent(_ id: String, for request: AccessRequests.Entry, hours: Int?) throws {
        let agent = request.agent
        let closes = hours.map { Date().addingTimeInterval(TimeInterval($0 * 3600)) }
        let (before, after) = try AgentPolicy.update(at: files.agents) { policy in
            let wasOpen = policy.level(of: id) != nil
            policy.levels[id] = .free
            if let limited = policy.agents[id], !limited.isEmpty {
                if !limited.contains(agent) { policy.agents[id] = limited + [agent] }
            } else if !wasOpen {
                policy.agents[id] = [agent]
            }
            policy.until[id] = closes
        }
        agentPolicy = after
        audit([(id, "request \(request.id) from \(request.agent) for \(request.provider)")], event: "allowed")
        audit(after.changes(from: before))
        try AccessRequests.append(
            AccessRequests.Entry(
                id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider,
                hours: hours, key: id),
            to: requestsFile)
    }

    public func decline(_ request: AccessRequests.Entry) {
        audit([(request.provider, "request \(request.id) from \(request.agent)")], event: "declined")
        try? AccessRequests.append(
            AccessRequests.Entry(id: request.id, at: Date(), event: .declined, agent: request.agent, provider: request.provider),
            to: requestsFile)
        reloadRequests()
    }

    /// The file behind a key an agent names, by its identifier.
    public func item(forKey id: String?) -> CatalogItem? {
        guard let id, let source = keyIndex.key(id)?.source else { return nil }
        return items.first { $0.path == source }
    }

    /// Rotates the key an agent asked about, where the person said it is used, and leaves how it went for
    /// the agent to read. The vault asks for the fingerprint as for any rotation.
    public func rotate(for request: AccessRequests.Entry, item: CatalogItem, handedOver: String?) {
        audit([(request.key ?? item.path, "rotation \(request.id) from \(request.agent)")], event: "allowed")
        runRotation(item, resume: false, handedOver: handedOver) { words in
            try? AccessRequests.append(
                AccessRequests.Entry(
                    id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider,
                    key: request.key, kind: "rotate", result: words),
                to: self.requestsFile)
            self.reloadRequests()
        }
    }

    public static let agentsCanSortKey = "agentsCanSort"

    /// What an agent may read to help sort the keys, written only while the person lets agents sort: each
    /// file's name, fields, provider and state, and the providers keyreeve knows. Never a value. With the
    /// setting off the file is gone, and agents are told how to ask for it.
    public func publishInventory() {
        let file = AgentSorting.inventoryFile(home: files.directory)
        guard UserDefaults.standard.bool(forKey: Self.agentsCanSortKey) else {
            try? FileManager.default.removeItem(at: file)
            return
        }
        guard unlocked else { return }
        let keys: [[String: Any]] = items.map { item in
            var row: [String: Any] = [
                "path": item.path, "fields": item.labels.filter { !$0.isEmpty }, "tags": item.tags, "level": item.level,
                "result": item.lastResult.isEmpty ? "never_checked" : item.lastResult,
                "sealed": item.vault == .sealed || item.vault == .outdated, "archived": item.isArchived,
                "untestable": item.isUntestable, "internal": item.isInternal,
            ]
            if let provider = item.recipes.first { row["provider"] = provider }
            if !item.field.isEmpty { row["field"] = item.field }
            if !item.description.isEmpty { row["what"] = item.description }
            if let day = item.expiryDay { row["expires"] = day }
            if let reaches = item.reaches { row["account"] = reaches }
            if item.needsField { row["needs"] = "a field: the file holds several values" }
            if item.holdsSeveralKeys { row["needs"] = "splitting: the file holds several keys of its provider" }
            if providers.needsHost(item) { row["needs_host"] = true }
            return row
        }
        let known = providers.all.filter { $0.problem == nil }.map { ["id": $0.id, "name": $0.name] }
        guard let data = try? JSONSerialization.data(withJSONObject: ["keys": keys, "providers": known], options: [.sortedKeys])
        else { return }
        try? files.writePrivate(data, to: file)
    }

    /// The changes an agent proposed, read against today's list.
    public func proposal(for request: AccessRequests.Entry) -> SortProposal {
        guard let data = AgentSorting.load(id: request.id, home: files.directory) else { return SortProposal() }
        return SortProposal.read(data, items: items, providers: providers)
    }

    /// Applies the chosen changes of an agent's proposal: sorting and archiving at once, then the checks,
    /// which may ask for the fingerprint, then sealing. The agent reads how it went in the next inventory.
    public func apply(_ proposal: SortProposal, chosen: Set<String>, for request: AccessRequests.Entry) {
        let byPath = Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var edits: [String: KeyEdit] = [:]
        for suggestion in proposal.suggestions where chosen.contains(suggestion.path) {
            guard let item = byPath[suggestion.path] else { continue }
            edits[suggestion.path] = suggestion.edit(for: item)
        }
        for (path, day) in proposal.expires where chosen.contains(path) {
            var change = edits[path] ?? KeyEdit()
            change.expires = day
            edits[path] = change
        }
        for (path, host) in proposal.hosts where chosen.contains(path) {
            var change = edits[path] ?? KeyEdit()
            change.host = host
            edits[path] = change
        }
        for path in proposal.archive where chosen.contains(path) {
            guard let item = byPath[path] else { continue }
            var change = edits[path] ?? KeyEdit()
            let tags = change.tags ?? item.tags
            change.tags = tags.contains("status:archived") ? tags : tags + ["status:archived"]
            edits[path] = change
        }
        if !edits.isEmpty {
            do {
                try files.saveEdits(edits)
            } catch {
                message = (error as? CheckError)?.description ?? T("%@ could not be saved", files.edits.lastPathComponent)
                return
            }
        }
        let updated = { (path: String) in byPath[path].map { item in edits[path].map(item.applying) ?? item } }
        let toSplit = proposal.split.filter(chosen.contains).compactMap(updated)
        let checkPaths = proposal.check.filter(chosen.contains).sorted()
        let sealPaths = proposal.seal.filter(chosen.contains).sorted()
        audit([("\(chosen.count) keys", "sorting \(request.id) from \(request.agent)")], event: "allowed")
        // Accepted, not done: what follows runs after, and its end is written down when it ends.
        let record = { (result: String) in
            try? AccessRequests.append(
                AccessRequests.Entry(
                    id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider, kind: "sort",
                    result: result),
                to: self.requestsFile)
            self.reloadRequests()
        }
        record("accepted: \(edits.count) changes saved; splitting \(toSplit.count), sealing \(sealPaths.count), checking \(checkPaths.count) follow")
        message = T("%d changes saved. Splitting, sealing and checking follow.", chosen.count)
        rebuildCatalog()
        // Splitting first: it makes the files that sealing and checking are about, so a file that is split is
        // sealed and checked as its new files, never as the original it moved away. Each step waits for the app.
        final class Outcome { var split: [String: [String]] = [:]; var failed: [String] = []; var skipped: [String] = [] }
        let outcome = Outcome()
        let expand = { (paths: [String]) in Self.afterSplit(paths, split: outcome.split) }
        let current = { (paths: [String]) -> [CatalogItem] in
            let now = Dictionary(self.items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
            return expand(paths).compactMap { now[$0] }
        }
        let finish = {
            let parts = [
                "split \(outcome.split.count)", outcome.failed.isEmpty ? nil : "not split: " + outcome.failed.joined(separator: ", "),
                outcome.skipped.isEmpty ? nil : "not run: " + outcome.skipped.joined(separator: ", "),
            ].compactMap { $0 }
            record((outcome.failed.isEmpty && outcome.skipped.isEmpty ? "done: " : "partly done: ") + parts.joined(separator: "; "))
        }
        whenIdle("splitting", skipped: { outcome.skipped.append("splitting, sealing, checking"); finish() }) {
            for item in toSplit {
                if let names = self.split(item) { outcome.split[item.path] = names } else { outcome.failed.append(item.path) }
            }
            self.whenIdle("sealing", skipped: { outcome.skipped.append("sealing, checking"); finish() }) {
                let toSeal = current(sealPaths).filter { $0.vault == .none }
                if !toSeal.isEmpty { self.seal(toSeal) }
                self.whenIdle("checking", skipped: { outcome.skipped.append("checking"); finish() }) {
                    let toCheck = current(checkPaths)
                    if !toCheck.isEmpty { self.check(toCheck) }
                    self.whenIdle("checking", skipped: { finish() }) { finish() }
                }
            }
        }
    }

    /// The files a step is for once splitting is done: a file that was split is its new files.
    nonisolated static func afterSplit(_ paths: [String], split: [String: [String]]) -> [String] {
        paths.flatMap { split[$0] ?? [$0] }
    }

    /// Runs the action once nothing else is running. After ten minutes it does not run, since running beside
    /// what is still going could break both: it says so, and `skipped` follows instead.
    func whenIdle(
        _ what: String = "That step", skipped: @escaping @MainActor () -> Void = {}, wait: TimeInterval = 600,
        _ action: @escaping @MainActor () -> Void
    ) {
        Task { @MainActor in
            let deadline = Date().addingTimeInterval(wait)
            while settling && Date() < deadline { try? await Task.sleep(for: .milliseconds(200)) }
            guard !settling else {
                message = T("%@ did not run: Keyreeve stayed busy for ten minutes.", what.prefix(1).uppercased() + what.dropFirst())
                skipped()
                return
            }
            action()
        }
    }
}
