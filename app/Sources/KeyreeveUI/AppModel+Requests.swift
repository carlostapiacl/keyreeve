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
}
