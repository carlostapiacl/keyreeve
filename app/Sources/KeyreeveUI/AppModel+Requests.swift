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
        return item.vault == .none || keyIndex.keys(forSource: item.path).isEmpty
    }

    /// Reads the requests, and tells agents which providers can be asked for. Only provider names leave the app.
    public func reloadRequests() {
        agentsPaused = AgentBridge.isPaused(home: files.directory)
        pendingRequests = AccessRequests.pending(AccessRequests.read(from: requestsFile))
        // Only from a loaded list: a locked window has none, and would tell agents there is nothing to ask for.
        guard unlocked, !items.isEmpty else { return }
        let offered = Array(Set(items.filter(canBeOffered).compactMap(\.recipes.first))).sorted()
        if AccessRequests.readOffered(from: offeredFile) != offered, let data = try? JSONEncoder().encode(offered) {
            try? files.writePrivate(data, to: offeredFile)
        }
    }

    /// The files that could answer a request: those whose last check passed first, rejected ones last.
    public func candidates(for request: AccessRequests.Entry) -> [CatalogItem] {
        func rank(_ item: CatalogItem) -> Int { item.lastResult == "works" ? 0 : item.lastResult == "rejected" ? 2 : 1 }
        return items.filter { $0.recipes.first == request.provider && canBeOffered($0) }
            .sorted { (rank($0), $0.path) < (rank($1), $1.path) }
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
            var policy = AgentPolicy.load(from: files.agents)
            let before = policy
            let wasOpen = policy.level(of: id) != nil
            policy.levels[id] = .free
            if let limited = policy.agents[id], !limited.isEmpty {
                if !limited.contains(request.agent) { policy.agents[id] = limited + [request.agent] }
            } else if !wasOpen {
                policy.agents[id] = [request.agent]
            }
            policy.until[id] = hours.map { Date().addingTimeInterval(TimeInterval($0 * 3600)) }
            try files.writePrivate(Data(policy.toml.utf8), to: files.agents)
            agentPolicy = policy
            audit([(id, "request \(request.id) from \(request.agent) for \(request.provider)")], event: "allowed")
            audit(policy.changes(from: before))
            try AccessRequests.append(
                AccessRequests.Entry(
                    id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider,
                    hours: hours, key: id),
                to: requestsFile)
            message = T("%@ is saved and open to %@", id, request.agent)
        } catch {
            message = (error as? VaultError)?.description ?? T("The request could not be answered")
        }
        load()
    }

    public func decline(_ request: AccessRequests.Entry) {
        audit([(request.provider, "request \(request.id) from \(request.agent)")], event: "declined")
        try? AccessRequests.append(
            AccessRequests.Entry(id: request.id, at: Date(), event: .declined, agent: request.agent, provider: request.provider),
            to: requestsFile)
        reloadRequests()
    }
}
