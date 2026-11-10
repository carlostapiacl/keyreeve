import AppKit
import KeyreeveCatalog
import KeyreeveVault

/// Bring in: find keys on this Mac or in a folder, review them on one screen, and seal the chosen ones at
/// once. Each gets an identifier and is not offered to agents. The files they came from are never
/// moved, changed or removed: where each came from is kept with its sealed copy.
public struct BringState {
    public enum Step: Equatable { case choose, looking, review, done }

    public struct Project: Identifiable, Equatable {
        public var id: URL { url }
        public var url: URL
        public var on: Bool
    }

    public enum Place: Equatable { case usual, everywhere, folder }

    public var step = Step.choose
    /// Usual places on this Mac, the whole home folder, or one folder.
    public var place = Place.usual
    /// With `everywhere`, only these folders: those an agent named, or those a search did not finish.
    public var under: [URL] = []
    public var usualPlaces: Bool {
        get { place == .usual }
        set { place = newValue ? .usual : .folder }
    }
    /// Folders to search for `.env` files. None is searched until the person turns it on.
    public var projects: [Project] = []
    public var folder: URL?
    public var report: BringReport?
    /// What the person chose for each key: seal it or not. A key to decide has no entry until they do.
    public var decisions: [Int: Bool] = [:]
    public var error: String?
    /// The identifiers given at the end, with whether a project's `.env` uses the key.
    public var sealed: [(id: String, fromProject: Bool)] = []
    public var failed: [String] = []
    /// The agent's request this review answers, when an agent proposed it.
    public var request: AccessRequests.Entry?
    public var agentProposal: AgentBringing.Proposal?
    /// The agent's suggestion for each key found again in this search, by its number here.
    public var agentChoices: [Int: AgentBringing.Proposal.Item] = [:]
    /// The agent's choices no key found now matches: the file changed or is gone.
    public var agentMissed: [AgentBringing.Proposal.Item] = []
    /// Whether the identifiers, notes and tags the agent suggested are used. The person can turn them off.
    public var useAgentNames = true

    public init(projects: [URL] = []) {
        self.projects = projects.map { Project(url: $0, on: false) }
    }

    public var scope: BringScope? {
        switch place {
        case .usual: return .places(projects: projects.filter(\.on).map(\.url))
        case .everywhere: return .everywhere(under: under)
        case .folder: return folder.map(BringScope.folder)
        }
    }

    func candidates(_ group: BringCandidate.Group) -> [BringCandidate] {
        report?.candidates.filter { $0.group == group } ?? []
    }

    /// Keys still to decide. Sealing waits for them.
    public var undecided: Int { candidates(.doubtful).filter { decisions[$0.id] == nil }.count }

    public var chosen: [BringCandidate] {
        (report?.candidates ?? []).filter { $0.group != .other && decisions[$0.id] == true }
    }

    public var fromProjects: [String] { sealed.filter(\.fromProject).map(\.id) }
}

@MainActor
extension AppModel {
    public func startBringIn() {
        bringing = BringState(projects: BringRunner.suggestedProjects())
    }

    public func cancelBringIn() { bringing = nil }

    public func chooseBringFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.message = T("Choose a folder to look for keys in")
        panel.prompt = T("Choose")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        bringing?.folder = url
        bringing?.usualPlaces = false
    }

    public func addBringProject() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.message = T("Choose a folder with projects")
        panel.prompt = T("Choose")
        guard panel.runModal() == .OK, let url = panel.url, bringing != nil else { return }
        if let at = bringing?.projects.firstIndex(where: { $0.url == url }) {
            bringing?.projects[at].on = true
        } else {
            bringing?.projects.append(.init(url: url, on: true))
        }
    }

    /// Reads and checks, off the screen. Nothing is written anywhere until the person seals.
    public func lookForKeys() {
        guard let scope = bringing?.scope else { return }
        guard let binary else {
            bringing?.error = T("This app was built without its command")
            return
        }
        bringing?.step = .looking
        bringing?.error = nil
        Task.detached {
            let result = Result { try BringRunner.run(binary: binary, scope: scope) }
            await MainActor.run { self.showBrought(result) }
        }
    }

    func showBrought(_ result: Result<BringReport, Error>) {
        guard bringing != nil else { return }
        switch result {
        case .success(let report):
            bringing?.report = report
            bringing?.decisions = Self.firstDecisions(report)
            if let proposal = bringing?.agentProposal {
                let found = Self.agentChoices(report, proposal: proposal)
                bringing?.agentChoices = found.choices
                bringing?.agentMissed = found.missed
                for (id, item) in found.choices { bringing?.decisions[id] = item.seal }
            }
            bringing?.step = .review
        case .failure(let error):
            bringing?.error = (error as? CheckError)?.description ?? T("Looking for keys did not finish")
            bringing?.step = .choose
        }
    }

    /// Keys that work are sealed and dead ones are not, until the person says otherwise. Those to decide wait.
    nonisolated static func firstDecisions(_ report: BringReport) -> [Int: Bool] {
        var decisions: [Int: Bool] = [:]
        for candidate in report.candidates {
            switch candidate.suggested {
            case "seal": decisions[candidate.id] = true
            case "skip": decisions[candidate.id] = false
            default: break
            }
        }
        return decisions
    }

    /// Opens an agent's proposal in Bring in: Keyreeve looks again where the agent looked, checks each key with
    /// its own provider as it does for the person, and fills the review with the agent's choices. Nothing is
    /// sealed until the person seals, with their fingerprint.
    public func reviewBringProposal(_ request: AccessRequests.Entry) {
        guard let data = AgentSorting.load(id: request.id, home: files.directory), let proposal = AgentBringing.decode(data) else {
            message = T("That proposal could not be read. Decline it, and ask the agent again.")
            return
        }
        var state = BringState()
        state.projects = proposal.scope.projects.map { .init(url: URL(fileURLWithPath: $0), on: true) }
        switch proposal.scope.place {
        case .places: state.place = .usual
        case .everywhere: state.place = .everywhere
        case .folders:
            state.place = .everywhere
            state.under = proposal.scope.folders.map { URL(fileURLWithPath: $0) }
        }
        state.request = request
        state.agentProposal = proposal
        bringing = state
        lookForKeys()
    }

    /// The agent's choice for each key found now, matched by file and part names, since numbers change from
    /// one search to the next. Configuration is never sealed, whatever the agent said.
    nonisolated static func agentChoices(
        _ report: BringReport, proposal: AgentBringing.Proposal
    ) -> (choices: [Int: AgentBringing.Proposal.Item], missed: [AgentBringing.Proposal.Item]) {
        var choices: [Int: AgentBringing.Proposal.Item] = [:]
        var used = Set<Int>()
        for candidate in report.candidates where candidate.group != .other {
            let signatures = Set(candidate.origins.map { origin in
                AgentBringing.signature(
                    path: origin.path,
                    parts: origin.parts.map { AgentBringing.Part(name: $0.name, line: $0.line, whole: $0.whole).label })
            })
            if let at = proposal.items.indices.first(where: { !used.contains($0) && !signatures.isDisjoint(with: proposal.items[$0].origins) }) {
                used.insert(at)
                choices[candidate.id] = proposal.items[at]
            }
        }
        let missed = proposal.items.indices.filter { !used.contains($0) }.map { proposal.items[$0] }
        return (choices, missed)
    }

    /// Goes on in the folders a search of everywhere did not finish, keeping the agent's proposal if there is one.
    public func lookInUnfinished() {
        guard let unfinished = bringing?.report?.unfinished, !unfinished.isEmpty else { return }
        bringing?.place = .everywhere
        bringing?.under = unfinished.map { URL(fileURLWithPath: $0) }
        lookForKeys()
    }

    public func decide(_ id: Int, seal: Bool) { bringing?.decisions[id] = seal }

    public func decideAllDoubtful(seal: Bool) {
        for candidate in bringing?.candidates(.doubtful) ?? [] { bringing?.decisions[candidate.id] = seal }
    }

    /// Seals every chosen key once the person's finger says so: one prompt for all of them.
    public func sealBrought() {
        guard let state = bringing, state.undecided == 0, !state.chosen.isEmpty else { return }
        guard vaultStore.exists else {
            startVault()
            return
        }
        let chosen = state.chosen
        confirm(reason: T("seal %d keys you brought in", chosen.count)) { allowed in
            guard allowed else { return }
            self.sealNow(chosen)
        }
    }

    func sealNow(_ chosen: [BringCandidate]) {
        do {
            var index = FileManager.default.fileExists(atPath: files.keyIndex.path) ? try KeyIndex.load(from: files.keyIndex) : keyIndex
            let selfHosted = Set(providers.all.filter(\.self_hosted).map(\.id))
            let variables = Dictionary(providers.all.compactMap { p in p.env_var.map { (p.id, $0) } }, uniquingKeysWith: { a, _ in a })
            let named = bringing?.useAgentNames == true ? bringing?.agentChoices ?? [:] : [:]
            let result = try Self.sealBrought(
                chosen, index: index, store: vaultStore, selfHosted: selfHosted, variables: variables, named: named
            ) { try self.files.writePrivate($0, to: self.files.keyIndex) }
            index = result.index
            keyIndex = index
            if let request = bringing?.request {
                audit(result.sealed.map { ($0.id, "brought in, proposed by \(request.agent) in \(request.id)") }, event: "sealed")
                // The agent learns how many, never which identifiers: they are not offered to it.
                let words = "the person sealed \(result.sealed.count) keys" + (result.failed.isEmpty ? "" : ", \(result.failed.count) could not be read")
                try? AccessRequests.append(
                    AccessRequests.Entry(
                        id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider,
                        kind: AgentBringing.kind, result: words),
                    to: requestsFile)
                reloadRequests()
            } else {
                audit(result.sealed.map { ($0.id, "brought in") }, event: "sealed")
            }
            bringing?.sealed = result.sealed
            bringing?.failed = result.failed
            bringing?.step = .done
        } catch {
            bringing?.error = (error as? VaultError)?.description ?? T("The vault could not be saved")
            return
        }
        load()
    }

    /// The keys a project's `.env` uses, offered to agents in one click.
    public func offerBroughtFromProjects() {
        for id in bringing?.fromProjects ?? [] { setOffered(true, id: id) }
        message = T("Offered to agents. Each still asks you before an agent uses it, as its level says.")
        bringing = nil
    }

    /// Reads each key from its file and seals them all in one change of the vault, then writes keys.toml.
    /// If keys.toml cannot be written, the copies just sealed are taken out again, so nothing is left with
    /// no name. A key whose file changed since it was read is left out and named in `failed`.
    nonisolated static func sealBrought(
        _ chosen: [BringCandidate], index: KeyIndex, store: VaultStore, selfHosted: Set<String> = [],
        variables: [String: String] = [:], named: [Int: AgentBringing.Proposal.Item] = [:], writeIndex: (Data) throws -> Void
    ) throws -> (index: KeyIndex, sealed: [(id: String, fromProject: Bool)], failed: [String]) {
        var index = index
        var values: [(entry: String, data: Data, source: String)] = []
        var sealed: [(id: String, fromProject: Bool)] = []
        var failed: [String] = []
        for candidate in chosen {
            // The first place it can still be read from: a key found twice is one key.
            var read: BringValue.Read?
            var problem = ""
            for origin in candidate.origins where read == nil {
                do { read = try BringValue.read(origin) } catch { problem = (error as? CheckError)?.description ?? "\(error)" }
            }
            guard let read else {
                failed.append(problem)
                continue
            }
            let first = candidate.origins[0]
            // The name an agent suggested, if it is free; a provider it suggested is never saved, only shown.
            let suggested = named[candidate.id]
            var id = index.suggestion(provider: candidate.provider, project: nil, source: first.path)
            if let wanted = suggested?.id, KeyIndex.isValid(id: wanted), !index.isTaken(wanted) {
                id = wanted
            }
            let entry = AppModel.addedFolder + id
            var key = KeyIndex.Key(id: id, source: entry, field: read.field, provider: candidate.provider)
            key.description = suggested?.description
            if let tags = suggested?.tags, !tags.isEmpty { key.more.tags = tags }
            let ownName = first.parts.count == 1 ? BringValue.envName(first.parts[0].name) : nil
            key.variable = ownName.flatMap { $0 == $0.uppercased() ? $0 : nil } ?? candidate.provider.flatMap { variables[$0] }
            if let provider = candidate.provider, selfHosted.contains(provider), let server = candidate.server {
                key.more.host = server
            }
            try index.addUnoffered(key)
            values.append((entry, read.data, candidate.origins.map(\.path).joined(separator: "\n")))
            sealed.append((id, candidate.from_project))
        }
        guard !values.isEmpty else { return (index, [], failed) }
        try store.update { vault in
            for value in values { try vault.add(name: value.entry, value: value.data, source: value.source) }
        }
        do {
            try writeIndex(Data(index.toml.utf8))
        } catch {
            do {
                try store.update { vault in for value in values { vault.entries[value.entry] = nil } }
            } catch {
                throw VaultError("the keys were sealed but keys.toml could not be written, and they could not be taken out again")
            }
            throw VaultError("keys.toml could not be written, so no key was saved. Nothing was left behind: try again")
        }
        return (index, sealed, failed)
    }
}
