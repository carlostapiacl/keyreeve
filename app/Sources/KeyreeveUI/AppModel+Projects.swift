import AppKit
import KeyreeveCatalog
import KeyreeveVault

/// A key Bring in found in a project, and whether the vault holds it.
public struct BringFound: Equatable, Sendable {
    public var candidate: Int
    public var names: String
    public var sealed: AgentBringing.Sealed?
}

/// Knowing what the vault holds, by value and with no value shown; the folders Bring in never looks in; and projects:
/// a folder, its keys, where they live and its key set, as one thing.
@MainActor
extension AppModel {
    var ignoreFile: URL { BringIgnore.file(home: files.directory) }
    var projectsFile: URL { Projects.file(home: files.directory) }

    // MARK: What the vault holds

    /// Whether every value in the vault has a keyed digest, read with no prompt.
    public func vaultCoverage() -> SealedMatcher.Coverage? {
        guard case .success(let matcher) = SealedMatcher.load(store: vaultStore, digestsFile: digestsFile, keys: keyIndex) else {
            return nil
        }
        return matcher.coverage
    }

    /// Opens every sealed value once, with one fingerprint, and keeps the keyed digest of each and of each field, then
    /// drops them. After that a key found anywhere tells whether the vault holds it, with no fingerprint. A no learns
    /// nothing.
    public func learnWhatTheVaultHolds(then done: (@MainActor (Bool) -> Void)? = nil) {
        guard vaultStore.exists else {
            message = T("There is no vault yet, so there is nothing to learn")
            done?(false)
            return
        }
        let store = vaultStore
        let file = digestsFile
        openVault(reason: T("learn what your vault holds, to tell keys you have from new ones")) { unlocked in
            guard let unlocked else {
                self.message = T("Nothing was learned: it was not confirmed")
                done?(false)
                return
            }
            Task.detached {
                let outcome = Result { () throws -> (learned: Int, failed: Int) in
                    // The chip key that asks nothing makes the digests. Making it asks nothing either.
                    _ = try? store.ensureUnattended()
                    let vault = try store.load()
                    guard let key = DigestKey.load(vault: vault, store: store) else {
                        throw CheckError(T("This Mac's chip could not make the digests"))
                    }
                    let recipient = try unlocked.recipient(store)
                    return try ValueDigests.learnAll(
                        revisions: vault.entries.mapValues(\.revision), open: { try vault.open(name: $0, with: recipient) }, key: key,
                        file: file)
                }
                await MainActor.run {
                    switch outcome {
                    case .success(let counts):
                        self.audit([("vault", "learned what \(counts.learned) values are, by keyed digest")], event: "digests-learned")
                        self.message = counts.failed == 0
                            ? T("Learned what %d values are. No value was kept.", counts.learned)
                            : T("Learned %d values; %d could not be opened.", counts.learned, counts.failed)
                        if self.bringing?.report != nil {
                            self.compareBrought(SealedMatcher.load(store: store, digestsFile: file, keys: self.keyIndex))
                            if let report = self.bringing?.report {
                                for (id, sealed) in self.bringing?.sealedNow ?? [:] {
                                    if case .now = sealed, report.candidates.contains(where: { $0.id == id }) { self.bringing?.decisions[id] = false }
                                }
                            }
                        }
                        done?(true)
                    case .failure(let error):
                        self.message = (error as? CheckError)?.description ?? T("The vault could not be opened")
                        done?(false)
                    }
                }
            }
        }
    }

    /// Compares what Bring in found with the vault, from the hashes it holds in memory.
    func compareBrought(_ matcher: Result<SealedMatcher, SealedMatcher.UnavailableError>) {
        guard let report = bringing?.report else { return }
        let hashes = bringing?.hashes ?? [:]
        var sealed: [Int: AgentBringing.Sealed] = [:]
        switch matcher {
        case .success(let matcher):
            bringing?.comparison = .compared(matcher.coverage)
            for candidate in report.candidates where candidate.kind == "key" || candidate.kind == "login" {
                guard let mine = hashes[candidate.id] else { continue }
                if let hit = matcher.match(mine) {
                    sealed[candidate.id] = hit.earlier ? .earlier(hit.ids) : .now(hit.ids)
                } else {
                    sealed[candidate.id] = matcher.coverage.complete ? .new : .unmatched
                }
            }
        case .failure(let why):
            bringing?.comparison = .unavailable(why.reason)
        }
        bringing?.sealedNow = sealed
        var byProject: [String: [BringFound]] = [:]
        for candidate in report.candidates where candidate.kind == "key" || candidate.kind == "login" {
            for project in Set(candidate.origins.map(\.projectPath)) {
                byProject[project, default: []].append(BringFound(candidate: candidate.id, names: candidate.partNames, sealed: sealed[candidate.id]))
            }
        }
        lastFound = byProject
    }

    // MARK: Where each key lives, from what was found

    /// A place for each key the vault holds now, where Bring in found it in a dotenv file: the file and its variable,
    /// updated by `dotenv-local`. Places already known are left out. Nothing is added until the person says so.
    public func foundPlaces() -> [PlaceBook.Place] {
        guard let state = bringing, let report = state.report else { return [] }
        var out: [PlaceBook.Place] = []
        for candidate in report.candidates {
            guard case .now(let ids) = state.sealedNow[candidate.id], let id = ids.first else { continue }
            for origin in candidate.origins where origin.parts.count == 1 && Self.isDotenv(origin.path) {
                guard let variable = BringValue.envName(origin.parts[0].name) else { continue }
                let place = PlaceBook.Place(
                    key: id, procedure: "dotenv-local", params: ["file": origin.path, "variable": variable],
                    label: shortPath(origin.path) + " · " + variable, by: "you", why: T("Bring in found the vault's value here"))
                let known = placesState.book.places.contains { $0.isSame(as: place) } || out.contains { $0.isSame(as: place) }
                if !known { out.append(place) }
            }
        }
        return out
    }

    nonisolated static func isDotenv(_ path: String) -> Bool {
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        return name == ".env" || name == ".envrc" || name.hasPrefix(".env.") || name.hasSuffix(".env")
    }

    /// Adds every place found, with one fingerprint, each pinned to its procedure as it is now.
    public func addFoundPlaces() {
        let found = foundPlaces()
        guard !found.isEmpty else { return }
        approvePlaces(found) { count in
            if count > 0 { self.bringing?.placesAdded = true }
        }
    }

    // MARK: The folders never looked in

    public func addIgnored(_ rule: String) {
        do {
            bringing?.ignore = try BringIgnore.update(at: ignoreFile) { rules in rules.append(rule) }
            audit([("bring", "don't look in \(rule)")], event: "bring-ignore")
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be saved", BringIgnore.fileName)
        }
    }

    public func removeIgnored(_ rule: String) {
        do {
            bringing?.ignore = try BringIgnore.update(at: ignoreFile) { rules in rules.removeAll { $0 == rule } }
            audit([("bring", "look in \(rule) again")], event: "bring-ignore")
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be saved", BringIgnore.fileName)
        }
    }

    public func chooseIgnoredFolder() {
        let panel = NSOpenPanelFactory.folder(message: T("Choose a folder Bring in should never look in"))
        guard let url = panel() else { return }
        addIgnored(BringIgnore.rule(for: url.path))
    }

    // MARK: Projects

    public func reloadProjects() {
        do {
            let book = try Projects.loadStrict(from: projectsFile)
            if book != projectBook { projectBook = book }
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be read", Projects.fileName)
        }
    }

    /// The projects in what Bring in found, each with the keys the vault holds or that were sealed here, and the files
    /// they were found in. Only projects with such a key.
    public func projectsFound() -> [Projects.Project] {
        guard let state = bringing, let report = state.report else { return [] }
        let known = Dictionary((report.projects ?? []).map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var keys: [String: [String]] = [:]
        var places: [String: [String]] = [:]
        for candidate in report.candidates {
            var ids: [String] = []
            if case .now(let found) = state.sealedNow[candidate.id] { ids = found }
            if let sealed = state.sealedIDs[candidate.id] { ids.append(sealed) }
            guard !ids.isEmpty else { continue }
            for origin in candidate.origins {
                let project = origin.projectPath
                for id in ids where !(keys[project] ?? []).contains(id) { keys[project, default: []].append(id) }
                if !(places[project] ?? []).contains(origin.path) { places[project, default: []].append(origin.path) }
            }
        }
        var book = projectBook
        return keys.keys.sorted().compactMap { folder in
            let name = book.project(at: folder)?.name ?? book.suggestedName(for: known[folder]?.path ?? folder)
            let project = Projects.Project(name: name, folder: folder, keys: keys[folder] ?? [], places: Array((places[folder] ?? []).prefix(Projects.maxPlaces)))
            try? book.merge(project)
            return project
        }
    }

    /// Keeps the projects found, adding keys and places to those already kept. The person's action.
    public func rememberProjects() {
        let found = projectsFound()
        guard !found.isEmpty else { return }
        do {
            projectBook = try Projects.update(at: projectsFile) { book in
                for project in found { try book.merge(project) }
            }
            bringing?.projectsKept = found.count
            audit(found.map { ($0.name, "project \($0.folder): \($0.keys.count) keys") }, event: "project")
            message = found.count == 1 ? T("1 project kept") : T("%d projects kept", found.count)
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be saved", Projects.fileName)
        }
    }

    public func removeProject(_ project: Projects.Project) {
        do {
            projectBook = try Projects.update(at: projectsFile) { $0.remove(folder: project.folder) }
            audit([(project.name, "project removed")], event: "project")
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be saved", Projects.fileName)
        }
    }

    /// Where each of a project's keys stands: in the vault, or missing from it.
    public func keyStates(of project: Projects.Project) -> (sealed: [String], missing: [String]) {
        let vault = (try? vaultStore.load())?.entries ?? [:]
        var sealed: [String] = []
        var missing: [String] = []
        for id in project.keys {
            if let key = indexed(id), vault[key.source] != nil { sealed.append(id) } else { missing.append(id) }
        }
        return (sealed, missing)
    }

    /// Keys the last Bring in found in this project that the vault does not hold.
    public func newKeys(in project: Projects.Project) -> Int {
        (lastFound[project.folder] ?? []).filter { found in
            switch found.sealed {
            case .now, .earlier: return false
            default: return true
            }
        }.count
    }

    /// A key set of the project's keys that agents are offered, named after it, and kept with it.
    public func makeKeySet(for project: Projects.Project) {
        let offered = project.keys.filter { keyIndex.key($0) != nil }
        guard !offered.isEmpty else {
            message = T("None of this project's keys is offered to agents, so a set would be empty. Offer them first.")
            return
        }
        let sets = loadSets()
        let name = project.set ?? (sets.set(project.name) == nil ? project.name : sets.suggestedName(for: project.folder))
        guard saveSet(KeySets.Set(name: name, keys: Array(offered.prefix(KeySets.maxKeys)), folder: project.folder)) else { return }
        do {
            projectBook = try Projects.update(at: projectsFile) { book in
                var changed = project
                changed.set = name
                try book.save(changed)
            }
            message = offered.count > KeySets.maxKeys
                ? T("Key set %@ made with the first %d keys", name, KeySets.maxKeys) : T("Key set %@ made", name)
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be saved", Projects.fileName)
        }
    }
}

/// A folder chooser, kept apart so the model reads simply.
enum NSOpenPanelFactory {
    @MainActor static func folder(message: String) -> () -> URL? {
        {
            let panel = NSOpenPanel()
            panel.canChooseFiles = false
            panel.canChooseDirectories = true
            panel.message = message
            panel.prompt = T("Choose")
            return panel.runModal() == .OK ? panel.url : nil
        }
    }
}
