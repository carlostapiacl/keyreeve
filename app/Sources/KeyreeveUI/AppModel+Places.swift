import Foundation
import KeyreeveCatalog
import KeyreeveVault

/// Where each key lives, as the app holds it: the book of places, the procedures the engine knows, and the
/// hashes the last checks found, which stay in memory and are never written.
public struct PlacesState: Equatable, Sendable {
    public var book = PlaceBook()
    public var procedures: [ProcedureInfo] = []
    /// Place id to the hash its last check found, kept only to compare once a value is opened.
    var found: [String: String] = [:]
    public var running: Set<String> = []
    public init() {}
}

@MainActor
extension AppModel {
    var placesFile: URL { PlaceBook.file(home: files.directory) }
    var digestsFile: URL { files.directory.appendingPathComponent(ValueDigests.fileName) }
    public var proceduresFolder: URL { PlaceBook.proceduresFolder(home: files.directory) }

    /// Reads the book, and asks the engine for its procedures in the background.
    public func reloadPlaces() {
        let book = PlaceBook.load(from: placesFile)
        if book != placesState.book { placesState.book = book }
        if !book.places.isEmpty { ensureDigestKey() }
        guard let binary else { return }
        let folder = proceduresFolder
        Task.detached {
            let list = PlaceRunner.procedures(binary: binary, folder: folder)
            await MainActor.run { if list != self.placesState.procedures { self.placesState.procedures = list } }
        }
    }

    /// The identifiers of a key's file: places belong to identifiers.
    func keyIDs(of item: CatalogItem) -> [String] { keyIndex.allKeys(forSource: item.path).map(\.id) }

    public func knownPlaces(for item: CatalogItem) -> [PlaceBook.Place] {
        let ids = Set(keyIDs(of: item))
        return placesState.book.places.filter { ids.contains($0.key) }
    }

    /// A key with no place: no procedure place, and no file or button set for its rotation.
    public func hasNoPlace(_ item: CatalogItem) -> Bool {
        knownPlaces(for: item).isEmpty && (places[item.path].map { !$0.isDecided } ?? true)
    }

    public var procedurePins: [String: String] { PlaceRunner.pins(placesState.procedures) }

    public func procedure(named name: String) -> ProcedureInfo? {
        placesState.procedures.first { $0.name == name && $0.problem == nil }
    }

    public func status(of place: PlaceBook.Place) -> PlaceBook.Status {
        // Before the engine lists its procedures, an approved place reads as approved: the engine checks the pin
        // again before it runs anything, and refuses one that changed.
        guard !placesState.procedures.isEmpty else { return place.sha256 == nil ? .waiting : .approved }
        return PlaceBook.status(of: place, currentPin: procedurePins[place.procedure])
    }

    /// The places a rotation of this key runs: approved, with the procedure still the one approved.
    func plannedProcedures(for item: CatalogItem) -> [PlannedProcedure] {
        knownPlaces(for: item).filter { status(of: $0) == .approved }.compactMap { place in
            place.sha256.map { PlannedProcedure(label: place.label, procedure: place.procedure, sha256: $0, params: place.params) }
        }
    }

    /// Places that rotation would leave out because they wait for the person.
    public func placesNeedingApproval(for item: CatalogItem) -> [PlaceBook.Place] {
        knownPlaces(for: item).filter { status(of: $0) != .approved }
    }

    // MARK: Checking

    /// Has each value the vault seals or opens in this process leave its keyed digest, so places compare with no
    /// fingerprint. Set once, when the app starts.
    public nonisolated static func learnValueDigests(files: KeyreeveFiles = KeyreeveFiles()) {
        let store = VaultStore(directory: files.directory.appendingPathComponent("vault"))
        VaultEvents.observe(VaultEvents.recorder(store: store, file: files.directory.appendingPathComponent(ValueDigests.fileName)))
    }

    /// Gives the vault its chip key that needs no fingerprint, which keyed digests come from, once places are in use.
    /// Making it asks nothing. Without a chip it fails, and places say "not compared".
    func ensureDigestKey() {
        let store = vaultStore
        Task.detached { _ = try? store.ensureUnattended() }
    }

    /// Where each key is sealed now: its vault name, its field and which sealing.
    func sealing(of keys: [String]) -> [String: (name: String, field: String?, revision: String?)] {
        let vault = try? vaultStore.load()
        var out: [String: (name: String, field: String?, revision: String?)] = [:]
        for key in Set(keys) {
            guard let found = indexed(key) else { continue }
            out[key] = (found.source, found.field, vault?.entries[found.source]?.revision)
        }
        return out
    }

    /// How each hash compares, with the keyed digests and the chip key as they are now.
    nonisolated static func compare(
        _ found: [String: String], places: [PlaceBook.Place], sealing: [String: (name: String, field: String?, revision: String?)],
        digests: ValueDigests, key: DigestKey?
    ) -> [String: PlaceBook.Result] {
        var out: [String: PlaceBook.Result] = [:]
        for place in places {
            guard let hash = found[place.id] else { continue }
            guard let sealed = sealing[place.key] else {
                out[place.id] = .notCompared
                continue
            }
            out[place.id] = digests.compare(hash, name: sealed.name, field: sealed.field, revision: sealed.revision, key: key)
        }
        return out
    }

    /// Asks each place for the hash of the value it holds, with no fingerprint, and compares its keyed digest with
    /// the vault's. A place whose procedure changed is not run.
    public func checkPlaces(_ list: [PlaceBook.Place]) {
        guard let binary, !list.isEmpty else { return }
        // Until the engine has listed its procedures every pin would look changed, so nothing runs yet.
        guard !placesState.procedures.isEmpty else {
            message = T("The procedures are still loading. Try again in a moment.")
            reloadPlaces()
            return
        }
        let pins = procedurePins
        let folder = proceduresFolder
        let tool = vaultTool
        let digestsFile = self.digestsFile
        let store = vaultStore
        let sealing = sealing(of: list.map(\.key))
        let file = placesFile
        placesState.running.formUnion(list.map(\.id))
        message = list.count == 1 ? T("Checking 1 place…") : T("Checking %d places…", list.count)
        Task.detached {
            var gathered: [String: PlaceBook.Check] = [:]
            var hashes: [String: String] = [:]
            for place in list {
                let now = Date()
                guard let pin = place.sha256 else {
                    gathered[place.id] = PlaceBook.Check(at: now, result: .error, detail: "not approved yet")
                    continue
                }
                guard pins[place.procedure]?.lowercased() == pin.lowercased() else {
                    gathered[place.id] = PlaceBook.Check(at: now, result: .changed)
                    continue
                }
                switch PlaceRunner.check(
                    procedure: place.procedure, pin: pin, params: place.params, binary: binary, folder: folder, vaultTool: tool)
                {
                case .hash(let hash):
                    hashes[place.id] = hash
                    gathered[place.id] = PlaceBook.Check(at: now, result: .notCompared)
                case .absent: gathered[place.id] = PlaceBook.Check(at: now, result: .absent)
                case .present: gathered[place.id] = PlaceBook.Check(at: now, result: .present)
                case .failed(let why): gathered[place.id] = PlaceBook.Check(at: now, result: .error, detail: why)
                }
            }
            // The chip key is read with no prompt. Without it every hash stays "not compared".
            let key = (try? store.load()).flatMap { DigestKey.load(vault: $0, store: store) }
            for (id, result) in Self.compare(
                hashes, places: list, sealing: sealing, digests: ValueDigests.load(from: digestsFile), key: key)
            {
                gathered[id]?.result = result
            }
            let (results, found) = (gathered, hashes)
            let saved = Result { try PlaceBook.update(at: file) { book in Self.record(results, in: &book) } }
            await MainActor.run {
                self.placesState.running.subtract(list.map(\.id))
                self.placesState.found.merge(found) { $1 }
                for place in list where found[place.id] == nil { self.placesState.found[place.id] = nil }
                if case .success(let book) = saved { self.placesState.book = book }
                self.audit(list.compactMap { place in
                    results[place.id].map { (place.key, "place \(place.label): \($0.result.rawValue)") }
                }, event: "place-checked")
                let same = results.values.filter { $0.result == .same }.count
                self.message = T("%d of %d places hold the value in the vault", same, list.count)
            }
        }
    }

    nonisolated static func record(_ results: [String: PlaceBook.Check], in book: inout PlaceBook) {
        for index in book.places.indices {
            if let check = results[book.places[index].id] { book.places[index].lastCheck = check }
        }
    }

    func indexed(_ id: String) -> KeyIndex.Key? { keyIndex.key(id) ?? keyIndex.unoffered.first { $0.id == id } }

    /// Opens these keys once, with the fingerprint, so a key sealed before keyed digests leaves its own, then compares
    /// the places last checked. Any other opening of a key does the same; this is for the ones not opened since.
    public func compareWithVault(_ list: [PlaceBook.Place]) {
        let keys = Array(Set(list.map(\.key))).sorted()
        let names = Array(Set(keys.compactMap { indexed($0)?.source })).sorted()
        guard !names.isEmpty else { return }
        let reason = keys.count == 1 ? T("compare 1 key with where it lives") : T("compare %d keys with where they live", keys.count)
        let store = vaultStore
        openVault(reason: reason) { unlocked in
            guard let unlocked else {
                self.message = T("Not compared: it was not confirmed")
                return
            }
            let file = self.digestsFile
            let found = self.placesState.found
            let placesFile = self.placesFile
            let sealing = self.sealing(of: keys)
            Task.detached {
                let outcome = Result { () throws -> PlaceBook in
                    _ = try? store.ensureUnattended()
                    // Opening leaves each value's keyed digest, through the vault's own recorder.
                    _ = try VaultKeeper.open(names: names, recipient: try unlocked.recipient(store), store: store, by: "place")
                    let key = (try? store.load()).flatMap { DigestKey.load(vault: $0, store: store) }
                    let book = PlaceBook.load(from: placesFile)
                    let results = Self.compare(
                        found, places: book.places, sealing: sealing, digests: ValueDigests.load(from: file), key: key)
                    return try PlaceBook.update(at: placesFile) { book in
                        for index in book.places.indices {
                            if let result = results[book.places[index].id] { book.places[index].lastCheck?.result = result }
                        }
                    }
                }
                await MainActor.run {
                    switch outcome {
                    case .success(let book):
                        self.placesState.book = book
                        self.audit(keys.map { ($0, "compared with where it lives") }, event: "place-compared")
                        self.message = T("Compared with the vault")
                    case .failure: self.message = T("The vault could not be opened")
                    }
                }
            }
        }
    }

    // MARK: Updating

    /// Puts the key's value now in one place, with the fingerprint, then checks it there.
    public func updatePlace(_ place: PlaceBook.Place) {
        guard let binary, let pin = place.sha256, status(of: place) == .approved, let key = indexed(place.key) else {
            message = T("This place waits for your approval, so it was not updated")
            return
        }
        let folder = proceduresFolder
        let tool = vaultTool
        openVault(reason: T("put %@ in %@", place.key, place.label)) { unlocked in
            guard let unlocked else {
                self.message = T("Not updated: it was not confirmed")
                return
            }
            let store = self.vaultStore
            self.placesState.running.insert(place.id)
            Task.detached {
                let outcome = Result { () throws in
                    guard (try store.load()).entries[key.source] != nil else { throw CheckError(T("This key is not in the vault")) }
                    // Opening it also leaves its keyed digest, so the check after compares.
                    let sealed = try VaultKeeper.open(
                        names: [key.source], recipient: try unlocked.recipient(store), store: store, by: "place")
                    let value = try EnvReferences.value(in: Data((sealed[key.source] ?? "").utf8), field: key.field)
                    try PlaceRunner.apply(
                        procedure: place.procedure, pin: pin, params: place.params, value: value, binary: binary, folder: folder,
                        vaultTool: tool)
                }
                await MainActor.run {
                    self.placesState.running.remove(place.id)
                    switch outcome {
                    case .success:
                        self.audit([(place.key, "place \(place.label): updated")], event: "place-updated")
                        self.checkPlaces([place])
                    case .failure(let error):
                        self.audit([(place.key, "place \(place.label): not updated")], event: "place-updated")
                        self.message = (error as? CheckError)?.description ?? T("The place was not updated")
                    }
                }
            }
        }
    }

    // MARK: Approving

    /// Approves places with one fingerprint, each pinned to its procedure as it is now. A procedure the engine
    /// does not know is left out.
    public func approvePlaces(_ list: [PlaceBook.Place], then done: (@MainActor (Int) -> Void)? = nil) {
        let pins = procedurePins
        let ready = list.filter { pins[$0.procedure] != nil }
        guard !ready.isEmpty else {
            message = T("None of these procedures is known, so nothing was approved")
            done?(0)
            return
        }
        let reason = ready.count == 1 ? T("approve 1 place for your keys") : T("approve %d places for your keys", ready.count)
        openVault(reason: reason) { unlocked in
            guard unlocked != nil else {
                self.message = T("Not approved: it was not confirmed")
                done?(0)
                return
            }
            var count = 0
            do {
                self.placesState.book = try PlaceBook.update(at: self.placesFile) { book in
                    count = book.approve(ready, pins: pins, at: Date())
                }
            } catch {
                self.message = (error as? VaultError)?.description ?? T("%@ could not be saved", PlaceBook.fileName)
                done?(0)
                return
            }
            self.audit(ready.map { ($0.key, "place \($0.label) approved, \($0.procedure) \($0.params.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))") }, event: "place-approved")
            self.message = count == 1 ? T("1 place approved") : T("%d places approved", count)
            done?(count)
        }
    }

    /// A place is forgotten. Nothing at the place changes.
    public func removePlace(_ place: PlaceBook.Place) {
        do {
            placesState.book = try PlaceBook.update(at: placesFile) { book in book.places.removeAll { $0.id == place.id } }
            audit([(place.key, "place \(place.label) removed")], event: "place-removed")
        } catch {
            message = (error as? VaultError)?.description ?? T("%@ could not be saved", PlaceBook.fileName)
        }
    }

    // MARK: An agent's proposal

    public func proposedPlaces(for request: AccessRequests.Entry) -> [PlaceBook.Place] {
        guard let data = AgentSorting.load(id: request.id, home: files.directory) else { return [] }
        return AgentBridge.proposedPlaces(data)
    }

    /// Approves the chosen places of an agent's proposal with one fingerprint. The rest are dropped.
    public func approveProposal(_ request: AccessRequests.Entry, chosen: [PlaceBook.Place]) {
        approvePlaces(chosen) { count in
            guard count > 0 else { return }
            self.answerPlaces(request, approved: count)
        }
    }

    /// Declines an agent's proposal: nothing is kept, not even the list.
    public func declinePlaces(_ request: AccessRequests.Entry) {
        decline(request)
        try? FileManager.default.removeItem(at: AgentSorting.proposalFile(id: request.id, home: files.directory))
    }

    func answerPlaces(_ request: AccessRequests.Entry, approved: Int) {
        try? AccessRequests.append(
            AccessRequests.Entry(
                id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider, kind: "places",
                result: "approved \(approved) places"),
            to: requestsFile)
        try? FileManager.default.removeItem(at: AgentSorting.proposalFile(id: request.id, home: files.directory))
        reloadRequests()
    }

    // MARK: What else says where a key is

    /// Programs, folders and agents that used one of this key's identifiers in the last 30 days, from the usage log.
    public func usedBy(_ item: CatalogItem, now: Date = Date()) -> [(program: String, folder: String?, agent: String?)] {
        let ids = Set(keyIDs(of: item) + [item.path])
        let since = now.addingTimeInterval(-30 * 86400)
        var seen = Set<String>()
        var out: [(String, String?, String?)] = []
        for entry in usage.entries where ids.contains(entry.key) && entry.at >= since && !entry.event.hasPrefix("place") {
            guard let program = entry.observed.map({ URL(fileURLWithPath: $0.program).lastPathComponent }), !program.isEmpty else { continue }
            let folder = entry.declared?.cwd
            let agent = entry.declared?.agent
            let mark = [program, folder ?? "", agent ?? ""].joined(separator: "\u{0}")
            if seen.insert(mark).inserted { out.append((program, folder, agent)) }
        }
        return out
    }

    /// Where Bring in found this key, as its sealed copy notes it.
    public func foundAt(_ item: CatalogItem) -> [String] {
        guard let source = (try? vaultStore.load())?.entries[item.path]?.source else { return [] }
        return source.split(separator: "\n").map(String.init).filter { $0.hasPrefix("/") || $0.hasPrefix("~") }
    }
}
