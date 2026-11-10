import AppKit
import KeyreeveCatalog
import KeyreeveVault

/// What came in without the person: keys an agent or a program added, keys sealed with no record, and new values
/// that wait. Read from the files with no fingerprint, so the menu bar can say it while the window is locked.
/// Names and counts only, never a value.
public struct ArrivalNews: Equatable, Sendable {
    public struct Added: Equatable, Sendable {
        public var who: String
        public var count: Int
    }

    public struct Waiting: Equatable, Sendable {
        /// The key's identifier, or its vault name when it has none.
        public var key: String
        public var from: String
    }

    public var added: [Added] = []
    public var waiting: [Waiting] = []
    public var withoutRecord = 0

    public init() {}

    public var isEmpty: Bool { added.isEmpty && waiting.isEmpty && withoutRecord == 0 }

    public static func read(files: KeyreeveFiles, store: VaultStore) -> ArrivalNews {
        let index = (try? KeyIndex.load(from: files.keyIndex)) ?? KeyIndex()
        return make(index: index, vault: store.exists ? try? store.load() : nil, journal: files.rotations)
    }

    static func make(index: KeyIndex, vault: VaultFile?, journal: URL) -> ArrivalNews {
        var news = ArrivalNews()
        let someone = T("an agent or a program")
        var counts: [String: Int] = [:]
        for key in index.keys + index.unoffered where !key.more.reviewed { counts[key.more.addedBy ?? someone, default: 0] += 1 }
        news.added = counts.map { Added(who: $0.key, count: $0.value) }.sorted { ($1.count, $0.who) < ($0.count, $1.who) }
        if let vault {
            news.waiting = KeyArrival.waiting(in: vault, journal: journal).map { name, from in
                Waiting(key: index.allKeys(forSource: name).first?.id ?? name, from: from ?? someone)
            }
            news.withoutRecord = KeyArrival.orphans(in: vault, index: index).count
        }
        return news
    }

    /// The same, from the list the window already read.
    public static func make(items: [CatalogItem], index: KeyIndex) -> ArrivalNews {
        var news = ArrivalNews()
        var counts: [String: Int] = [:]
        for item in items {
            if let who = item.newFrom { counts[who, default: 0] += 1 }
            if let from = item.waitingFrom { news.waiting.append(Waiting(key: index.allKeys(forSource: item.path).first?.id ?? item.path, from: from)) }
            if item.withoutRecord { news.withoutRecord += 1 }
        }
        news.added = counts.map { Added(who: $0.key, count: $0.value) }.sorted { ($1.count, $0.who) < ($0.count, $1.who) }
        return news
    }

    /// One line for each: "claude added 21 keys".
    public var lines: [String] {
        added.map { $0.count == 1 ? T("%@ added 1 key", $0.who) : T("%@ added %d keys", $0.who, $0.count) }
            + waiting.map { T("A new value for %@ is waiting, from %@", $0.key, $0.from) }
            + (withoutRecord == 0 ? [] : [withoutRecord == 1 ? T("1 key is sealed without a record") : T("%d keys are sealed without a record", withoutRecord)])
    }
}

@MainActor
extension AppModel {
    /// Marks each key with how it got in. Done while the list is read, so it costs nothing on screen.
    nonisolated static func markArrivals(_ items: inout [CatalogItem], vault: VaultFile?, index: KeyIndex, journal: URL) {
        guard let vault else { return }
        let orphans = Set(KeyArrival.orphans(in: vault, index: index))
        let waiting = Dictionary(
            KeyArrival.waiting(in: vault, journal: journal).map { ($0.name, $0.from) }, uniquingKeysWith: { first, _ in first })
        let someone = T("an agent or a program")
        for position in items.indices {
            let path = items[position].path
            if let fresh = index.allKeys(forSource: path).first(where: { !$0.more.reviewed }) {
                items[position].newFrom = fresh.more.addedBy ?? someone
            }
            items[position].withoutRecord = orphans.contains(path)
            if let from = waiting[path] { items[position].waitingFrom = from ?? someone }
        }
    }

    /// A file the person sealed in the app gets its record too, reviewed and not offered to agents, so no key is in
    /// the vault with no identifier.
    func recordSealed(_ sealed: [CatalogItem]) {
        guard !sealed.isEmpty else { return }
        // Read and written under the lock keyreeve-vault takes too, so a record an agent just added stays.
        guard let changed = try? KeyIndex.change(at: files.keyIndex, { index in
            for item in sealed where index.allKeys(forSource: item.path).isEmpty {
                var key = KeyIndex.Key(
                    id: index.suggestion(provider: item.recipes.first, project: nil, source: item.path), source: item.path,
                    field: item.field.isEmpty ? nil : item.field, provider: item.recipes.first)
                (key.more.addedBy, key.more.addedAt) = (KeyArrival.byPerson, KeyArrival.stamp())
                try? index.addUnoffered(key)
            }
        }) else { return }
        keyIndex = changed.index
    }

    /// Reads the list again when keys.toml changed on disk since it was read: a key an agent added shows up with no
    /// restart. Called on focus and by the menu bar's ticker; a stat, and nothing more, while nothing changed.
    public func reloadIfIndexChanged() {
        guard unlocked, !settling else { return }
        let now = KeyIndex.stamp(of: files.keyIndex)
        guard now != indexStamp else { return }
        indexStamp = now
        load()
    }

    /// Brings the window to the new keys.
    public func showNewKeysNow() { showNewKeys &+= 1 }

    /// The person looked at these keys. Nothing is offered by this: offering stays its own choice.
    public func markReviewed(_ chosen: [CatalogItem]) {
        do {
            let (index, changed) = try KeyIndex.change(at: files.keyIndex) { index -> [(key: String, detail: String)] in
                var changed: [(key: String, detail: String)] = []
                for item in chosen {
                    for key in index.allKeys(forSource: item.path) where !key.more.reviewed {
                        index.update(id: key.id) { $0.more.reviewed = true }
                        changed.append((key.id, "reviewed, added by \(key.more.addedBy ?? "unknown")"))
                    }
                }
                return changed
            }
            keyIndex = index
            guard !changed.isEmpty else { return }
            audit(changed, event: "reviewed")
            message = changed.count == 1 ? T("1 key reviewed. It is still not offered to agents.") : T("%d keys reviewed. They are still not offered to agents.", changed.count)
        } catch {
            message = T("That identifier could not be saved")
        }
        load()
    }

    /// Gives a key sealed with no record its identifier, not offered to agents.
    public func giveRecord(to item: CatalogItem) {
        do {
            let made = try KeyArrival.giveRecords(to: [item.path], addedBy: nil, reviewed: true, index: files.keyIndex)
            keyIndex = try KeyIndex.load(from: files.keyIndex)
            audit(made.map { ($0.id, "identifier given to \(item.path), sealed with no record; not offered to agents") }, event: "policy")
            if let id = made.first?.id { message = T("%@ has an identifier now. It is not offered to agents.", id) }
        } catch {
            message = (error as? VaultError)?.description ?? T("That identifier could not be saved")
        }
        load()
    }

    /// Puts the waiting value in force, after the person's finger. The value it replaces stays sealed as history.
    public func acceptWaiting(_ item: CatalogItem) {
        guard !busy, let from = item.waitingFrom else { return }
        let id = auditName(of: item.path)
        openVault(reason: T("accept a new value for %@, from %@", id, from)) { unlocked in
            guard let unlocked else {
                self.message = T("Not changed: it was not confirmed")
                return
            }
            let store = self.vaultStore
            let journal = self.files.rotations
            let name = item.path
            let epoch = self.lockEpoch
            self.busy = true
            Task.detached {
                let result = Result { try KeyArrival.accept(name, with: try unlocked.recipient(store), journal: journal, store: store) }
                await MainActor.run {
                    self.busy = false
                    guard epoch == self.lockEpoch else { return }
                    switch result {
                    case .success:
                        self.audit([(id, "accepted a new value from \(from); the old one stays sealed as history")], event: "sealed")
                        // What was opened with the old value is not what the person said yes to.
                        self.revoke(key: id)
                        self.message = T("The new value of %@ is in force. The old one stays sealed.", id)
                    case .failure(let error):
                        self.message = (error as? VaultError)?.description ?? T("The vault could not be saved")
                    }
                    self.load()
                }
            }
        }
    }

    /// Throws the waiting value away. The key keeps the value it had.
    public func discardWaiting(_ item: CatalogItem) {
        guard let from = item.waitingFrom else { return }
        let id = auditName(of: item.path)
        do {
            try KeyArrival.discard(item.path, journal: files.rotations, store: vaultStore)
            audit([(id, "discarded a new value from \(from)")], event: "sealed")
            message = T("Discarded. %@ keeps the value it had.", id)
        } catch {
            message = (error as? VaultError)?.description ?? T("The vault could not be saved")
        }
        load()
    }
}
