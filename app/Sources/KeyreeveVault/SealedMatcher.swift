import Foundation

/// Tells whether a value Bring in found is already in the vault, with no value and no fingerprint. The engine hands
/// over each value's plain SHA-256 apart from its report, in a private file read and removed at once; this turns each
/// into the keyed digest only this Mac can make and looks it up among the vault's, in `value-digests.json`. The plain
/// hash is dropped here: it never reaches an agent, a report, a log or a file that stays.
public struct SealedMatcher: Sendable {
    /// Where a found value matched: a vault entry, the field it matched in, and the keys that name it.
    public struct Hit: Equatable, Sendable {
        /// Every key whose sealed value holds it, offered to agents or not. Only offered ones are ever shown to an agent.
        public var ids: [String]
        /// An earlier value of those keys, such as the one before a rotation, not the one sealed now.
        public var earlier: Bool

        public init(ids: [String], earlier: Bool) {
            self.ids = ids
            self.earlier = earlier
        }
    }

    /// How much of the vault is known: entries whose value now has a keyed digest, of all entries.
    public struct Coverage: Equatable, Sendable {
        public var known: Int
        public var total: Int
        public var complete: Bool { known >= total }

        public init(known: Int, total: Int) {
            self.known = known
            self.total = total
        }
    }

    private struct Spot: Hashable, Sendable {
        var name: String
        var field: String
        var current: Bool
    }

    let key: DigestKey
    private let spots: [String: [Spot]]
    /// Vault name to the keys that name it, with the field each one takes.
    private let keys: [String: [(id: String, field: String?)]]
    public let coverage: Coverage

    /// - Parameters:
    ///   - revisions: each vault entry's name and the sealing it holds now.
    ///   - keys: every key in keys.toml, offered or not, as id, vault name and field.
    public init(digests: ValueDigests, key: DigestKey, revisions: [String: String], keys: [(id: String, source: String, field: String?)]) {
        self.key = key
        var spots: [String: [Spot]] = [:]
        for (name, sealings) in digests.entries where revisions[name] != nil {
            for (revision, fields) in sealings {
                for (field, digest) in fields {
                    spots[digest, default: []].append(Spot(name: name, field: field, current: revision == revisions[name]))
                }
            }
        }
        self.spots = spots
        var byName: [String: [(id: String, field: String?)]] = [:]
        for key in keys { byName[key.source, default: []].append((key.id, key.field)) }
        self.keys = byName
        let known = revisions.filter { digests.knows(name: $0.key, revision: $0.value) }.count
        coverage = Coverage(known: known, total: revisions.count)
    }

    /// The vault entries that hold every part of a key found: a value alone matches the whole of an entry or one of its
    /// fields, and a key of several parts matches an entry that holds each of them. A current value wins over an earlier
    /// one. Nil when nothing matches, which says "new" only if `coverage` is complete.
    public func match(_ hexes: [String]) -> Hit? {
        guard !hexes.isEmpty else { return nil }
        let found: [[Spot]] = hexes.map { hex in key.digest(ofHex: hex).flatMap { spots[$0] } ?? [] }
        for current in [true, false] {
            var names: Set<String>?
            var fieldsByName: [String: [String]] = [:]
            for spotsOfPart in found {
                let these = spotsOfPart.filter { $0.current == current }
                for spot in these { fieldsByName[spot.name, default: []].append(spot.field) }
                let partNames = Set(these.map(\.name))
                names = names.map { $0.intersection(partNames) } ?? partNames
            }
            guard let names, !names.isEmpty else { continue }
            var ids: [String] = []
            for name in names.sorted() {
                let fields = Set(fieldsByName[name] ?? [])
                let all = keys[name] ?? []
                // The key that takes the field the value matched, else the one that takes the whole entry, else any.
                let exact = all.filter { key in key.field.map { fields.contains($0) } ?? false }
                let whole = all.filter { $0.field == nil }
                let chosen = !exact.isEmpty ? exact : !whole.isEmpty ? whole : all
                for key in chosen where !ids.contains(key.id) { ids.append(key.id) }
            }
            return Hit(ids: ids, earlier: !current)
        }
        return nil
    }

    // MARK: Loading, with no prompt

    /// Why the vault's values could not be compared.
    public enum Unavailable: String, Sendable {
        case noVault = "no-vault"
        /// No digest is known yet: the person has not had Keyreeve learn what the vault holds.
        case nothingLearned = "not-learned"
        /// The chip key that asks nothing, which digests come from, is not on this Mac.
        case noKey = "no-chip-key"
    }

    /// The matcher for this vault, read with no fingerprint: its keyed digests and the chip key that needs none.
    public static func load(store: VaultStore, digestsFile: URL, keys: KeyIndex?) -> Result<SealedMatcher, UnavailableError> {
        guard let vault = try? store.load() else { return .failure(UnavailableError(.noVault)) }
        let digests = ValueDigests.load(from: digestsFile)
        guard !digests.entries.isEmpty else { return .failure(UnavailableError(.nothingLearned)) }
        guard let key = DigestKey.load(vault: vault, store: store) else { return .failure(UnavailableError(.noKey)) }
        let revisions = vault.entries.filter { !VaultFile.isTemporary($0.key) }.mapValues(\.revision)
        let all = (keys?.keys ?? []) + (keys?.unoffered ?? [])
        return .success(SealedMatcher(
            digests: digests, key: key, revisions: revisions, keys: all.map { ($0.id, $0.source, $0.field) }))
    }

    public struct UnavailableError: Error, Sendable {
        public var reason: Unavailable
        public init(_ reason: Unavailable) { self.reason = reason }
    }
}

// MARK: Learning what the vault holds

extension ValueDigests {
    /// Opens every sealed value once, with the one fingerprint the caller already has, and records the keyed digest of
    /// each and of each field. Values stay in memory only for as long as each digest takes. Returns how many were
    /// learned and how many could not be opened.
    @discardableResult
    public static func learnAll(
        revisions: [String: String], open: (String) throws -> Data, key: DigestKey, file: URL, now: Date = Date()
    ) throws -> (learned: Int, failed: Int) {
        var made: [(name: String, revision: String, digests: [String: String])] = []
        var failed = 0
        for (name, revision) in revisions.sorted(by: { $0.key < $1.key }) where !VaultFile.isTemporary(name) {
            do {
                var value = try open(name)
                defer { value.resetBytes(in: 0..<value.count) }
                made.append((name, revision, digests(of: value, key: key)))
            } catch {
                failed += 1
            }
        }
        try update(at: file) { book in
            for one in made where !one.digests.isEmpty { book.entries[one.name, default: [:]][one.revision] = one.digests }
            book.learned = now
        }
        return (made.filter { !$0.digests.isEmpty }.count, failed)
    }
}

// MARK: The hashes the engine hands over

/// Runs `keyreeve bring` with `--hashes-out`, into a file in a private folder of its own, and removes both as soon as the
/// engine ends, whatever happened. The hashes stay in this process's memory only, until a matcher drops them.
public enum EngineHashes {
    /// A private folder, readable by this user alone, with a name nobody can guess, for one run.
    static func privateFolder() throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-bring-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return folder
    }

    /// Runs `body` with the arguments to add and the place the engine writes to, then reads and removes it.
    public static func around<Report>(_ body: ([String]) throws -> Report) throws -> (report: Report, hashes: [Int: [String]]) {
        let folder = try privateFolder()
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("hashes.json")
        let report = try body(["--hashes-out", file.path])
        var hashes: [Int: [String]] = [:]
        if var data = try? Data(contentsOf: file) {
            try? FileManager.default.removeItem(at: file)
            hashes = read(data)
            data.resetBytes(in: 0..<data.count)
        }
        return (report, hashes)
    }

    /// `{"schema":1,"keys":{"<n>":["<hex>",...]}}`. Anything else is nothing.
    static func read(_ data: Data) -> [Int: [String]] {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keys = object["keys"] as? [String: [String]]
        else { return [:] }
        var out: [Int: [String]] = [:]
        for (number, hexes) in keys {
            guard let number = Int(number), hexes.allSatisfy({ $0.count == 64 }) else { continue }
            out[number] = hexes
        }
        return out
    }
}
