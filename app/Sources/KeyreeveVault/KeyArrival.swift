import Foundation

/// The one way a key gets into the vault, whatever path it takes: every entry leaves a record in keys.toml, not
/// offered to agents, that says who sealed it and when; and a new value for a key already there waits beside it,
/// under `<name>#pending`, until the person accepts it with a fingerprint. Nothing here opens a value.
public enum KeyArrival {
    /// What a record says when the person sealed the key in the app.
    public static let byPerson = "you, in Keyreeve"

    /// Who sealed something, as the other events of the usage log name it: the agent, when the process tree or
    /// `KEYREEVE_AGENT` names one, or else the program that ran this and the ones above it. A hint, not proof.
    public static func addedBy(observed: AuditLog.Observed, declared: String?) -> String {
        let parents = Array(observed.chain.dropFirst())
        let knownAgent = parents.contains { $0.lowercased().contains("claude") || $0.lowercased().contains("codex") }
        if knownAgent || declared.flatMap(AgentPolicy.cleanAgentName) != nil {
            return AgentBridge.agentName(chain: observed.chain, declared: declared)
        }
        return parents.isEmpty ? "a program" : parents.prefix(4).joined(separator: " < ")
    }

    /// The agent, when one is named: what the usage log keeps as declared.
    public static func agent(observed: AuditLog.Observed, declared: String?) -> String? {
        let parents = observed.chain.dropFirst()
        let knownAgent = parents.contains { $0.lowercased().contains("claude") || $0.lowercased().contains("codex") }
        return knownAgent || declared.flatMap(AgentPolicy.cleanAgentName) != nil
            ? AgentBridge.agentName(chain: observed.chain, declared: declared) : nil
    }

    public static func stamp(_ date: Date = Date()) -> String {
        ISO8601DateFormatter.string(from: date, timeZone: .gmt, formatOptions: [.withInternetDateTime])
    }

    /// The identifier a vault name gets: the name without `added/`, made valid, with a number if it is taken.
    public static func identifier(for name: String, in index: KeyIndex) -> String {
        let bare = name.hasPrefix(VaultFile.pastedFolder) ? String(name.dropFirst(VaultFile.pastedFolder.count)) : name
        return index.identifier(for: bare)
    }

    /// The record of a vault entry, not offered to agents: the one it has, or a new one. A key the person sealed in
    /// the app is reviewed; anything else waits under "New, not reviewed".
    @discardableResult
    public static func record(
        _ name: String, in index: inout KeyIndex, addedBy: String?, reviewed: Bool, now: Date = Date(),
        description: String? = nil, tags: [String]? = nil
    ) throws -> KeyIndex.Key {
        if let existing = index.allKeys(forSource: name).first { return existing }
        let description = description?.trimmingCharacters(in: .whitespacesAndNewlines)
        var key = KeyIndex.Key(id: identifier(for: name, in: index), source: name, description: description?.isEmpty == false ? description : nil)
        let tags = (tags ?? []).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        key.more.tags = tags.isEmpty ? nil : tags
        key.more.addedBy = addedBy
        key.more.addedAt = stamp(now)
        key.more.reviewed = reviewed
        try index.addUnoffered(key)
        return key
    }

    /// Seals a new key and writes its record in one step, under the vault's lock, so two at once never lose a
    /// record. If keys.toml cannot be written, nothing is sealed.
    public static func add(
        _ value: Data, as name: String, addedBy: String, description: String? = nil, tags: [String]? = nil,
        store: VaultStore, index indexURL: URL, now: Date = Date()
    ) throws -> KeyIndex.Key {
        try VaultFile.check(name: name)
        guard !VaultFile.isTemporary(name) else { throw VaultError("that name is kept for a rotation") }
        return try store.update { vault in
            if vault.entries[name] != nil { throw VaultError("\(name) already exists") }
            try vault.add(name: name, value: value, now: now)
            return try writeRecord(
                name, addedBy: addedBy, reviewed: false, description: description, tags: tags, index: indexURL, now: now)
        }
    }

    /// Reads keys.toml as it is now, adds the record and writes it back. Called inside the vault's lock, before
    /// the vault is saved: a keys.toml that cannot be read or written stops the vault change too.
    private static func writeRecord(
        _ name: String, addedBy: String?, reviewed: Bool, description: String? = nil, tags: [String]? = nil,
        index indexURL: URL, now: Date
    ) throws -> KeyIndex.Key {
        var index = try KeyIndex.load(from: indexURL)
        if let existing = index.allKeys(forSource: name).first { return existing }
        let key = try record(name, in: &index, addedBy: addedBy, reviewed: reviewed, now: now, description: description, tags: tags)
        try PrivateFile.write(Data(index.toml.utf8), to: indexURL)
        return key
    }

    /// Gives a record to each of these vault entries that has none. For `reseal`, and for the app's button on a key
    /// sealed with no record. Returns the records made.
    public static func giveRecords(
        to names: [String], addedBy: String?, reviewed: Bool, index indexURL: URL, now: Date = Date()
    ) throws -> [KeyIndex.Key] {
        var index = try KeyIndex.load(from: indexURL)
        var made: [KeyIndex.Key] = []
        for name in names where index.allKeys(forSource: name).isEmpty && !VaultFile.isTemporary(name) {
            made.append(try record(name, in: &index, addedBy: addedBy, reviewed: reviewed, now: now))
        }
        if !made.isEmpty { try PrivateFile.write(Data(index.toml.utf8), to: indexURL) }
        return made
    }

    /// Vault entries with no record in keys.toml, such as keys an older version sealed. In a book of every key
    /// (schema 2) that is any entry; in a first-version book, files from the keys folder have their own line in
    /// the list and never had one, so only keys with no file count.
    public static func orphans(in vault: VaultFile, index: KeyIndex) -> [String] {
        let recorded = Set((index.keys + index.unoffered).map(\.source))
        return vault.entries.filter { name, entry in
            !VaultFile.isTemporary(name) && !recorded.contains(name)
                && (index.schema >= 2 || entry.source == nil || name.hasPrefix(VaultFile.pastedFolder))
        }.keys.sorted()
    }

    // MARK: A new value for a key already there

    public static func waitingName(_ name: String) -> String { name + "#pending" }

    /// The keys whose rotation is open in the journal. Read as the engine reads it: the latest rotation of a key
    /// is open until it completes or rolls back.
    public static func openRotations(journal: URL) -> Set<String> {
        guard let data = try? Data(contentsOf: journal) else { return [] }
        var latest: [String: Int] = [:]
        var open: [String: Bool] = [:]
        for line in data.split(separator: 10) {
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                let key = object["key"] as? String, let rotation = object["rotation"] as? Int, let event = object["event"] as? String
            else { continue }
            if rotation > latest[key, default: -1] {
                latest[key] = rotation
                open[key] = false
            }
            guard rotation == latest[key] else { continue }
            switch event {
            case "completed", "rolled_back": open[key] = false
            case "sink_updated", "manual_action", "replaced": break
            default: open[key] = true
            }
        }
        return Set(open.filter(\.value).keys)
    }

    public enum PutOutcome: Equatable {
        /// There was no such key: it went in as `add` would, with a record.
        case added(KeyIndex.Key)
        /// Its own rotation replaced it: the old value stays as history.
        case replacedByRotation
        /// The new value waits under `<name>#pending`, and the current one stays in force.
        case waiting
        /// A rotation's temporary copy, written as before.
        case temporary
    }

    /// `keyreeve-vault put`. A new name goes in with a record. A key that is there is replaced only by its own
    /// rotation, which saved the old value as `#previous` first and runs from keyreeve's engine; any other new value
    /// waits for the person. `byEngine` is whether the program that ran this is keyreeve's engine, from the system.
    public static func put(
        _ value: Data, as name: String, addedBy: String, byEngine: Bool, journal: URL, store: VaultStore, index indexURL: URL,
        now: Date = Date()
    ) throws -> PutOutcome {
        try VaultFile.check(name: name)
        let rotating = openRotations(journal: journal)
        return try store.update { vault in
            if VaultFile.isTemporary(name) {
                // A rotation's temporary copies have no history worth keeping.
                vault.entries[name] = nil
                try vault.replace(name: name, value: value, now: now)
                if name.hasSuffix("#pending") { vault.entries[name]?.from = addedBy }
                return .temporary
            }
            guard vault.entries[name] != nil else {
                try vault.add(name: name, value: value, now: now)
                return .added(try writeRecord(name, addedBy: addedBy, reviewed: false, index: indexURL, now: now))
            }
            if rotating.contains(name) {
                guard byEngine, vault.entries[name + "#previous"] != nil else {
                    throw VaultError("a rotation of \(name) is open, so a new value cannot wait beside it. Try again once it ends")
                }
                try vault.replace(name: name, value: value, now: now)
                return .replacedByRotation
            }
            // A newer value that waits takes the place of an older one: neither was ever in force.
            let pending = waitingName(name)
            vault.entries[pending] = nil
            try vault.add(name: pending, value: value, now: now)
            vault.entries[pending]?.from = addedBy
            return .waiting
        }
    }

    /// The keys with a new value waiting for the person, and who put each. A rotation's own copy is not one.
    public static func waiting(in vault: VaultFile, journal: URL) -> [(name: String, from: String?)] {
        let pending = vault.entries.filter { $0.key.hasSuffix("#pending") }
        guard !pending.isEmpty else { return [] }
        let rotating = openRotations(journal: journal)
        return pending.compactMap { waitingName, entry -> (name: String, from: String?)? in
            let name = String(waitingName.dropLast("#pending".count))
            guard vault.entries[name] != nil, !rotating.contains(name) else { return nil }
            return (name, entry.from)
        }.sorted { $0.name < $1.name }
    }

    /// Puts the waiting value in force. The current one stays as history, as any replacement keeps it. Opening it
    /// takes the person's fingerprint, in `identity`.
    public static func accept(_ name: String, with identity: Age.Identity, journal: URL, store: VaultStore, now: Date = Date()) throws {
        guard !openRotations(journal: journal).contains(name) else { throw VaultError("a rotation of \(name) is open") }
        try store.update { vault in
            let pending = waitingName(name)
            guard vault.entries[name] != nil, vault.entries[pending] != nil else {
                throw VaultError("no new value for \(name) is waiting")
            }
            let value = try vault.open(name: pending, with: identity)
            try vault.replace(name: name, value: value, now: now)
            vault.entries[pending] = nil
        }
    }

    /// Throws the waiting value away. The key keeps the value it had.
    public static func discard(_ name: String, journal: URL, store: VaultStore) throws {
        guard !openRotations(journal: journal).contains(name) else { throw VaultError("a rotation of \(name) is open") }
        try store.update { vault in
            guard vault.entries[waitingName(name)] != nil else { throw VaultError("no new value for \(name) is waiting") }
            vault.entries[waitingName(name)] = nil
        }
    }
}
