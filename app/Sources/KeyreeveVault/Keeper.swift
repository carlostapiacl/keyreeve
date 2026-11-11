import CryptoKit
import Foundation

/// A new vault that exists only in memory until the person says they kept the recovery key.
public struct VaultDraft {
    public let recoveryKey: String
    let file: VaultFile
    let blob: Data

    public init(enclave: VaultRecipient, blob: Data, recovery: Age.X25519Identity = .init()) {
        recoveryKey = recovery.string
        file = VaultFile(enclave: enclave.publicKey, recovery: recovery.recipient)
        self.blob = blob
    }

    /// The end of the recovery key, which the person types back as proof they have it.
    public var lastGroup: String { String(recoveryKey.suffix(6)) }

    public func accepts(_ typed: String) -> Bool {
        typed.trimmingCharacters(in: .whitespaces).uppercased() == lastGroup
    }

    public func save(to store: VaultStore) throws {
        try store.create(file, blob: blob)
    }
}

/// Moves key files into the vault, and proves the copies match. Originals are only ever read.
public enum VaultKeeper {
    public enum Skip: String, Error, Equatable, Sendable {
        case unreadable, empty, tooLarge, notText, outsideFolder, reservedName
    }

    public struct SealReport: Equatable, Sendable {
        public var sealed: [String] = []
        public var already: [String] = []
        public var skipped: [String: Skip] = [:]
        public init() {}
    }

    public struct CompareReport: Equatable, Sendable {
        public var same: [String] = []
        public var different: [String] = []
        public var noFile: [String] = []
        /// What each matching file held, as a hash in memory, so moving it later can tell if it changed.
        public var digests: [String: Data] = [:]
        public init() {}
    }

    private static let maxBytes = 1024 * 1024

    /// Reads each file and seals it under its path. This needs no fingerprint, and one bad file
    /// does not stop the others. A key that is already there stays as it is.
    public static func seal(paths: [String], folder: URL, store: VaultStore, now: Date = Date()) throws -> SealReport {
        try store.update { vault in
            var report = SealReport()
            for path in paths {
                if vault.entries[path] != nil {
                    report.already.append(path)
                    continue
                }
                if VaultFile.isReserved(path) {
                    report.skipped[path] = .reservedName
                    continue
                }
                switch read(path, in: folder) {
                case .failure(let skip):
                    report.skipped[path] = skip
                case .success(let data):
                    do {
                        try vault.add(name: path, value: data, now: now, source: folder.path)
                        report.sealed.append(path)
                    } catch {
                        report.skipped[path] = .outsideFolder
                    }
                }
            }
            return report
        }
    }

    /// Seals the file's current text over its old copy, which stays sealed under `replaced`.
    public static func sealAgain(paths: [String], folder: URL, store: VaultStore, now: Date = Date()) throws -> SealReport {
        try store.update { vault in
            var report = SealReport()
            for path in paths {
                switch read(path, in: folder) {
                case .failure(let skip): report.skipped[path] = skip
                case .success(let data):
                    try vault.replace(name: path, value: data, now: now)
                    report.sealed.append(path)
                }
            }
            return report
        }
    }

    /// Opens these keys for one use, and notes the use. Values stay in the returned memory only.
    /// `event` is `checked` when they are opened only to ask their providers whether they work.
    public static func open(
        names: [String], recipient: Age.Identity, store: VaultStore, by command: String, event: String = "used"
    ) throws -> [String: String] {
        let vault = try store.load()
        var opened: [String: String] = [:]
        for name in names {
            let value = try vault.open(name: name, with: recipient)
            guard let text = String(data: value, encoding: .utf8) else {
                throw VaultError("\(name) is not text")
            }
            opened[name] = text
            if !VaultFile.isTemporary(name) {
                store.recordUse(of: name, by: command, event: event)
            }
        }
        return opened
    }

    /// Opens every sealed copy and compares it with its file. The report holds names alone.
    public static func compare(
        names: [String], folder: URL, recipient: Age.Identity, store: VaultStore
    ) throws -> CompareReport {
        let vault = try store.load()
        var report = CompareReport()
        for name in names {
            let value = try vault.open(name: name, with: recipient)
            switch read(name, in: folder) {
            case .success(let data) where data == value:
                report.same.append(name)
                report.digests[name] = Data(SHA256.hash(data: data))
            case .success: report.different.append(name)
            case .failure: report.noFile.append(name)
            }
            store.recordUse(of: name, by: "compare", event: "checked")
        }
        return report
    }

    /// True if this copy came from a different folder, where the same path can be another key.
    public static func isFromAnotherFolder(_ entry: VaultFile.Entry, folder: URL) -> Bool {
        guard let source = entry.source else { return false }
        return source != folder.path
    }

    /// The paths in a comparison whose files still hold what was compared. A file that changed since
    /// then is not what the vault holds, and moving it away could lose it.
    public static func stillMatching(_ report: CompareReport, folder: URL) -> [String] {
        report.same.filter { name in
            guard case .success(let data) = read(name, in: folder), let digest = report.digests[name] else {
                return false
            }
            return Data(SHA256.hash(data: data)) == digest
        }
    }

    /// True if the file changed after its copy was sealed, so the copy may be an old key.
    public static func isOutdated(_ entry: VaultFile.Entry, path: String, folder: URL) -> Bool {
        let attributes = try? FileManager.default.attributesOfItem(
            atPath: folder.appendingPathComponent(path).path)
        guard let modified = attributes?[.modificationDate] as? Date else { return false }
        // The vault stores whole seconds, so a file written just before sealing is not newer.
        return modified.timeIntervalSince1970.rounded(.down) > entry.added.timeIntervalSince1970
    }

    private static func read(_ path: String, in folder: URL) -> Result<Data, Skip> {
        let base = folder.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        let url = folder.appendingPathComponent(path).resolvingSymlinksInPath().standardizedFileURL
        guard url.path.hasPrefix(base) else { return .failure(.outsideFolder) }
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
            let size = attributes[.size] as? NSNumber
        else { return .failure(.unreadable) }
        guard size.intValue <= maxBytes else { return .failure(.tooLarge) }
        guard let data = try? Data(contentsOf: url) else { return .failure(.unreadable) }
        guard !data.isEmpty else { return .failure(.empty) }
        // A certificate or a keystore is sealed as it is, byte for byte: kept and compared like any key. Only a
        // check with a provider, or handing it to a program as a variable, needs text, and those say so.
        return .success(data)
    }
}

/// Originals taken out of the keys folder after their sealed copies were compared. Moving is the
/// only thing done to them: nothing here deletes a file.
public struct MovedOriginals {
    public let ledger: URL
    public let destination: URL

    public init(ledger: URL, destination: URL) {
        self.ledger = ledger
        self.destination = destination
    }

    /// The inventory's own form, so the catalog keeps listing these keys. It holds no value.
    struct Ledger: Codable {
        var schema = 1
        var items: [Item] = []
    }

    struct Item: Codable {
        var path: String
        var modified: Double
        var mode: String?
        var format: String
        var fields: [String]
        var kinds: [String]
        var moved_to: String?
    }

    func read() -> Ledger {
        guard let data = try? Data(contentsOf: ledger) else { return Ledger() }
        return (try? JSONDecoder().decode(Ledger.self, from: data)) ?? Ledger()
    }

    func write(_ value: Ledger) throws { try PrivateFile.write(try JSONEncoder().encode(value), to: ledger) }

    public var paths: Set<String> { Set(read().items.map(\.path)) }

    /// Moves each file, keeping its place inside the destination. Its line goes in the ledger
    /// first, so a crash cannot lose track of a file. A file with no description stays where it is.
    public func move(_ paths: [String], from folder: URL, inventory: URL) throws -> [String] {
        struct Inventory: Decodable { let items: [Item] }
        let known = (try? JSONDecoder().decode(Inventory.self, from: Data(contentsOf: inventory)))?.items ?? []
        var ledgerValue = read()
        var moved: [String] = []
        let manager = FileManager.default
        for path in paths {
            guard var item = known.first(where: { $0.path == path }), !path.hasPrefix("/"), !path.contains("..") else { continue }
            let source = folder.appendingPathComponent(path)
            let target = destination.appendingPathComponent(path)
            guard manager.fileExists(atPath: source.path), !manager.fileExists(atPath: target.path) else { continue }
            let folderOfTarget = target.deletingLastPathComponent()
            try manager.createDirectory(at: folderOfTarget, withIntermediateDirectories: true)
            try makePrivate(folderOfTarget)
            item.moved_to = target.path
            ledgerValue.items.removeAll { $0.path == path }
            ledgerValue.items.append(item)
            try write(ledgerValue)
            try manager.moveItem(at: source, to: target)
            try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            moved.append(path)
        }
        return moved
    }

    /// Refuses a destination reached through a link, which could lead anywhere, and closes each
    /// folder on the way, since one that already existed may be open to other users.
    private func makePrivate(_ folder: URL) throws {
        let home = ledger.deletingLastPathComponent().standardizedFileURL
        var current = folder.standardizedFileURL
        while current.path.hasPrefix(home.path + "/") {
            let attributes = try FileManager.default.attributesOfItem(atPath: current.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else {
                throw VaultError("the folder for originals is not a plain folder")
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: current.path)
            current = current.deletingLastPathComponent()
        }
    }

    /// Keeps on the list the sealed keys whose file left the folder some other way, such as by hand.
    /// `before` is the inventory as it was before the scan that no longer found them. They go in the
    /// ledger with no place, since nothing here moved them, so there is nothing to put back.
    public func keepSealed(_ sealed: Set<String>, before: Data?, inventory: URL) throws -> [String] {
        struct Inventory: Decodable { let items: [Item] }
        guard let before, let old = try? JSONDecoder().decode(Inventory.self, from: before).items else { return [] }
        let now = (try? JSONDecoder().decode(Inventory.self, from: Data(contentsOf: inventory)).items) ?? []
        let found = Set(now.map(\.path))
        var ledgerValue = read()
        let listed = Set(ledgerValue.items.map(\.path))
        var kept: [String] = []
        for var item in old where sealed.contains(item.path) && !found.contains(item.path) && !listed.contains(item.path) {
            item.moved_to = nil
            ledgerValue.items.append(item)
            kept.append(item.path)
        }
        if !kept.isEmpty { try write(ledgerValue) }
        return kept
    }

    /// Puts files back. One whose old place is taken stays moved, and stays in the ledger.
    public func putBack(_ paths: [String], to folder: URL) throws -> [String] {
        var ledgerValue = read()
        var restored: [String] = []
        let manager = FileManager.default
        for path in paths {
            guard let item = ledgerValue.items.first(where: { $0.path == path }), let from = item.moved_to else { continue }
            let target = folder.appendingPathComponent(path)
            guard !manager.fileExists(atPath: target.path), manager.fileExists(atPath: from) else { continue }
            try manager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try manager.moveItem(atPath: from, toPath: target.path)
            ledgerValue.items.removeAll { $0.path == path }
            try write(ledgerValue)
            restored.append(path)
        }
        return restored
    }
}
