import CryptoKit
import Foundation

/// A new vault that exists only in memory until the person says they kept the recovery key.
public struct VaultDraft {
    public let recoveryKey: String
    let file: VaultFile
    let blob: Data

    public init(enclave: VaultRecipient, blob: Data, recovery: P256.KeyAgreement.PrivateKey) {
        recoveryKey = RecoveryKey.encode(recovery)
        file = VaultFile(enclave: enclave.publicKey, recovery: recovery.publicKey)
        self.blob = blob
    }

    /// The last group of the recovery key, which the person types back as proof they have it.
    public var lastGroup: String { recoveryKey.split(separator: "-").last.map(String.init) ?? "" }

    public func accepts(_ typed: String) -> Bool {
        typed.trimmingCharacters(in: .whitespaces).uppercased() == lastGroup
    }

    public func save(to store: VaultStore) throws {
        guard !store.exists else { throw VaultError("there is already a vault") }
        try store.saveBlob(blob)
        try store.save(file)
    }
}

/// Moves key files into the vault, and proves the copies match. Originals are only ever read.
public enum VaultKeeper {
    public enum Skip: String, Error, Equatable, Sendable {
        case unreadable, empty, tooLarge, notText, outsideFolder
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
        public init() {}
    }

    private static let maxBytes = 1024 * 1024

    /// Reads each file and seals it under its path. This needs no fingerprint, and one bad file
    /// does not stop the others. A key that is already there stays as it is.
    public static func seal(paths: [String], folder: URL, store: VaultStore, now: Date = Date()) throws -> SealReport {
        var vault = try store.load()
        var report = SealReport()
        for path in paths {
            if vault.entries[path] != nil {
                report.already.append(path)
                continue
            }
            switch read(path, in: folder) {
            case .failure(let skip):
                report.skipped[path] = skip
            case .success(let data):
                do {
                    try vault.add(name: path, value: data, now: now)
                    report.sealed.append(path)
                } catch {
                    report.skipped[path] = .outsideFolder
                }
            }
        }
        if !report.sealed.isEmpty { try store.save(vault) }
        return report
    }

    /// Seals the file's current text over its old copy, which stays sealed under `replaced`.
    public static func sealAgain(paths: [String], folder: URL, store: VaultStore, now: Date = Date()) throws -> SealReport {
        var vault = try store.load()
        var report = SealReport()
        for path in paths {
            switch read(path, in: folder) {
            case .failure(let skip): report.skipped[path] = skip
            case .success(let data):
                try vault.replace(name: path, value: data, now: now)
                report.sealed.append(path)
            }
        }
        if !report.sealed.isEmpty { try store.save(vault) }
        return report
    }

    /// Opens these keys for one use, and notes the use. Values stay in the returned memory only.
    public static func open(
        names: [String], recipient: VaultRecipient, store: VaultStore, by command: String
    ) throws -> [String: String] {
        let vault = try store.load()
        var opened: [String: String] = [:]
        for name in names {
            let value = try vault.open(name: name, with: recipient)
            guard let text = String(data: value, encoding: .utf8) else {
                throw VaultError("\(name) is not text")
            }
            opened[name] = text
            if !name.hasSuffix("#pending"), !name.hasSuffix("#previous") {
                store.recordUse(of: name, by: command)
            }
        }
        return opened
    }

    /// Opens every sealed copy and compares it with its file. The report holds names alone.
    public static func compare(
        names: [String], folder: URL, recipient: VaultRecipient, store: VaultStore
    ) throws -> CompareReport {
        let vault = try store.load()
        var report = CompareReport()
        for name in names {
            let value = try vault.open(name: name, with: recipient)
            switch read(name, in: folder) {
            case .success(let data) where data == value: report.same.append(name)
            case .success: report.different.append(name)
            case .failure: report.noFile.append(name)
            }
            store.recordUse(of: name, by: "compare")
        }
        return report
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
        guard String(data: data, encoding: .utf8) != nil else { return .failure(.notText) }
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

    func write(_ value: Ledger) throws {
        let previous = umask(0o077)
        defer { umask(previous) }
        try JSONEncoder().encode(value).write(to: ledger, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ledger.path)
    }

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
            let previous = umask(0o077)
            defer { umask(previous) }
            try manager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            item.moved_to = target.path
            ledgerValue.items.removeAll { $0.path == path }
            ledgerValue.items.append(item)
            try write(ledgerValue)
            try manager.moveItem(at: source, to: target)
            moved.append(path)
        }
        return moved
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
