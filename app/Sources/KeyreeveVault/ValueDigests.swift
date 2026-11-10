import CryptoKit
import Foundation

/// A key that turns a value's SHA-256 into a digest only this Mac can make: HMAC-SHA256(K, SHA-256(value)). K comes
/// from the chip key the vault uses for copies that need no fingerprint, by key agreement with its own public key and
/// HKDF, so it is made with no prompt and never leaves memory. Without the chip, the digests file says nothing, even
/// of a short password.
public struct DigestKey: Sendable {
    let key: SymmetricKey
    public static let label = "keyreeve value digests v1"

    public init(key: SymmetricKey) { self.key = key }

    /// From the chip key that needs no fingerprint. Agreeing with its own public key gives a secret only the chip
    /// can make: a point whose discrete log anyone knows would let them make it too from the public key.
    public static func derive(from recipient: some VaultRecipient, tag: String) throws -> DigestKey {
        let shared = try recipient.sharedSecret(with: recipient.publicKey)
        return DigestKey(key: shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(label.utf8), sharedInfo: Data(tag.utf8), outputByteCount: 32))
    }

    /// The key for this vault, if it has a chip key that needs no fingerprint and this Mac holds it. Never a prompt.
    public static func load(vault: VaultFile, store: VaultStore) -> DigestKey? {
        guard let tag = vault.unattended else { return nil }
        if let cached = cache.get(tag) { return cached }
        guard let blob = try? store.loadUnattendedBlob(for: vault), let recipient = try? EnclaveRecipient.loadUnattended(blob: blob),
            let made = try? derive(from: recipient, tag: tag)
        else { return nil }
        cache.set(tag, made)
        return made
    }

    private final class Cache: @unchecked Sendable {
        private let lock = NSLock()
        private var keys: [String: DigestKey] = [:]
        func get(_ tag: String) -> DigestKey? { lock.withLock { keys[tag] } }
        func set(_ tag: String, _ key: DigestKey) { lock.withLock { keys[tag] = key } }
    }
    private static let cache = Cache()

    public func digest(ofValue value: String) -> String { digest(ofSHA256: Data(SHA256.hash(data: Data(value.utf8)))) }

    /// From the hex SHA-256 a place gave, which never goes anywhere else.
    public func digest(ofHex hex: String) -> String? {
        let hex = hex.lowercased()
        guard hex.count == 64 else { return nil }
        var bytes = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return digest(ofSHA256: bytes)
    }

    func digest(ofSHA256 bytes: Data) -> String {
        Data(HMAC<SHA256>.authenticationCode(for: bytes, using: key)).map { String(format: "%02x", $0) }.joined()
    }
}

/// The keyed digest of each value in the vault, by sealing, so a check of a place compares with no fingerprint, and
/// tells the value now from an earlier one, such as the one before a rotation. It is written whenever a value is
/// sealed, and filled in for older ones the next time each is opened for any reason.
public struct ValueDigests: Codable, Equatable, Sendable {
    public static let fileName = "value-digests.json"
    public static let schemaVersion = 2
    public var schema = ValueDigests.schemaVersion
    /// Vault name, then the sealing's revision, then the field (empty for the whole value), then the keyed digest.
    public var entries: [String: [String: [String: String]]] = [:]
    /// When the person last had Keyreeve learn what the whole vault holds, with one fingerprint.
    public var learned: Date?

    public init() {}

    /// What a file holds, or nothing. A file from before keyed digests is dropped, never trusted.
    public static func load(from url: URL) -> ValueDigests {
        guard let read = try? JSONDecoder().decode(ValueDigests.self, from: Data(contentsOf: url)), read.schema == schemaVersion
        else { return ValueDigests() }
        return read
    }

    public static func update(at url: URL, _ change: (inout ValueDigests) -> Void) throws {
        try PrivateFile.folder(url.deletingLastPathComponent())
        let lockFile = open(url.path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lockFile >= 0 else { throw VaultError("the digests could not be locked") }
        defer { close(lockFile) }
        guard flock(lockFile, LOCK_EX) == 0 else { throw VaultError("the digests could not be locked") }
        defer { flock(lockFile, LOCK_UN) }
        let before = load(from: url)
        var after = before
        change(&after)
        guard after != before else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try PrivateFile.write(try encoder.encode(after), to: url)
    }

    /// The keyed digests of a sealed value: the whole of it and each field it holds.
    public static func digests(of value: Data, key: DigestKey) -> [String: String] {
        guard value.count <= 1 << 20, let text = String(data: value, encoding: .utf8) else { return [:] }
        var out: [String: String] = [:]
        if let whole = try? EnvReferences.value(in: value, field: nil) { out[""] = key.digest(ofValue: whole) }
        for case .value(let name, _) in EnvReferences.parse(text) {
            if let field = try? EnvReferences.value(in: value, field: name) { out[name] = key.digest(ofValue: field) }
        }
        return out
    }

    public mutating func learn(name: String, revision: String, value: Data, key: DigestKey) {
        let made = Self.digests(of: value, key: key)
        guard !made.isEmpty else { return }
        entries[name, default: [:]][revision] = made
    }

    public func knows(name: String, revision: String) -> Bool { entries[name]?[revision] != nil }

    /// How a hash a place gave compares with the vault's value now, and its earlier ones. With no key, or a value
    /// never seen, it says so, rather than guess.
    public func compare(_ found: String, name: String, field: String?, revision: String?, key: DigestKey?) -> PlaceBook.Result {
        guard let key, let revision, let digest = key.digest(ofHex: found),
            let current = entries[name]?[revision]?[field ?? ""]
        else { return .notCompared }
        if current == digest { return .same }
        let earlier = (entries[name] ?? [:]).contains { $0.key != revision && $0.value[field ?? ""] == digest }
        return earlier ? .old : .different
    }
}

/// Learns each value's keyed digest as the vault seals or opens it, which is when keyreeve holds it anyway. One per
/// process: the app and keyreeve-vault each set theirs for their home.
public enum VaultEvents {
    private final class Box: @unchecked Sendable {
        let lock = NSLock()
        var recorder: (@Sendable (VaultFile, String, String, Data) -> Void)?
    }
    private static let box = Box()

    public static func observe(_ recorder: (@Sendable (_ vault: VaultFile, _ name: String, _ revision: String, _ value: Data) -> Void)?) {
        box.lock.withLock { box.recorder = recorder }
    }

    static func saw(_ vault: VaultFile, name: String, revision: String, value: Data) {
        guard !VaultFile.isTemporary(name), let recorder = box.lock.withLock({ box.recorder }) else { return }
        recorder(vault, name, revision, value)
    }

    /// Writes each digest it can make, and nothing when the chip key that needs no fingerprint is not there.
    public static func recorder(
        store: VaultStore, file: URL, key keyFor: (@Sendable (VaultFile) -> DigestKey?)? = nil
    ) -> @Sendable (VaultFile, String, String, Data) -> Void {
        let known = Known()
        return { vault, name, revision, value in
            if known.contains(name, revision) { return }
            guard let key = keyFor?(vault) ?? DigestKey.load(vault: vault, store: store) else { return }
            if (try? ValueDigests.update(at: file) { digests in
                if !digests.knows(name: name, revision: revision) { digests.learn(name: name, revision: revision, value: value, key: key) }
            }) != nil {
                known.insert(name, revision)
            }
        }
    }

    private final class Known: @unchecked Sendable {
        let lock = NSLock()
        var seen: Set<String> = []
        func contains(_ name: String, _ revision: String) -> Bool { lock.withLock { seen.contains(name + "\u{0}" + revision) } }
        func insert(_ name: String, _ revision: String) { _ = lock.withLock { seen.insert(name + "\u{0}" + revision) } }
    }
}
