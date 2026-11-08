import CryptoKit
import Foundation

public struct VaultError: Error, CustomStringConvertible, Equatable {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// A chip's key, or a stand-in for one in tests. It agrees on a secret without showing its key.
public protocol VaultRecipient: Age.Identity {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension VaultRecipient {
    public func unwrap(_ stanza: Age.Stanza) throws -> Data? {
        try Age.unwrapTag(stanza, publicKey: publicKey) { try sharedSecret(with: $0) }
    }

    public var ageRecipient: Age.TagRecipient { Age.TagRecipient(publicKey: publicKey) }
}

public struct SoftwareRecipient: VaultRecipient {
    let key: P256.KeyAgreement.PrivateKey
    public init(key: P256.KeyAgreement.PrivateKey = .init()) { self.key = key }
    public var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }
    public func sharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: other)
    }
}

/// The contents of the vault file. Each value is an age file, sealed for the chip and for the
/// recovery key, so either one opens it, with keyreeve or with any age tool.
public struct VaultFile: Codable, Equatable {
    public var schema = 2
    /// `age1tag1...`, the chip's public key.
    public var enclave: String
    /// `age1...`, the recovery key's public key.
    public var recovery: String
    public var entries: [String: Entry] = [:]
    /// Copies that a newer one replaced, oldest first. Nothing in the vault is ever lost by replacing.
    public var replaced: [String: [Entry]]?
    /// `age1tag1...` of a second key in this Mac's chip that opens with no fingerprint. Only the keys the person
    /// marked "always, no fingerprint" have a copy sealed to it, and only the proxy ever uses it.
    public var unattended: String?

    public struct Entry: Codable, Equatable {
        public var added: Date
        /// The folder this file was sealed from, because a path means nothing without its folder.
        public var source: String?
        /// A whole age file. Its text starts with a line naming the key, then the value.
        public var sealed: Data
        /// The same value sealed only to the key that needs no fingerprint, for a key the person marked so.
        public var unattendedSealed: Data?

        /// Which sealing this is. Each seal encrypts afresh, so a replaced value always has a new one.
        public var revision: String { SHA256.hash(data: sealed).prefix(12).map { String(format: "%02x", $0) }.joined() }
    }

    public init(enclave: P256.KeyAgreement.PublicKey, recovery: Age.X25519Recipient) {
        self.enclave = Age.TagRecipient(publicKey: enclave).string
        self.recovery = recovery.string
    }

    private static func nameLine(_ name: String) -> Data { Data("keyreeve-name: \(name)\n".utf8) }

    private func seal(name: String, value: Data, now: Date, source: String?) throws -> Entry {
        // Needs no fingerprint, because sealing uses only public keys. The name goes inside, so
        // a program that can edit this file cannot swap two values under each other's names.
        let file = try Age.encrypt(
            Self.nameLine(name) + value,
            to: [try Age.TagRecipient(string: enclave), try Age.X25519Recipient(string: recovery)])
        return Entry(added: now, source: source, sealed: file)
    }

    public mutating func add(name: String, value: Data, now: Date = Date(), source: String? = nil) throws {
        try Self.check(name: name)
        if entries[name] != nil { throw VaultError("\(name) already exists") }
        entries[name] = try seal(name: name, value: value, now: now, source: source)
    }

    /// Seals a new value under this name, and keeps the old one where it can still be opened.
    public mutating func replace(name: String, value: Data, now: Date = Date()) throws {
        try Self.check(name: name)
        let old = entries[name]
        entries[name] = try seal(name: name, value: value, now: now, source: old?.source)
        // A key marked to need no fingerprint stays so through a rotation: sealing needs only the public key.
        if old?.unattendedSealed != nil, unattended != nil { try sealUnattended(name: name, value: value) }
        if let old { replaced = (replaced ?? [:]).merging([name: [old]]) { $0 + $1 } }
    }

    /// Opens a copy that was replaced. Index 0 is the oldest.
    public func openReplaced(name: String, index: Int, with identity: Age.Identity) throws -> Data {
        guard let list = replaced?[name], list.indices.contains(index) else {
            throw VaultError("\(name) has no such old copy")
        }
        return try open(entry: list[index], name: name, with: identity)
    }

    /// Seals a copy of the value to the key that needs no fingerprint. The value comes from the person, who
    /// opened it with theirs to mark the key.
    public mutating func sealUnattended(name: String, value: Data) throws {
        guard let unattended else { throw VaultError("this vault has no key for use without a fingerprint yet") }
        guard entries[name] != nil else { throw VaultError("\(name) is not in the vault") }
        entries[name]?.unattendedSealed = try Age.encrypt(Self.nameLine(name) + value, to: [try Age.TagRecipient(string: unattended)])
    }

    /// Takes the copy away, so the key needs a fingerprint again.
    public mutating func dropUnattended(name: String) { entries[name]?.unattendedSealed = nil }

    /// Opens the copy that needs no fingerprint, for a key marked so. Never the copy that needs one.
    public func openUnattended(name: String, with identity: Age.Identity) throws -> Data {
        guard let file = entries[name]?.unattendedSealed else { throw VaultError("\(name) is not marked for use without a fingerprint") }
        let plain = try Age.decrypt(file, with: identity)
        let line = Self.nameLine(name)
        guard plain.starts(with: line) else { throw VaultError("\(name) could not be opened: the file was changed or damaged") }
        return plain.dropFirst(line.count)
    }

    public func open(name: String, with identity: Age.Identity) throws -> Data {
        guard let entry = entries[name] else { throw VaultError("\(name) is not in the vault") }
        return try open(entry: entry, name: name, with: identity)
    }

    private func open(entry: Entry, name: String, with identity: Age.Identity) throws -> Data {
        let plain = try Age.decrypt(entry.sealed, with: identity)
        let line = Self.nameLine(name)
        guard plain.starts(with: line) else {
            throw VaultError("\(name) could not be opened: the file was changed or damaged")
        }
        return plain.dropFirst(line.count)
    }

    /// Proves the recovery key opens this vault, or a backup of it: every key and every replaced copy is opened with
    /// it, and only how many is said. One that would not open is named, so a backup that cannot bring the keys back
    /// is known before it is needed.
    public func openAll(with recovery: Age.X25519Identity) throws -> Int {
        guard recovery.recipient.string == self.recovery else {
            throw VaultError("this is not the recovery key of this vault")
        }
        var opened = 0
        for (name, entry) in entries {
            do { _ = try open(entry: entry, name: name, with: recovery) } catch { throw VaultError("\(name) does not open with the recovery key") }
            opened += 1
        }
        for (name, list) in replaced ?? [:] {
            for entry in list {
                do { _ = try open(entry: entry, name: name, with: recovery) } catch {
                    throw VaultError("an old copy of \(name) does not open with the recovery key")
                }
            }
        }
        return opened
    }

    /// Moves the vault to a new chip, using the recovery key. Each value is sealed again.
    public mutating func moveToNewEnclave(
        _ newEnclave: P256.KeyAgreement.PublicKey, recovery identity: Age.X25519Identity
    ) throws {
        guard identity.recipient.string == recovery else {
            throw VaultError("this is not the recovery key of this vault")
        }
        var moved = self
        moved.enclave = Age.TagRecipient(publicKey: newEnclave).string
        // The key that needs no fingerprint belongs to the old chip; on a new one each key is marked again.
        moved.unattended = nil
        for name in moved.entries.keys { moved.entries[name]?.unattendedSealed = nil }
        for (name, entry) in entries {
            let value = try open(entry: entry, name: name, with: identity)
            moved.entries[name] = try moved.seal(name: name, value: value, now: entry.added, source: entry.source)
        }
        for (name, list) in replaced ?? [:] {
            let sealedAgain = try list.map { entry in
                let value = try open(entry: entry, name: name, with: identity)
                return try moved.seal(name: name, value: value, now: entry.added, source: entry.source)
            }
            moved.replaced?[name] = sealedAgain
        }
        self = moved
    }

    /// Names a rotation keeps for itself, so a key can never be overwritten by one.
    public static func isTemporary(_ name: String) -> Bool {
        name.hasSuffix("#pending") || name.hasSuffix("#previous") || name.hasSuffix("#incoming")
    }

    /// Where keys pasted in the app live. A file in a keys folder at this path is never sealed under
    /// it, so a pasted key and a file can never share a name.
    public static let pastedFolder = "added/"

    /// A name the vault keeps for itself: a rotation's copies, or a pasted key.
    public static func isReserved(_ name: String) -> Bool { isTemporary(name) || name.hasPrefix(pastedFolder) }

    /// A name can be a file's path, which can hold spaces and accents. What matters is that it
    /// stays on one line when a person reads it, and inside the sealed text.
    public static func check(name: String) throws {
        guard !name.isEmpty, name.count <= 200,
            !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else {
            throw VaultError("a name is one line of at most 200 characters")
        }
    }
}
