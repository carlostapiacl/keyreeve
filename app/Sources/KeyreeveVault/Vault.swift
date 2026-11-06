import CryptoKit
import Foundation

public struct VaultError: Error, CustomStringConvertible, Equatable {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Someone who can open what was sealed for their public key.
public protocol VaultRecipient {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

public struct SoftwareRecipient: VaultRecipient {
    let key: P256.KeyAgreement.PrivateKey
    public init(key: P256.KeyAgreement.PrivateKey = .init()) { self.key = key }
    public var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }
    public func sharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: other)
    }
}

/// The contents of the vault file. Each value has its own random key, sealed separately for
/// the Secure Enclave and for the recovery key, so either one can open it.
public struct VaultFile: Codable, Equatable {
    public var schema = 1
    public var enclavePublicKey: Data
    public var recoveryPublicKey: Data
    public var entries: [String: Entry] = [:]

    public struct Entry: Codable, Equatable {
        public var added: Date
        public var sealedValue: Data
        public var enclaveWrap: Wrap
        public var recoveryWrap: Wrap
    }

    public struct Wrap: Codable, Equatable {
        public var ephemeralPublicKey: Data
        public var sealedKey: Data
    }

    public init(enclave: P256.KeyAgreement.PublicKey, recovery: P256.KeyAgreement.PublicKey) {
        enclavePublicKey = enclave.rawRepresentation
        recoveryPublicKey = recovery.rawRepresentation
    }

    /// Needs no fingerprint, because sealing uses only public keys.
    public mutating func add(name: String, value: Data, now: Date = Date()) throws {
        try Self.check(name: name)
        if entries[name] != nil { throw VaultError("\(name) already exists") }
        let valueKey = SymmetricKey(size: .bits256)
        let box = try AES.GCM.seal(value, using: valueKey, authenticating: Data(name.utf8))
        guard let sealedValue = box.combined else { throw VaultError("could not seal the value") }
        let keyBytes = valueKey.withUnsafeBytes { Data($0) }
        entries[name] = Entry(
            added: now,
            sealedValue: sealedValue,
            enclaveWrap: try Self.wrap(keyBytes, for: enclavePublicKey, name: name),
            recoveryWrap: try Self.wrap(keyBytes, for: recoveryPublicKey, name: name)
        )
    }

    public func open(name: String, with recipient: VaultRecipient) throws -> Data {
        guard let entry = entries[name] else { throw VaultError("\(name) is not in the vault") }
        let valueKey = try unwrap(entry: entry, name: name, recipient: recipient)
        do {
            let box = try AES.GCM.SealedBox(combined: entry.sealedValue)
            return try AES.GCM.open(box, using: valueKey, authenticating: Data(name.utf8))
        } catch {
            throw VaultError("\(name) could not be opened: the file was changed or damaged")
        }
    }

    /// Moves the vault to a new Secure Enclave key, using the recovery key.
    public mutating func moveToNewEnclave(
        _ enclave: P256.KeyAgreement.PublicKey,
        recovery: VaultRecipient
    ) throws {
        guard recovery.publicKey.rawRepresentation == recoveryPublicKey else {
            throw VaultError("this is not the recovery key of this vault")
        }
        let target = enclave.rawRepresentation
        var moved = entries
        for (name, entry) in entries {
            let valueKey = try unwrap(entry: entry, name: name, recipient: recovery)
            let keyBytes = valueKey.withUnsafeBytes { Data($0) }
            moved[name]?.enclaveWrap = try Self.wrap(keyBytes, for: target, name: name)
        }
        entries = moved
        enclavePublicKey = target
    }

    private func unwrap(entry: Entry, name: String, recipient: VaultRecipient) throws -> SymmetricKey {
        let wrap: Wrap
        switch recipient.publicKey.rawRepresentation {
        case enclavePublicKey: wrap = entry.enclaveWrap
        case recoveryPublicKey: wrap = entry.recoveryWrap
        default: throw VaultError("this key cannot open this vault")
        }
        let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: wrap.ephemeralPublicKey)
        // A failed fingerprint surfaces here and is not a damaged file, so it passes through.
        let secret = try recipient.sharedSecret(with: ephemeral)
        let wrapKey = Self.derive(
            secret, ephemeral: wrap.ephemeralPublicKey,
            recipient: recipient.publicKey.rawRepresentation, name: name)
        do {
            let box = try AES.GCM.SealedBox(combined: wrap.sealedKey)
            return SymmetricKey(data: try AES.GCM.open(box, using: wrapKey, authenticating: Data(name.utf8)))
        } catch {
            throw VaultError("\(name) could not be opened: the file was changed or damaged")
        }
    }

    private static func wrap(_ keyBytes: Data, for recipient: Data, name: String) throws -> Wrap {
        let target = try P256.KeyAgreement.PublicKey(rawRepresentation: recipient)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: target)
        let wrapKey = derive(
            secret, ephemeral: ephemeral.publicKey.rawRepresentation, recipient: recipient, name: name)
        let box = try AES.GCM.seal(keyBytes, using: wrapKey, authenticating: Data(name.utf8))
        guard let sealedKey = box.combined else { throw VaultError("could not seal the key") }
        return Wrap(ephemeralPublicKey: ephemeral.publicKey.rawRepresentation, sealedKey: sealedKey)
    }

    private static func derive(
        _ secret: SharedSecret, ephemeral: Data, recipient: Data, name: String
    ) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("keyreeve-vault-v1".utf8),
            sharedInfo: ephemeral + recipient + Data(name.utf8),
            outputByteCount: 32)
    }

    /// A name can be a file's path, which can hold spaces and accents. It is bound to its value,
    /// so what matters is that it stays on one line when a person reads it.
    public static func check(name: String) throws {
        guard !name.isEmpty, name.count <= 200,
            !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else {
            throw VaultError("a name is one line of at most 200 characters")
        }
    }
}

/// The recovery key, written so a person can copy it. It ends in a checksum, to catch a typo.
public enum RecoveryKey {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    public static func encode(_ key: P256.KeyAgreement.PrivateKey) -> String {
        let raw = key.rawRepresentation
        let bytes = raw + Data(SHA256.hash(data: raw).prefix(2))
        var bits = 0
        var count = 0
        var out = ""
        for byte in bytes {
            bits = (bits << 8) | Int(byte)
            count += 8
            while count >= 5 {
                count -= 5
                out.append(alphabet[(bits >> count) & 31])
            }
            bits &= (1 << count) - 1
        }
        if count > 0 { out.append(alphabet[(bits << (5 - count)) & 31]) }
        return stride(from: 0, to: out.count, by: 5).map { start in
            let from = out.index(out.startIndex, offsetBy: start)
            let to = out.index(from, offsetBy: min(5, out.count - start))
            return String(out[from..<to])
        }.joined(separator: "-")
    }

    public static func decode(_ text: String) throws -> P256.KeyAgreement.PrivateKey {
        var bits = 0
        var count = 0
        var bytes = Data()
        for character in text.uppercased() where character != "-" && !character.isWhitespace {
            guard let value = alphabet.firstIndex(of: character) else {
                throw VaultError("the recovery key has a character it should not have")
            }
            bits = (bits << 5) | value
            count += 5
            if count >= 8 {
                count -= 8
                bytes.append(UInt8((bits >> count) & 255))
                bits &= (1 << count) - 1
            }
        }
        guard bytes.count == 34,
            Data(SHA256.hash(data: bytes.prefix(32)).prefix(2)) == bytes.suffix(2)
        else { throw VaultError("the recovery key is not right: check for a typo") }
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes.prefix(32))
    }
}
