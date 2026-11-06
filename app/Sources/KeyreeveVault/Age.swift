import CryptoKit
import Foundation

/// The age file format (age-encryption.org/v1), so a vault's files open with any age tool and nobody
/// depends on keyreeve to get their keys back. Only the two recipient types the vault uses are here:
/// X25519 for the recovery key, and `p256tag`, which age 1.3 defines for keys held in hardware.
public enum Age {
    static let header = "age-encryption.org/v1"
    static let chunkSize = 64 * 1024
    static let maxFileBytes = 16 * 1024 * 1024
    /// Well under the limit for opening, so everything sealed here can always be opened, with room
    /// for the header and each chunk's tag.
    public static let maxPlainBytes = 8 * 1024 * 1024

    public struct Stanza: Equatable {
        public let type: String
        public let arguments: [String]
        public let body: Data
    }

    /// Someone who can get the file key out of a stanza meant for them.
    public protocol Identity {
        func unwrap(_ stanza: Stanza) throws -> Data?
    }

    public protocol Recipient {
        func wrap(_ fileKey: Data) throws -> Stanza
    }

    // MARK: Files

    public static func encrypt(_ plain: Data, to recipients: [Recipient]) throws -> Data {
        guard plain.count <= maxPlainBytes else { throw VaultError("that is too large to be a key") }
        let fileKey = randomBytes(16)
        let stanzas = try recipients.map { try $0.wrap(fileKey) }
        var head = Data("\(header)\n".utf8)
        for stanza in stanzas { head += encode(stanza) }
        head += Data("---".utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: head, using: macKey(fileKey))
        head += Data(" \(base64(Data(mac)))\n".utf8)
        let nonce = randomBytes(16)
        return head + nonce + (try seal(plain, key: payloadKey(fileKey, nonce: nonce)))
    }

    public static func decrypt(_ file: Data, with identity: Identity) throws -> Data {
        guard file.count <= maxFileBytes else { throw VaultError("the file is too large") }
        let parsed = try parse(file)
        var found: Data?
        for stanza in parsed.stanzas {
            if let key = try identity.unwrap(stanza) {
                found = key
                break
            }
        }
        guard let fileKey = found else { throw VaultError("this key cannot open this file") }
        guard fileKey.count == 16,
            HMAC<SHA256>.isValidAuthenticationCode(parsed.mac, authenticating: parsed.signed, using: macKey(fileKey))
        else { throw VaultError("the file was changed or damaged") }
        guard parsed.payload.count >= 16 else { throw VaultError("the file was changed or damaged") }
        let nonce = parsed.payload.prefix(16)
        return try open(parsed.payload.dropFirst(16), key: payloadKey(fileKey, nonce: Data(nonce)))
    }

    private static func macKey(_ fileKey: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey), salt: Data(), info: Data("header".utf8), outputByteCount: 32)
    }

    private static func payloadKey(_ fileKey: Data, nonce: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey), salt: nonce, info: Data("payload".utf8), outputByteCount: 32)
    }

    private static func streamNonce(_ counter: UInt64, last: Bool) throws -> ChaChaPoly.Nonce {
        var bytes = Data(repeating: 0, count: 3)
        withUnsafeBytes(of: counter.bigEndian) { bytes.append(contentsOf: $0) }
        bytes.append(last ? 1 : 0)
        return try ChaChaPoly.Nonce(data: bytes)
    }

    private static func seal(_ plain: Data, key: SymmetricKey) throws -> Data {
        var out = Data()
        var counter: UInt64 = 0
        var offset = plain.startIndex
        repeat {
            let end = plain.index(offset, offsetBy: chunkSize, limitedBy: plain.endIndex) ?? plain.endIndex
            let box = try ChaChaPoly.seal(
                plain[offset..<end], using: key, nonce: try streamNonce(counter, last: end == plain.endIndex))
            out += box.ciphertext + box.tag
            counter += 1
            offset = end
        } while offset < plain.endIndex
        return out
    }

    private static func open(_ sealed: Data, key: SymmetricKey) throws -> Data {
        let size = chunkSize + 16
        var out = Data()
        var counter: UInt64 = 0
        var offset = sealed.startIndex
        repeat {
            let end = sealed.index(offset, offsetBy: size, limitedBy: sealed.endIndex) ?? sealed.endIndex
            let chunk = sealed[offset..<end]
            let last = end == sealed.endIndex
            guard chunk.count >= 16, last || chunk.count == size else {
                throw VaultError("the file was changed or damaged")
            }
            // Only an empty file may have an empty chunk: anything else could hide a cut.
            guard chunk.count > 16 || (counter == 0 && last) else {
                throw VaultError("the file was changed or damaged")
            }
            do {
                let box = try ChaChaPoly.SealedBox(
                    nonce: try streamNonce(counter, last: last), ciphertext: chunk.dropLast(16), tag: chunk.suffix(16))
                out += try ChaChaPoly.open(box, using: key)
            } catch {
                throw VaultError("the file was changed or damaged")
            }
            counter += 1
            offset = end
        } while offset < sealed.endIndex
        return out
    }

    // MARK: Text of the header

    static func base64(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    /// Strict on purpose, as the format asks: one spelling for each value, with no padding.
    static func fromBase64(_ text: String) throws -> Data {
        guard !text.contains("="), !text.contains("\n"), !text.contains("\r"),
            let data = Data(base64Encoded: text + String(repeating: "=", count: (4 - text.count % 4) % 4)),
            base64(data) == text
        else { throw VaultError("the file was changed or damaged") }
        return data
    }

    private static func encode(_ stanza: Stanza) -> Data {
        var out = "-> " + ([stanza.type] + stanza.arguments).joined(separator: " ") + "\n"
        let body = base64(stanza.body)
        var rest = Substring(body)
        while rest.count >= 64 {
            out += rest.prefix(64) + "\n"
            rest = rest.dropFirst(64)
        }
        out += rest + "\n"
        return Data(out.utf8)
    }

    private struct Parsed {
        let stanzas: [Stanza]
        let signed: Data
        let mac: Data
        let payload: Data
    }

    private static func parse(_ file: Data) throws -> Parsed {
        let bad = VaultError("the file was changed or damaged")
        var offset = file.startIndex
        func line() throws -> String {
            guard let end = file[offset...].firstIndex(of: 10),
                let text = String(data: file[offset..<end], encoding: .utf8)
            else { throw bad }
            offset = file.index(after: end)
            return text
        }
        guard try line() == header else { throw VaultError("this is not an age file") }
        var stanzas: [Stanza] = []
        while true {
            let start = offset
            let text = try line()
            if text.hasPrefix("--- ") {
                let macStart = file.index(start, offsetBy: 3)
                return Parsed(
                    stanzas: stanzas, signed: Data(file[file.startIndex..<macStart]),
                    mac: try fromBase64(String(text.dropFirst(4))), payload: Data(file[offset...]))
            }
            guard text.hasPrefix("-> ") else { throw bad }
            let parts = text.dropFirst(3).split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            guard let type = parts.first, !type.isEmpty, !parts.contains("") else { throw bad }
            var body = Data()
            while true {
                let piece = try line()
                guard piece.count <= 64 else { throw bad }
                body += try fromBase64(piece)
                if piece.count < 64 { break }
            }
            stanzas.append(Stanza(type: type, arguments: Array(parts.dropFirst()), body: body))
        }
    }

    static func randomBytes(_ count: Int) -> Data {
        SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }

    // MARK: X25519, for the recovery key

    public struct X25519Recipient: Recipient, Equatable {
        public let publicKey: Data

        public init(string: String) throws {
            let decoded = try Bech32.decode(string)
            guard decoded.hrp == "age", decoded.data.count == 32 else {
                throw VaultError("this is not an age recipient")
            }
            publicKey = decoded.data
        }

        public init(publicKey: Data) { self.publicKey = publicKey }

        public var string: String { Bech32.encode(hrp: "age", publicKey) }

        public func wrap(_ fileKey: Data) throws -> Stanza {
            let ephemeral = Curve25519.KeyAgreement.PrivateKey()
            let target = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: target)
            let sender = ephemeral.publicKey.rawRepresentation
            let key = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: sender + publicKey,
                sharedInfo: Data("age-encryption.org/v1/X25519".utf8), outputByteCount: 32)
            return Stanza(type: "X25519", arguments: [base64(sender)], body: try sealKey(fileKey, with: key))
        }
    }

    public struct X25519Identity: Identity {
        let key: Curve25519.KeyAgreement.PrivateKey

        public init(key: Curve25519.KeyAgreement.PrivateKey = .init()) { self.key = key }

        /// `AGE-SECRET-KEY-1...`, as `age-keygen` writes it.
        public init(string: String) throws {
            let decoded = try Bech32.decode(string.trimmingCharacters(in: .whitespacesAndNewlines))
            guard decoded.hrp == "age-secret-key-", decoded.data.count == 32 else {
                throw VaultError("this is not an age secret key")
            }
            key = try .init(rawRepresentation: decoded.data)
        }

        public var string: String { Bech32.encode(hrp: "age-secret-key-", key.rawRepresentation).uppercased() }
        public var recipient: X25519Recipient { X25519Recipient(publicKey: key.publicKey.rawRepresentation) }

        public func unwrap(_ stanza: Stanza) throws -> Data? {
            guard stanza.type == "X25519", stanza.arguments.count == 1 else { return nil }
            let sender = try fromBase64(stanza.arguments[0])
            guard sender.count == 32 else { throw VaultError("the file was changed or damaged") }
            let shared = try key.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: sender))
            let wrap = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: sender + key.publicKey.rawRepresentation,
                sharedInfo: Data("age-encryption.org/v1/X25519".utf8), outputByteCount: 32)
            return try? openKey(stanza.body, with: wrap)
        }
    }

    static func sealKey(_ fileKey: Data, with key: SymmetricKey) throws -> Data {
        let box = try ChaChaPoly.seal(fileKey, using: key, nonce: try ChaChaPoly.Nonce(data: Data(count: 12)))
        return box.ciphertext + box.tag
    }

    static func openKey(_ body: Data, with key: SymmetricKey) throws -> Data {
        guard body.count == 32 else { throw VaultError("the file was changed or damaged") }
        let box = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: Data(count: 12)), ciphertext: body.prefix(16), tag: body.suffix(16))
        return try ChaChaPoly.open(box, using: key)
    }
}

/// `p256tag`: HPKE with P-256 and ChaCha20-Poly1305, for a key that does its half of the math inside
/// a chip. The key agreement is passed in, because the Secure Enclave will not give its key to a library.
extension Age {
    static let tagLabel = Data("age-encryption.org/p256tag".utf8)

    public struct TagRecipient: Recipient, Equatable {
        public let compressed: Data

        public init(string: String) throws {
            let decoded = try Bech32.decode(string)
            guard decoded.hrp == "age1tag", decoded.data.count == 33 else {
                throw VaultError("this is not a hardware recipient")
            }
            compressed = decoded.data
        }

        public init(publicKey: P256.KeyAgreement.PublicKey) { compressed = publicKey.compressedRepresentation }

        public var string: String { Bech32.encode(hrp: "age1tag", compressed) }

        public func wrap(_ fileKey: Data) throws -> Stanza {
            let target = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressed)
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let enc = ephemeral.publicKey.x963Representation
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: target)
            let schedule = try HPKE.schedule(shared: shared, enc: enc, recipient: target.x963Representation)
            let box = try ChaChaPoly.seal(fileKey, using: schedule.key, nonce: schedule.nonce)
            return Stanza(
                type: "p256tag", arguments: [base64(tag(enc: enc, recipient: compressed)), base64(enc)],
                body: box.ciphertext + box.tag)
        }
    }

    static func tag(enc: Data, recipient compressed: Data) -> Data {
        let digest = Data(SHA256.hash(data: compressed)).prefix(4)
        let extracted = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: enc + digest), salt: tagLabel)
        return extracted.withUnsafeBytes { Data($0.prefix(4)) }
    }

    /// Opens a `p256tag` stanza with whichever private key the caller holds.
    public static func unwrapTag(
        _ stanza: Stanza, publicKey: P256.KeyAgreement.PublicKey,
        agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret
    ) throws -> Data? {
        guard stanza.type == "p256tag", stanza.arguments.count == 2 else { return nil }
        let enc = try fromBase64(stanza.arguments[1])
        guard enc.count == 65, try fromBase64(stanza.arguments[0]) == tag(enc: enc, recipient: publicKey.compressedRepresentation)
        else { return nil }
        let shared = try agree(try P256.KeyAgreement.PublicKey(x963Representation: enc))
        let schedule = try HPKE.schedule(shared: shared, enc: enc, recipient: publicKey.x963Representation)
        guard stanza.body.count == 32 else { throw VaultError("the file was changed or damaged") }
        let box = try ChaChaPoly.SealedBox(
            nonce: schedule.nonce, ciphertext: stanza.body.prefix(16), tag: stanza.body.suffix(16))
        return try? ChaChaPoly.open(box, using: schedule.key)
    }

    /// RFC 9180, written out so the shared secret can come from the chip.
    enum HPKE {
        static let kemSuite = Data("KEM".utf8) + Data([0x00, 0x10])
        static let suite = Data("HPKE".utf8) + Data([0x00, 0x10, 0x00, 0x01, 0x00, 0x03])
        static let version = Data("HPKE-v1".utf8)

        static func extract(salt: Data, suite: Data, label: String, ikm: Data) -> SymmetricKey {
            let code = HKDF<SHA256>.extract(
                inputKeyMaterial: SymmetricKey(data: version + suite + Data(label.utf8) + ikm), salt: salt)
            return code.withUnsafeBytes { SymmetricKey(data: Data($0)) }
        }

        static func expand(prk: SymmetricKey, suite: Data, label: String, info: Data, count: Int) -> SymmetricKey {
            let length = Data([UInt8(count >> 8), UInt8(count & 255)])
            return prk.withUnsafeBytes { raw in
                HKDF<SHA256>.expand(
                    pseudoRandomKey: SymmetricKey(data: Data(raw)),
                    info: length + version + suite + Data(label.utf8) + info, outputByteCount: count)
            }
        }

        static func schedule(shared: SharedSecret, enc: Data, recipient: Data) throws -> (key: SymmetricKey, nonce: ChaChaPoly.Nonce) {
            let dh = shared.withUnsafeBytes { Data($0) }
            let eae = extract(salt: Data(), suite: kemSuite, label: "eae_prk", ikm: dh)
            let kemShared = expand(prk: eae, suite: kemSuite, label: "shared_secret", info: enc + recipient, count: 32)
            let bytes = { (key: SymmetricKey) in key.withUnsafeBytes { Data($0) } }
            let pskHash = bytes(extract(salt: Data(), suite: suite, label: "psk_id_hash", ikm: Data()))
            let infoHash = bytes(extract(salt: Data(), suite: suite, label: "info_hash", ikm: tagLabel))
            let context = Data([0]) + pskHash + infoHash
            let secret = extract(salt: bytes(kemShared), suite: suite, label: "secret", ikm: Data())
            let key = expand(prk: secret, suite: suite, label: "key", info: context, count: 32)
            let nonce = expand(prk: secret, suite: suite, label: "base_nonce", info: context, count: 12)
            return (key, try ChaChaPoly.Nonce(data: bytes(nonce)))
        }
    }
}

/// BIP 173, which age uses for its keys. A typo in a written-down key fails the checksum.
public enum Bech32 {
    private static let alphabet = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let generator: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
        var check: UInt32 = 1
        for value in values {
            let top = check >> 25
            check = (check & 0x1ff_ffff) << 5 ^ UInt32(value)
            for index in 0..<5 where (top >> UInt32(index)) & 1 == 1 { check ^= generator[index] }
        }
        return check
    }

    private static func expanded(_ hrp: String) -> [UInt8] {
        let bytes = Array(hrp.utf8)
        return bytes.map { $0 >> 5 } + [0] + bytes.map { $0 & 31 }
    }

    public static func encode(hrp: String, _ data: Data) -> String {
        var groups: [UInt8] = []
        var bits = 0
        var value = 0
        for byte in data {
            value = (value << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                groups.append(UInt8((value >> bits) & 31))
            }
            value &= (1 << bits) - 1
        }
        if bits > 0 { groups.append(UInt8((value << (5 - bits)) & 31)) }
        let check = polymod(expanded(hrp) + groups + [0, 0, 0, 0, 0, 0]) ^ 1
        let tail = (0..<6).map { UInt8((check >> UInt32(5 * (5 - $0))) & 31) }
        return hrp + "1" + String((groups + tail).map { alphabet[Int($0)] })
    }

    public static func decode(_ text: String) throws -> (hrp: String, data: Data) {
        let bad = VaultError("this key has a typo")
        guard text == text.lowercased() || text == text.uppercased() else { throw bad }
        let lower = text.lowercased()
        guard let separator = lower.lastIndex(of: "1"), separator != lower.startIndex else { throw bad }
        let hrp = String(lower[..<separator])
        var groups: [UInt8] = []
        for character in lower[lower.index(after: separator)...] {
            guard let value = alphabet.firstIndex(of: character) else { throw bad }
            groups.append(UInt8(value))
        }
        guard groups.count >= 6, polymod(expanded(hrp) + groups) == 1 else { throw bad }
        var data = Data()
        var bits = 0
        var value = 0
        for group in groups.dropLast(6) {
            value = (value << 5) | Int(group)
            bits += 5
            if bits >= 8 {
                bits -= 8
                data.append(UInt8((value >> bits) & 255))
                value &= (1 << bits) - 1
            }
        }
        guard bits < 5, value == 0 else { throw bad }
        return (hrp, data)
    }
}
