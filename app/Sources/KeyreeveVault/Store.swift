import CryptoKit
import Foundation
import LocalAuthentication

/// A key inside this Mac's Secure Enclave. Using it asks for a fingerprint, and it cannot leave
/// the chip: the blob on disk is useless on another Mac.
public struct EnclaveRecipient: VaultRecipient {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    public var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }

    public func sharedSecret(with other: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: other)
    }

    /// Survives adding a new finger. Without a working sensor, use the recovery key.
    public static func create() throws -> (recipient: EnclaveRecipient, blob: Data) {
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryAny],
                &error)
        else { throw VaultError("could not set up the fingerprint requirement") }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        return (EnclaveRecipient(key: key), key.dataRepresentation)
    }

    public static func load(blob: Data, reason: String, interactive: Bool = true) throws -> EnclaveRecipient {
        let context = LAContext()
        context.localizedReason = reason
        context.interactionNotAllowed = !interactive
        return try load(blob: blob, context: context)
    }

    /// With a context that already has the fingerprint, so a batch asks once.
    public static func load(blob: Data, context: LAContext) throws -> EnclaveRecipient {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: context)
        return EnclaveRecipient(key: key)
    }
}

/// The vault's folder: `vault.json`, which is sealed, and `enclave.blob`.
public struct VaultStore {
    public let directory: URL
    var vaultURL: URL { directory.appendingPathComponent("vault.json") }
    var blobURL: URL { directory.appendingPathComponent("enclave.blob") }

    public init(directory: URL) { self.directory = directory }

    public static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keyreeve/vault")
    }

    public var exists: Bool { FileManager.default.fileExists(atPath: vaultURL.path) }

    public func load() throws -> VaultFile {
        guard exists else { throw VaultError("there is no vault yet: run keyreeve-vault init") }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            let vault = try decoder.decode(VaultFile.self, from: Data(contentsOf: vaultURL))
            guard vault.schema == 1 else { throw VaultError("unknown vault schema \(vault.schema)") }
            return vault
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError("the vault file cannot be read")
        }
    }

    public func save(_ vault: VaultFile) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try write(try encoder.encode(vault), to: vaultURL)
    }

    public func saveBlob(_ blob: Data) throws { try write(blob, to: blobURL) }

    /// Keeps which key was used and by which program, next to the vault. It never holds a value or
    /// the command's arguments, which can carry anything. A failure here stops nothing.
    public func recordUse(of name: String, by command: String) {
        let entry: [String: Any] = [
            "at": Int(Date().timeIntervalSince1970), "name": name,
            "command": URL(fileURLWithPath: command).lastPathComponent,
        ]
        guard let line = try? JSONSerialization.data(withJSONObject: entry) else { return }
        let path = directory.deletingLastPathComponent().appendingPathComponent("usage.jsonl").path
        let descriptor = open(path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
        guard descriptor >= 0 else { return }
        defer { close(descriptor) }
        _ = (line + Data("\n".utf8)).withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
    }

    public func loadBlob() throws -> Data { try Data(contentsOf: blobURL) }

    private func write(_ data: Data, to url: URL) throws {
        let previous = umask(0o077)
        defer { umask(previous) }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
