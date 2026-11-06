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

    /// Asks for the finger once, so several keys can open on one touch.
    public static func confirm(reason: String) throws -> LAContext {
        let context = LAContext()
        let done = DispatchSemaphore(value: 0)
        var accepted = false
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            accepted = success
            done.signal()
        }
        done.wait()
        guard accepted else { throw VaultError("the fingerprint was not accepted") }
        return context
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

/// The vault's folder: `vault.json`, which is sealed, and the chip's blob.
public struct VaultStore: Sendable {
    public let directory: URL
    var vaultURL: URL { directory.appendingPathComponent("vault.json") }
    /// The blob that belongs to this public key. The vault names its key, so moving to a new chip
    /// switches blobs in the one atomic write of `vault.json`, and a crash cannot split the pair.
    func blobURL(for publicKey: String) -> URL {
        let digest = SHA256.hash(data: Data(publicKey.utf8)).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent("enclave-\(digest).blob")
    }

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
            guard vault.schema == 2 else { throw VaultError("this vault's format is not one this version reads") }
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

    public func saveBlob(_ blob: Data, for publicKey: String) throws { try write(blob, to: blobURL(for: publicKey)) }

    /// Creates the vault, unless one appeared in the meantime. Nothing gets overwritten.
    public func create(_ vault: VaultFile, blob: Data) throws {
        try withLock {
            guard !exists else { throw VaultError("there is already a vault") }
            try saveBlob(blob, for: vault.enclave)
            try save(vault)
        }
    }

    /// Keeps which key was used and by which program, next to the vault. It never holds a value or
    /// the command's arguments, which can carry anything. A failure here stops nothing.
    public func recordUse(of name: String, by command: String, reason: String? = nil) {
        var entry: [String: Any] = [
            "at": Int(Date().timeIntervalSince1970), "name": name,
            "command": URL(fileURLWithPath: command).lastPathComponent,
        ]
        if let reason { entry["reason"] = String(reason.prefix(200)) }
        guard let line = try? JSONSerialization.data(withJSONObject: entry) else { return }
        let path = directory.deletingLastPathComponent().appendingPathComponent("usage.jsonl").path
        let descriptor = open(path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
        guard descriptor >= 0 else { return }
        defer { close(descriptor) }
        _ = (line + Data("\n".utf8)).withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
    }

    public func loadBlob() throws -> Data {
        try Data(contentsOf: blobURL(for: try load().enclave))
    }

    /// Changes the vault with no other process in the middle. Without this, two writers that loaded
    /// the same file would each save it, and the first one's key would vanish.
    @discardableResult
    public func update<T>(_ change: (inout VaultFile) throws -> T) throws -> T {
        try withLock {
            var vault = try load()
            let result = try change(&vault)
            try save(vault)
            return result
        }
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try prepareDirectory()
        // Close on exec: a child that inherited this would hold the vault's lock for as long as it runs.
        let descriptor = open(directory.appendingPathComponent(".lock").path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw VaultError("the vault could not be locked") }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw VaultError("the vault could not be locked") }
        return try body()
    }

    private func prepareDirectory() throws {
        let previous = umask(0o077)
        defer { umask(previous) }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    /// Reaches the disk before it returns: a rotation records a step only after this. The new file
    /// is private from its first byte, and the rename leaves the old file or the new one.
    private func write(_ data: Data, to url: URL) throws {
        try prepareDirectory()
        let temp = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        let descriptor = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw VaultError("the vault could not be saved") }
        var saved = false
        defer {
            close(descriptor)
            if !saved { unlink(temp.path) }
        }
        try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(descriptor, bytes.baseAddress! + offset, bytes.count - offset)
                guard written > 0 else { throw VaultError("the vault could not be saved") }
                offset += written
            }
        }
        guard fsync(descriptor) == 0, rename(temp.path, url.path) == 0 else {
            throw VaultError("the vault could not be saved")
        }
        saved = true
        let folder = open(directory.path, O_RDONLY)
        guard folder >= 0 else { throw VaultError("the vault could not be saved") }
        defer { close(folder) }
        guard fsync(folder) == 0 else { throw VaultError("the vault could not be saved") }
    }
}
