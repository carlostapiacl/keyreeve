import CryptoKit
import Foundation

/// The services of your own on this Mac that you approved a key for, with your fingerprint: a server such as
/// `127.0.0.1:8790` that checks a token you keep in the vault. `local` in keys.toml says where a key would go;
/// only an address written here, for that key, lets the key service send it there.
///
/// Only loopback and one port: `127.0.0.1`, `[::1]` or `localhost`, a colon and the port. Never another address
/// of this machine or a private network, so an approval cannot become a way into one.
public struct LocalServices: Codable, Equatable, Sendable {
    public static let fileName = "local-services.json"

    /// The address approved for each key, by identifier.
    public var approved: [String: String] = [:]

    public init(approved: [String: String] = [:]) { self.approved = approved }

    /// The address as the proxy matches it, or nil for anything that is not loopback and a port. The proxy
    /// checks it again the same way.
    public static func address(_ text: String) -> String? {
        let text = text.trimmingCharacters(in: .whitespaces)
        guard let colon = text.lastIndex(of: ":") else { return nil }
        let host = text[..<colon].lowercased()
        let port = text[text.index(after: colon)...]
        guard !port.isEmpty, port.allSatisfy({ $0.isASCII && $0.isNumber }), let number = Int(port), (1...65535).contains(number)
        else { return nil }
        guard ["127.0.0.1", "[::1]", "localhost"].contains(host) else { return nil }
        return "\(host):\(number)"
    }

    /// Where this key may go, if `local` in keys.toml names a place the person approved for it. Throws when keys.toml
    /// names one that is not approved, or not local, so the agent hears why and the person what to do.
    public func destination(of key: KeyIndex.Key) throws -> String? {
        guard let declared = key.local else { return nil }
        guard let address = Self.address(declared) else {
            throw VaultError(
                "\(key.id) names \(declared) as its local service, which is not 127.0.0.1, [::1] or localhost with a port")
        }
        guard approved[key.id] == address else {
            throw VaultError(
                "\(key.id) is set to go to the local service \(address), which the person has not approved. "
                    + "Ask them to approve it in Keyreeve, on the key's page")
        }
        return address
    }

    /// The approvals, or none for a file that is missing or not this one: nothing is approved by a guess.
    public static func load(from url: URL) -> LocalServices {
        guard let data = try? Data(contentsOf: url) else { return LocalServices() }
        return (try? JSONDecoder().decode(LocalServices.self, from: data)) ?? LocalServices()
    }

    /// Approves `address` for `key`, in place of any other. Call it only after the person's fingerprint.
    public static func approve(key: String, address text: String, at url: URL) throws {
        guard let address = address(text) else {
            throw VaultError("\(text) is not a local service: write 127.0.0.1, [::1] or localhost, a colon and the port")
        }
        var all = load(from: url)
        all.approved[key] = address
        try save(all, to: url)
    }

    /// Takes the approval away. Needs no fingerprint: it only closes.
    public static func withdraw(key: String, at url: URL) throws {
        var all = load(from: url)
        guard all.approved.removeValue(forKey: key) != nil else { return }
        try save(all, to: url)
    }

    /// Names each key's local service in keys.toml and approves it, for several keys at once. Every key must be in
    /// keys.toml and every address local, or nothing is written. Call it only after the person's fingerprint.
    public static func apply(_ wanted: [String: String], keys: URL, approvals: URL) throws {
        var clean: [String: String] = [:]
        for (id, text) in wanted {
            guard let address = address(text) else {
                throw VaultError("\(text) is not a local service: write 127.0.0.1, [::1] or localhost, a colon and the port")
            }
            clean[id] = address
        }
        try KeyIndex.change(at: keys) { index in
            for (id, address) in clean {
                guard index.isTaken(id) else { throw VaultError("no key is called \(id) in keys.toml") }
                guard index.key(id)?.provider != KeyService.sshProvider,
                    !index.unoffered.contains(where: { $0.id == id && $0.provider == KeyService.sshProvider })
                else { throw VaultError("\(id) is an SSH key, which cannot go to a local service") }
                index.update(id: id) { $0.local = address }
            }
        }
        var all = load(from: approvals)
        for (id, address) in clean { all.approved[id] = address }
        try save(all, to: approvals)
    }

    /// Takes a key's local service away, from keys.toml and from the approvals. Needs no fingerprint: it only closes.
    public static func remove(_ id: String, keys: URL, approvals: URL) throws {
        try KeyIndex.change(at: keys) { index in index.update(id: id) { $0.local = nil } }
        try withdraw(key: id, at: approvals)
    }

    private static func save(_ all: LocalServices, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try PrivateFile.write(try encoder.encode(all), to: url)
    }
}

/// What a server of yours keeps in place of a token it checks: the token's SHA-256. A server that compares the
/// SHA-256 of what it receives with this needs no secret to start, so it starts with no fingerprint, and a copy of
/// its settings opens nothing. Given only for a value too random to be found from its hash.
public enum ServerVerifier {
    /// The least randomness a value needs before its hash is handed out, by the same count the stand-ins use:
    /// log2(26) for each letter, log2(10) for each digit, nothing for anything else.
    public static let minimumBits = 128.0

    public static func bits(of value: String) -> Double {
        value.reduce(0) { total, character in
            switch character {
            case "a"..."z", "A"..."Z": return total + log2(26)
            case "0"..."9": return total + log2(10)
            default: return total
            }
        }
    }

    /// `sha256:` and the hex of the value's SHA-256, or an error for a value that could be guessed from it.
    public static func verifier(of value: String) throws -> String {
        guard bits(of: value) >= minimumBits else {
            throw VaultError(
                "this key is too short or plain for its hash to be safe to hand out (\(Int(bits(of: value))) bits, under \(Int(minimumBits))). Rotate it to a long random token first")
        }
        let digest = SHA256.hash(data: Data(value.utf8))
        return "sha256:" + digest.map { String(format: "%02x", $0) }.joined()
    }
}
