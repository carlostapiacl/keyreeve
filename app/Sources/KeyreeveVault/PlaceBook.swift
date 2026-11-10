import CryptoKit
import Foundation

/// Where each key lives, and how to update it there: a place is a key, a procedure that knows that kind of
/// place, its parameters and a label a person reads, such as "VPS2 · /opt/lh/.env · OPENAI_API_KEY". It holds
/// no value. A place receives the real key when it is updated, so it is pinned to the SHA-256 of the procedure
/// a person approved with their fingerprint, and a procedure that changed does not run until they approve it
/// again. The app owns this file; agents only propose places, which wait for the person.
public struct PlaceBook: Codable, Hashable, Sendable {
    public static let fileName = "key-places.json"
    public static let proceduresFolderName = "procedures"
    /// The procedures that ship with keyreeve, in `procedures/` of the repository. A file of the person's cannot
    /// take one of these names.
    public static let builtinProcedures = [
        "coolify-env", "github-secret", "netlify-env", "ssh-env", "supabase-secret", "vercel-env",
    ]
    public static let maxPlaces = 100

    public var schema = 1
    public var places: [Place] = []

    public init(places: [Place] = []) { self.places = places }

    public struct Place: Codable, Hashable, Identifiable, Sendable {
        public var id: String
        /// The key's identifier, as keys.toml gives it.
        public var key: String
        public var procedure: String
        public var params: [String: String]
        public var label: String
        /// The SHA-256 of the procedure the person approved. A place without one never runs.
        public var sha256: String?
        public var approved: Date?
        /// Who proposed it: `you`, or the agent.
        public var by: String?
        /// Why the agent thinks the key is there, in its own words.
        public var why: String?
        public var lastCheck: Check?

        public init(
            id: String = PlaceBook.newID(), key: String, procedure: String, params: [String: String], label: String,
            sha256: String? = nil, approved: Date? = nil, by: String? = nil, why: String? = nil, lastCheck: Check? = nil
        ) {
            self.id = id
            self.key = key
            self.procedure = procedure
            self.params = params
            self.label = label
            self.sha256 = sha256
            self.approved = approved
            self.by = by
            self.why = why
            self.lastCheck = lastCheck
        }

        /// The same key, procedure and parameters: the same place, whatever its label says.
        public func isSame(as other: Place) -> Bool {
            key == other.key && procedure == other.procedure && params == other.params
        }
    }

    /// What the last check found. Never a value, and never the hash: only how it compares.
    public struct Check: Codable, Hashable, Sendable {
        public var at: Date
        public var result: Result
        /// Why it could not tell, in keyreeve's words.
        public var detail: String?
        public init(at: Date, result: Result, detail: String? = nil) {
            self.at = at
            self.result = result
            self.detail = detail
        }
    }

    public enum Result: String, Codable, Sendable {
        /// The value in place is the one in the vault.
        case same
        /// An earlier value of this key, such as the one before a rotation.
        case old
        /// Another value.
        case different
        case absent
        /// A value is there, and the place does not give back even its hash.
        case present
        /// The hash came back, and the vault's value has not been compared yet: that takes a fingerprint once.
        case notCompared = "not-compared"
        /// The procedure changed since it was approved, so it did not run.
        case changed
        case error
    }

    public static func newID() -> String { "p-" + UUID().uuidString.lowercased().prefix(12) }

    public func places(forKey key: String) -> [Place] { places.filter { $0.key == key } }

    // MARK: Names and parameters, as the engine checks them too

    public static func isValidProcedureName(_ name: String) -> Bool {
        (1...64).contains(name.utf8.count) && !name.hasPrefix("-")
            && name.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }

    public static func checkParams(_ params: [String: String]) throws {
        guard params.count <= 16 else { throw VaultError("at most 16 parameters") }
        for (name, value) in params {
            let bytes = Array(name.utf8)
            guard (1...32).contains(bytes.count), (97...122).contains(bytes[0]),
                bytes.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 })
            else { throw VaultError("\(name) is not a parameter name: lower case letters, digits and _") }
            guard value.count <= 512, !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw VaultError("the parameter \(name) must be one short line")
            }
        }
    }

    /// A procedure of the person's, read from their folder: `<name>.sh` or `<name>`. Nil for one that ships, whose
    /// text the engine holds, or for none.
    public static func folderProcedure(_ name: String, in folder: URL) -> Data? {
        guard isValidProcedureName(name), !builtinProcedures.contains(name) else { return nil }
        for candidate in [folder.appendingPathComponent(name + ".sh"), folder.appendingPathComponent(name)] {
            var isFolder: ObjCBool = false
            guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isFolder), !isFolder.boolValue,
                let data = try? Data(contentsOf: candidate), data.count <= 256 * 1024
            else { continue }
            return data
        }
        return nil
    }

    public static func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    /// Whether a procedure by this name exists: one that ships, or a file in the folder.
    public static func procedureExists(_ name: String, in folder: URL) -> Bool {
        builtinProcedures.contains(name) || folderProcedure(name, in: folder) != nil
    }

    // MARK: The file

    public static func file(home: URL) -> URL { home.appendingPathComponent(fileName) }

    /// The person's procedures: `procedures` in keyreeve's home, which can be a git repository.
    public static func proceduresFolder(home: URL) -> URL { home.appendingPathComponent(proceduresFolderName) }

    /// The book as it is on disk, or an empty one. A damaged file reads as empty and is never written over.
    public static func load(from url: URL) -> PlaceBook { (try? loadStrict(from: url)) ?? PlaceBook() }

    static func loadStrict(from url: URL) throws -> PlaceBook {
        guard FileManager.default.fileExists(atPath: url.path) else { return PlaceBook() }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(PlaceBook.self, from: Data(contentsOf: url))
        } catch {
            throw VaultError("\(url.lastPathComponent) cannot be read, so it was left as it is")
        }
    }

    /// Changes the book under a lock, so the app and an agent's server never write over each other.
    @discardableResult
    public static func update(at url: URL, _ change: (inout PlaceBook) throws -> Void) throws -> PlaceBook {
        try PrivateFile.folder(url.deletingLastPathComponent())
        let lockFile = open(url.path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lockFile >= 0 else { throw VaultError("the places could not be locked") }
        defer { close(lockFile) }
        guard flock(lockFile, LOCK_EX) == 0 else { throw VaultError("the places could not be locked") }
        defer { flock(lockFile, LOCK_UN) }
        let before = try loadStrict(from: url)
        var after = before
        try change(&after)
        if after != before {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
            try PrivateFile.write(try encoder.encode(after), to: url)
        }
        return after
    }

    // MARK: Approving

    /// Adds places the person approved, each pinned to the hash of its procedure as they saw it. A place that is
    /// already there is approved again with the new pin rather than added twice. Returns how many changed.
    @discardableResult
    public mutating func approve(_ chosen: [Place], pins: [String: String], at date: Date) -> Int {
        var changed = 0
        for var place in chosen {
            guard let pin = pins[place.procedure] else { continue }
            place.sha256 = pin
            place.approved = date
            if let index = places.firstIndex(where: { $0.isSame(as: place) }) {
                places[index].sha256 = pin
                places[index].approved = date
                places[index].label = place.label
                changed += 1
            } else if places.count < Self.maxPlaces * 10 {
                places.append(place)
                changed += 1
            }
        }
        return changed
    }

    /// Whether this place may run now: approved, and its procedure still the one approved.
    public static func status(of place: Place, currentPin: String?) -> Status {
        guard let pin = place.sha256 else { return .waiting }
        guard let currentPin else { return .missing }
        return pin.lowercased() == currentPin.lowercased() ? .approved : .changed
    }

    public enum Status: String, Sendable {
        case approved
        /// Not approved yet.
        case waiting
        /// The procedure changed since it was approved.
        case changed
        /// The procedure is gone.
        case missing
    }
}
