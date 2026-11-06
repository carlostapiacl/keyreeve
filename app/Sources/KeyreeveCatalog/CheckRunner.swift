import Foundation

public struct CheckError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Where keyreeve keeps its private files. The defaults are those the README uses.
public struct KeyreeveFiles: Sendable {
    public let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keyreeve")
    }

    public var catalog: URL { directory.appendingPathComponent("catalog.csv") }
    public var inventory: URL { directory.appendingPathComponent("inventory.json") }
    public var rules: URL { directory.appendingPathComponent("rules.yaml") }
    public var history: URL { directory.appendingPathComponent("history.jsonl") }
    public var usage: URL { directory.appendingPathComponent("usage.jsonl") }
    public var details: URL { directory.appendingPathComponent("details.json") }
    public var edits: URL { directory.appendingPathComponent("edits.json") }
    public var ignored: URL { directory.appendingPathComponent("ignored.json") }
    public var words: URL { directory.appendingPathComponent("words.txt") }
    public var moved: URL { directory.appendingPathComponent("moved.json") }
    public var originals: URL { directory.appendingPathComponent("originals") }
    public var rotations: URL { directory.appendingPathComponent("rotations.jsonl") }
    public var places: URL { directory.appendingPathComponent("places.json") }
    var rotationPlan: URL { directory.appendingPathComponent(".rotation-plan.json") }
    var plan: URL { directory.appendingPathComponent(".check-plan.json") }
    var settings: URL { directory.appendingPathComponent("app-settings.json") }

    public func activity() -> [ActivityItem] {
        let read = { (url: URL) in (try? String(contentsOf: url, encoding: .utf8)) ?? "" }
        return ActivityItem.parse(history: read(history), usage: read(usage))
    }

    public func keysFolder() -> URL? {
        guard let data = try? Data(contentsOf: settings),
            let values = try? JSONDecoder().decode([String: String].self, from: data),
            let path = values["keys_folder"]
        else { return nil }
        return URL(fileURLWithPath: path)
    }

    public func saveKeysFolder(_ url: URL) throws {
        try writePrivate(try JSONEncoder().encode(["keys_folder": url.path]), to: settings)
    }

    func writePrivate(_ data: Data, to url: URL) throws {
        let previous = umask(0o077)
        defer { umask(previous) }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

public enum CheckRunner {
    /// A plan for `keyreeve verify`. JSON is valid YAML, and it escapes any file name safely.
    public static func plan(for items: [CatalogItem]) throws -> Data {
        struct Plan: Encodable { let keys: [Key] }
        struct Key: Encodable {
            let file: String
            let recipe: String
            let field: String?
            let host: String?
        }
        let keys = items.filter(\.canCheck).flatMap { item in
            item.recipes.map {
                Key(
                    file: item.path, recipe: $0, field: item.field.isEmpty ? nil : item.field,
                    host: item.host.isEmpty ? nil : item.host)
            }
        }
        return try JSONEncoder().encode(Plan(keys: keys))
    }

    /// Runs the checks and rebuilds the catalog. The command's output is discarded, because the
    /// history already holds the results, so nothing it prints can stay in this app's memory.
    /// `sealed` holds copies opened from the vault, by path, and they travel on stdin alone.
    public static func run(
        _ items: [CatalogItem], binary: URL, keysFolder: URL, files: KeyreeveFiles,
        sealed: [String: String] = [:],
        progress: @escaping @Sendable (Int, Int) -> Void = { _, _ in }
    ) throws {
        try files.writePrivate(try plan(for: items), to: files.plan)
        defer { try? FileManager.default.removeItem(at: files.plan) }
        var arguments = ["verify", "--plan", files.plan.path, "--keys", keysFolder.path, "--history", files.history.path, "--progress"]
        if !sealed.isEmpty { arguments.append("--sealed-stdin") }
        let verify = try streaming(binary, arguments, stdin: try payload(sealed), progress: progress)
        // 0 is all passed and 1 is at least one did not. Both finished their work.
        guard verify == 0 || verify == 1 else { throw CheckError(T("The check could not start")) }

        try rebuildCatalog(binary: binary, files: files)
    }

    /// Asks each provider whose key this is. The answer's chosen fields go to a private file.
    public static func identify(
        _ items: [CatalogItem], providers: ProviderDirectory, binary: URL, keysFolder: URL, files: KeyreeveFiles,
        sealed: [String: String] = [:]
    ) throws {
        try files.writePrivate(try plan(for: items.filter(providers.canIdentify)), to: files.plan)
        defer { try? FileManager.default.removeItem(at: files.plan) }
        var arguments = ["identify", "--plan", files.plan.path, "--keys", keysFolder.path, "--details", files.details.path]
        if !sealed.isEmpty { arguments.append("--sealed-stdin") }
        let code = try execute(binary, arguments, stdin: try payload(sealed))
        guard code == 0 else { throw CheckError(T("The check could not start")) }
    }

    /// The providers keyreeve knows, from what ships and from your own files.
    public static func providers(binary: URL) -> ProviderDirectory {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = binary
        process.arguments = ["recipes", "--json"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return ProviderDirectory() }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return ProviderDirectory.parse(data)
    }

    public static func approveHost(_ host: String, for provider: String, binary: URL) throws {
        guard try execute(binary, ["recipes", "approve-host", provider, host]) == 0 else {
            throw CheckError(T("That is not a server address"))
        }
    }

    public static func approve(_ provider: String, binary: URL) throws {
        guard try execute(binary, ["recipes", "approve", provider]) == 0 else {
            throw CheckError(T("The check could not start"))
        }
    }

    /// Scans the folder again, so names, dates and permissions match what is on disk. The
    /// command reads the key files, and writes only their descriptions.
    public static func refresh(binary: URL, keysFolder: URL, files: KeyreeveFiles) throws {
        var arguments = ["inventory", keysFolder.path, "--out", files.inventory.path]
        if FileManager.default.fileExists(atPath: files.words.path) {
            arguments += ["--words", files.words.path]
        }
        guard try execute(binary, arguments) == 0 else {
            throw CheckError(T("The folder could not be scanned"))
        }
        try rebuildCatalog(binary: binary, files: files)
    }

    public static func rebuildCatalog(binary: URL, files: KeyreeveFiles) throws {
        guard FileManager.default.fileExists(atPath: files.inventory.path) else {
            throw CheckError(T("Scan the folder first"))
        }
        var arguments = ["catalog", files.inventory.path, "--out", files.catalog.path, "--history", files.history.path]
        if FileManager.default.fileExists(atPath: files.rules.path) {
            arguments += ["--rules", files.rules.path]
        }
        arguments += ["--edits", files.edits.path, "--moved", files.moved.path]
        guard try execute(binary, arguments) == 0 else {
            throw CheckError(T("The list could not be updated"))
        }
    }

    /// Runs one rotation with the opened copies on stdin, and returns what happened.
    public static func rotate(
        plan: RotationPlan, resume: Bool, sealed: [String: String], binary: URL, vaultTool: URL, files: KeyreeveFiles
    ) throws -> RotationReport {
        try files.writePrivate(try JSONEncoder().encode(plan), to: files.rotationPlan)
        defer { try? FileManager.default.removeItem(at: files.rotationPlan) }
        var arguments = ["rotate", "--plan", files.rotationPlan.path, "--vault-tool", vaultTool.path, "--journal", files.rotations.path]
        if resume { arguments.append("--resume") }
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        let input = Pipe()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = errors
        process.standardInput = input
        try process.run()
        send(try JSONEncoder().encode(sealed), to: input)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let problem = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0, let report = try? JSONDecoder().decode(RotationReport.self, from: data) else {
            // The command's errors are its own words, and they never quote a value.
            let why = String(decoding: problem, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw CheckError(why.isEmpty ? T("The rotation did not finish") : why)
        }
        return report
    }

    public static func rotations(binary: URL, files: KeyreeveFiles) -> [RotationStatus] {
        guard FileManager.default.fileExists(atPath: files.rotations.path) else { return [] }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = binary
        process.arguments = ["rotations", "--journal", files.rotations.path]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return [] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (try? JSONDecoder().decode([RotationStatus].self, from: data)) ?? []
    }

    /// Runs a button of your own, and returns what it says, which the command has already filtered.
    public static func runAction(
        provider: String, action: CustomAction, item: CatalogItem, binary: URL, keysFolder: URL?,
        sealed: String? = nil
    ) throws -> String {
        var arguments = ["action", provider, action.id]
        if action.needs_key {
            if sealed != nil {
                arguments.append("--key-stdin")
            } else if let keysFolder {
                arguments += ["--key-file", keysFolder.appendingPathComponent(item.path).path]
            }
            if !item.field.isEmpty { arguments += ["--field", item.field] }
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let input = sealed.map { Data($0.utf8) }
        let inputPipe = input.map { _ in Pipe() }
        if let inputPipe { process.standardInput = inputPipe }
        try process.run()
        if let input, let inputPipe { send(input, to: inputPipe) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw CheckError(T("The action did not finish")) }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Copies from the vault, as the command wants them. No copies means nothing to send.
    private static func payload(_ sealed: [String: String]) throws -> Data? {
        sealed.isEmpty ? nil : try JSONEncoder().encode(sealed)
    }

    /// A command that stops early must fail on its own, and must not take this app with it.
    private static func send(_ data: Data, to pipe: Pipe) {
        signal(SIGPIPE, SIG_IGN)
        try? pipe.fileHandleForWriting.write(contentsOf: data)
        try? pipe.fileHandleForWriting.close()
    }

    /// Reads progress lines as they come. They hold two counts, and the rest of the output is dropped.
    private static func streaming(
        _ binary: URL, _ arguments: [String], stdin: Data? = nil, progress: @Sendable (Int, Int) -> Void
    ) throws -> Int32 {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let inputPipe = stdin.map { _ in Pipe() }
        if let inputPipe { process.standardInput = inputPipe }
        try process.run()
        if let stdin, let inputPipe { send(stdin, to: inputPipe) }
        var pending = Data()
        while true {
            let chunk = pipe.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            pending.append(chunk)
            while let end = pending.firstIndex(of: 10) {
                let line = String(decoding: pending[pending.startIndex..<end], as: UTF8.self)
                pending.removeSubrange(pending.startIndex...end)
                let parts = line.split(separator: " ")
                if parts.count == 3, parts[0] == "progress", let done = Int(parts[1]), let total = Int(parts[2]) {
                    progress(done, total)
                }
            }
        }
        process.waitUntilExit()
        return process.terminationStatus
    }

    private static func execute(_ binary: URL, _ arguments: [String], stdin: Data? = nil) throws -> Int32 {
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let inputPipe = stdin.map { _ in Pipe() }
        if let inputPipe { process.standardInput = inputPipe }
        try process.run()
        if let stdin, let inputPipe { send(stdin, to: inputPipe) }
        process.waitUntilExit()
        return process.terminationStatus
    }
}

public struct RotationPlan: Encodable, Sendable {
    public var key: String
    public var recipe: String
    public var field: String?
    public var host: String?
    public var admin: String?
    public var admin_field: String?
    public var overlap_secs: Int
    public var known_id: String?
    public var issued_name: String
    public var original: String?
    public var place_files: [String]
    public var place_actions: [String]

    public init(
        item: CatalogItem, places: KeyPlaces, admin: CatalogItem?, original: String?, now: Date = Date()
    ) {
        key = item.path
        recipe = item.recipes.first ?? ""
        field = item.field.isEmpty ? nil : item.field
        host = item.host.isEmpty ? nil : item.host
        self.admin = admin?.path
        admin_field = admin.flatMap { $0.field.isEmpty ? nil : $0.field }
        overlap_secs = places.overlapMinutes * 60
        known_id = item.details?.fields["key_id"]
        // The provider shows this name, and a file's path is private.
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.dateFormat = "yyyy-MM-dd"
        issued_name = "keyreeve-\(format.string(from: now))"
        self.original = original
        place_files = places.files
        place_actions = places.actions
    }
}

public struct RotationReport: Decodable, Equatable, Sendable {
    public let outcome: String
    public let reason: String?
    public let revoke_after: Double?
    public let manual: [String]
}

public struct RotationStatus: Decodable, Equatable, Identifiable, Sendable {
    public let key: String
    public let phase: String
    public let at: Double
    public let revoke_after: Double?
    public let reason: String?
    public let manual: [String]
    public var id: String { key }

    public init(key: String, phase: String, at: Double = 0, revoke_after: Double? = nil, reason: String? = nil, manual: [String] = []) {
        self.key = key
        self.phase = phase
        self.at = at
        self.revoke_after = revoke_after
        self.reason = reason
        self.manual = manual
    }

    public var isOpen: Bool { ["waiting", "unfinished", "rolling_back"].contains(phase) }
}

/// Where a key is used, chosen by you. The rotation updates each place before the old key goes.
public struct KeyPlaces: Codable, Equatable, Sendable {
    public var files: [String] = []
    /// `provider/action`, from a provider file you approved.
    public var actions: [String] = []
    /// You said nothing else holds this key, so it is safe with no places.
    public var nothingElse = false
    /// How long the old key keeps working after the new one is in place.
    public var overlapMinutes = 1440
    /// Another key that creates and revokes, when this one cannot.
    public var admin: String?

    public init() {}

    public var isDecided: Bool { nothingElse || !files.isEmpty || !actions.isEmpty }
}

extension KeyreeveFiles {
    public func allPlaces() -> [String: KeyPlaces] {
        guard let data = try? Data(contentsOf: places) else { return [:] }
        return (try? JSONDecoder().decode([String: KeyPlaces].self, from: data)) ?? [:]
    }

    public func savePlaces(_ value: KeyPlaces, for path: String) throws {
        var all = allPlaces()
        all[path] = value
        try writePrivate(try JSONEncoder().encode(all), to: places)
    }
}
