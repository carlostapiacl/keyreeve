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
    public static func run(
        _ items: [CatalogItem], binary: URL, keysFolder: URL, files: KeyreeveFiles
    ) throws {
        try files.writePrivate(try plan(for: items), to: files.plan)
        defer { try? FileManager.default.removeItem(at: files.plan) }
        let verify = try execute(
            binary,
            ["verify", "--plan", files.plan.path, "--keys", keysFolder.path, "--history", files.history.path])
        // 0 is all passed and 1 is at least one did not. Both finished their work.
        guard verify == 0 || verify == 1 else { throw CheckError(T("The check could not start")) }

        try rebuildCatalog(binary: binary, files: files)
    }

    /// Asks each provider whose key this is. The answer's chosen fields go to a private file.
    public static func identify(
        _ items: [CatalogItem], providers: ProviderDirectory, binary: URL, keysFolder: URL, files: KeyreeveFiles
    ) throws {
        try files.writePrivate(try plan(for: items.filter(providers.canIdentify)), to: files.plan)
        defer { try? FileManager.default.removeItem(at: files.plan) }
        let code = try execute(
            binary,
            ["identify", "--plan", files.plan.path, "--keys", keysFolder.path, "--details", files.details.path])
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
        arguments += ["--edits", files.edits.path]
        guard try execute(binary, arguments) == 0 else {
            throw CheckError(T("The list could not be updated"))
        }
    }

    private static func execute(_ binary: URL, _ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}
