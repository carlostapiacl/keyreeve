import Foundation

public struct CheckError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
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
        let pipe = privatePipe()
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
        plan: RotationPlan, resume: Bool, revokeNow: Bool = false, sealed: [String: String], binary: URL, vaultTool: URL,
        files: KeyreeveFiles
    ) throws -> RotationReport {
        try files.writePrivate(try JSONEncoder().encode(plan), to: files.rotationPlan)
        defer { try? FileManager.default.removeItem(at: files.rotationPlan) }
        var arguments = ["rotate", "--plan", files.rotationPlan.path, "--vault-tool", vaultTool.path, "--journal", files.rotations.path]
        if resume { arguments.append("--resume") }
        if revokeNow { arguments.append("--revoke-now") }
        let process = Process()
        let output = privatePipe()
        let errors = privatePipe()
        let input = privatePipe()
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

    public enum KeyCheck: Sendable { case works, rejected, unknown }

    /// Checks one key's text, with nothing written to the history, since this is not that key's
    /// present but an old copy of it.
    public static func checkText(_ text: String, recipe: String, field: String?, binary: URL) throws -> KeyCheck {
        var arguments = ["verify", recipe, "--key-stdin"]
        if let field, !field.isEmpty { arguments += ["--field", field] }
        switch try execute(binary, arguments, stdin: Data(text.utf8)) {
        case 0: return .works
        case 1: return .rejected
        default: return .unknown
        }
    }

    /// A key replaced by hand is another key, so the id on record must not be revoked for it.
    public static func forgetRotationID(of key: String, binary: URL, files: KeyreeveFiles) throws {
        guard FileManager.default.fileExists(atPath: files.rotations.path) else { return }
        guard try execute(binary, ["rotations", "--journal", files.rotations.path, "--forget-id", key]) == 0 else {
            throw CheckError(T("The vault could not be saved"))
        }
    }

    public static func rotations(binary: URL, files: KeyreeveFiles) -> [RotationStatus] {
        guard FileManager.default.fileExists(atPath: files.rotations.path) else { return [] }
        let process = Process()
        let pipe = privatePipe()
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
        let pipe = privatePipe()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let input = sealed.map { Data($0.utf8) }
        let inputPipe = input.map { _ in privatePipe() }
        if let inputPipe { process.standardInput = inputPipe }
        try process.run()
        if let input, let inputPipe { send(input, to: inputPipe) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw CheckError(T("The action did not finish")) }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// A pipe a child must not inherit by accident. A program started at the same moment would otherwise
    /// keep this pipe's write end open, and the command reading the keys would never see their end.
    static func privatePipe() -> Pipe {
        let pipe = Pipe()
        _ = fcntl(pipe.fileHandleForReading.fileDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        return pipe
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
        let pipe = privatePipe()
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let inputPipe = stdin.map { _ in privatePipe() }
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
        let inputPipe = stdin.map { _ in privatePipe() }
        if let inputPipe { process.standardInput = inputPipe }
        try process.run()
        if let stdin, let inputPipe { send(stdin, to: inputPipe) }
        process.waitUntilExit()
        return process.terminationStatus
    }
}
