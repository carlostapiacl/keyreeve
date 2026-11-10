import Foundation

/// A procedure that updates one kind of place, as `keyreeve procedures --json` lists it, with the text a person
/// reads before approving it.
public struct ProcedureInfo: Decodable, Equatable, Identifiable, Sendable {
    public struct Param: Decodable, Equatable, Sendable {
        public let name: String
        public let optional: Bool
        public let about: String
    }

    public let name: String
    /// `builtin` for one that ships, `folder` for one of the person's.
    public let origin: String
    public let sha256: String
    public let description: String
    public let params: [Param]
    public let text: String
    public let problem: String?
    public var id: String { name + "\u{0}" + origin }

    public var isBuiltin: Bool { origin == "builtin" }
}

/// Runs procedures through the engine, which checks each one's pin and keeps values out of what it says.
public enum PlaceRunner {
    /// What a check found. A hash is compared with the vault's in memory and never kept.
    public enum Found: Equatable, Sendable {
        case hash(String)
        case absent
        case present
        case failed(String)
    }

    /// Every procedure the engine knows: those that ship, then the folder's.
    public static func procedures(binary: URL, folder: URL) -> [ProcedureInfo] {
        guard let (status, data) = try? run(binary, ["procedures", "--json", "--folder", folder.path], seconds: 30), status == 0
        else { return [] }
        return (try? JSONDecoder().decode([ProcedureInfo].self, from: data)) ?? []
    }

    /// The pins procedures have now, by name. One the folder shadows a shipped name with is never used, so it is
    /// left out.
    public static func pins(_ list: [ProcedureInfo]) -> [String: String] {
        Dictionary(list.filter { $0.problem == nil }.map { ($0.name, $0.sha256) }, uniquingKeysWith: { first, _ in first })
    }

    static func arguments(
        _ verb: String, procedure: String, pin: String, params: [String: String], folder: URL, vaultTool: URL?
    ) -> [String] {
        var arguments = ["place", verb, procedure, "--sha256", pin, "--folder", folder.path]
        if let vaultTool { arguments += ["--vault-tool", vaultTool.path] }
        for (name, value) in params.sorted(by: { $0.key < $1.key }) { arguments += ["--param", "\(name)=\(value)"] }
        return arguments
    }

    public static func check(
        procedure: String, pin: String, params: [String: String], binary: URL, folder: URL, vaultTool: URL?
    ) -> Found {
        let arguments = arguments("check", procedure: procedure, pin: pin, params: params, folder: folder, vaultTool: vaultTool)
        guard let (status, data) = try? run(binary, arguments, seconds: 150) else { return .failed(T("The check could not start")) }
        guard status == 0 else { return .failed(T("The place did not answer a check")) }
        return found(in: data)
    }

    /// Reads the engine's answer. Only a hash or a word is taken, so nothing else could pass for one.
    public static func found(in data: Data) -> Found {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let state = object["state"] as? String
        else { return .failed(T("The place did not answer a check")) }
        switch state {
        case "absent": return .absent
        case "present": return .present
        case "hash":
            guard let hash = object["sha256"] as? String, hash.count == 64, hash.allSatisfy(\.isHexDigit) else {
                return .failed(T("The place did not answer a check"))
            }
            return .hash(hash.lowercased())
        default: return .failed(T("The place did not answer a check"))
        }
    }

    /// Puts the value in the place. It goes on stdin, never in an argument.
    public static func apply(
        procedure: String, pin: String, params: [String: String], value: String, binary: URL, folder: URL, vaultTool: URL?
    ) throws {
        let arguments = arguments("apply", procedure: procedure, pin: pin, params: params, folder: folder, vaultTool: vaultTool)
        let (status, _) = try run(binary, arguments, stdin: Data(value.utf8), seconds: 150)
        guard status == 0 else { throw CheckError(T("The place was not updated")) }
    }

    /// Runs the engine with a time limit, its errors dropped: they are its own words, and a procedure's are not.
    static func run(_ binary: URL, _ arguments: [String], stdin: Data? = nil, seconds: TimeInterval) throws -> (Int32, Data) {
        let process = Process()
        let output = Pipe()
        _ = fcntl(output.fileHandleForReading.fileDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(output.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        process.executableURL = binary
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let input = stdin.map { _ in Pipe() }
        if let input {
            _ = fcntl(input.fileHandleForReading.fileDescriptor, F_SETFD, FD_CLOEXEC)
            _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        }
        process.standardInput = input.map { $0 as Any } ?? FileHandle.nullDevice
        try process.run()
        CheckRunner.watch(process, seconds: seconds)
        if let stdin, let input {
            signal(SIGPIPE, SIG_IGN)
            try? input.fileHandleForWriting.write(contentsOf: stdin)
            try? input.fileHandleForWriting.close()
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, data)
    }
}
