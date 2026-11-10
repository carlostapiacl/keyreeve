import Foundation

/// What `keyreeve bring --json` says: the keys it found, what each is and whether it works. It holds
/// paths, names and places in files, and never a value.
public struct BringReport: Codable, Equatable, Sendable {
    public struct Skipped: Codable, Equatable, Sendable {
        public var too_large = 0
        public var unreadable = 0
        public var too_deep = 0
        public var examples = 0
        public var stopped_early = false
    }

    public struct Summary: Codable, Equatable, Sendable {
        public var works = 0
        public var doubtful = 0
        public var other = 0
        public var dead = 0
        public var duplicates = 0
    }

    public var schema: Int
    public var scope: String
    public var roots: [String]
    public var suggested_projects: [String]
    public var files: Int
    public var checked: Bool
    public var skipped: Skipped
    public var summary: Summary
    public var candidates: [BringCandidate]
    /// Folders a search of everywhere did not finish before its time ran out.
    public var unfinished: [String]? = nil
}

public struct BringCandidate: Codable, Equatable, Hashable, Sendable, Identifiable {
    public enum Group: String, Codable, Sendable { case works, doubtful, other, dead }

    public struct Check: Codable, Equatable, Hashable, Sendable {
        public var recipe: String
        public var result: String
        public var reason: String?
    }

    public struct Origin: Codable, Equatable, Hashable, Sendable {
        public var path: String
        /// `home`, `project` or `folder`.
        public var area: String
        public var bytes: UInt64
        public var modified: UInt64
        public var parts: [Part]
    }

    public struct Part: Codable, Equatable, Hashable, Sendable {
        public var name: String?
        public var section: String?
        public var line: Int
        public var span: [Int]?
        public var json: [String]?
        public var whole: Bool
    }

    public var id: Int
    public var group: Group
    /// `key`, `configuration`, `login`, `document` or `public`.
    public var kind: String
    public var why: String
    /// The provider strong evidence names: the key's prefix, its variable, or its client id's domain. Only
    /// this one is ever sent the key, and only this one is saved with it.
    public var provider: String?
    /// `prefix`, `variable` or `domain`.
    public var evidence: String?
    /// Providers only suggested by a name, or by evidence that disagrees. Shown as a guess, never checked or saved.
    public var guessed: [String]
    public var check: Check?
    /// Why a key was not checked, when it was not.
    public var unchecked: String?
    public var server: String?
    public var origins: [Origin]
    public var duplicate: Bool
    public var from_project: Bool
    /// `seal`, `decide` or `skip`.
    public var suggested: String

    enum CodingKeys: String, CodingKey {
        case id, group, kind = "class", why, provider, evidence, guessed, check, unchecked, server, origins, duplicate
        case from_project, suggested
    }

    /// The names of its parts, as the file writes them: `client_id + client_secret`, or the line.
    public var partNames: String {
        guard let origin = origins.first else { return "" }
        return origin.parts.map { part in
            part.name ?? (part.whole ? T("whole file") : T("line %d", part.line))
        }.joined(separator: " + ")
    }
}

/// Where to look for keys.
public enum BringScope: Equatable, Sendable {
    /// The places tools keep keys in, and `.env` files under these project folders.
    case places(projects: [URL])
    case folder(URL)
    /// The whole home folder, or only the folders given, for `.env` files and files that hold keys.
    case everywhere(under: [URL])

    public var arguments: [String] {
        switch self {
        case .places(let projects): ["--places"] + projects.flatMap { ["--projects", $0.path] }
        case .folder(let folder): ["--folder", folder.path]
        case .everywhere(let under): ["--everywhere"] + under.flatMap { ["--under", $0.path] }
        }
    }
}

public enum BringRunner {
    /// Folders under the home where projects usually are, if they are there. The person picks which to search.
    public static func suggestedProjects(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [URL] {
        ["Desktop", "Documents", "code", "src", "Projects", "dev"].map { home.appendingPathComponent($0) }.filter {
            var folder: ObjCBool = false
            return FileManager.default.fileExists(atPath: $0.path, isDirectory: &folder) && folder.boolValue
        }
    }

    /// Runs `keyreeve bring` and reads its report. Each key is checked with one read-only request to
    /// its provider, unless `check` is false. Only the report is read: the command prints no value.
    public static func run(binary: URL, scope: BringScope, check: Bool = true) throws -> BringReport {
        let process = Process()
        let pipe = CheckRunner.privatePipe()
        process.executableURL = binary
        process.arguments = ["bring"] + scope.arguments + (check ? [] : ["--dry-run"]) + ["--json"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        try process.run()
        CheckRunner.watch(process, seconds: 10 * 60)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw CheckError(
                process.terminationReason == .uncaughtSignal
                    ? T("Looking for keys took too long and was stopped")
                    : T("Looking for keys ended with code %d", Int(process.terminationStatus)))
        }
        do {
            return try JSONDecoder().decode(BringReport.self, from: data)
        } catch {
            throw CheckError(T("The list of keys found could not be read"))
        }
    }
}

/// Reads a key found by `keyreeve bring` from its file, to seal it. The value is read where the report
/// says it stands, and only from the same file the report read: if the file changed since, nothing is
/// read, since its place may now hold other text.
public enum BringValue {
    public struct Read: Sendable {
        /// What is sealed: the value, or for a key of several parts, one `NAME=value` line each.
        public var data: Data
        /// For a key of several parts, their names joined with `+`, as keyreeve reads them.
        public var field: String?
    }

    public static func read(_ origin: BringCandidate.Origin) throws -> Read {
        let url = URL(fileURLWithPath: origin.path)
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attributes?[.size] as? NSNumber)?.uint64Value
        let modified = (attributes?[.modificationDate] as? Date).map { UInt64($0.timeIntervalSince1970.rounded(.down)) }
        guard attributes?[.type] as? FileAttributeType == .typeRegular else {
            throw CheckError(T("%@ is not there any more", url.lastPathComponent))
        }
        guard size == origin.bytes, modified == origin.modified else {
            throw CheckError(T("%@ changed after it was read. Look for keys again.", url.lastPathComponent))
        }
        let file = try Data(contentsOf: url)
        guard UInt64(file.count) == origin.bytes else {
            throw CheckError(T("%@ changed after it was read. Look for keys again.", url.lastPathComponent))
        }
        if origin.parts.count == 1, origin.parts[0].whole { return Read(data: file, field: nil) }
        let values = try origin.parts.map { try value(of: $0, in: file, name: url.lastPathComponent) }
        if values.count == 1 { return Read(data: Data(values[0].utf8), field: nil) }
        var names: [String] = []
        for (index, part) in origin.parts.enumerated() {
            var name = envName(part.name) ?? "part\(index + 1)"
            if names.contains(name) { name += "_\(index + 1)" }
            names.append(name)
        }
        // Quoted when a space or `#` would end the value early as keyreeve reads a line.
        let text = zip(names, values).map { name, value in
            let quote = (value.contains(" ") || value.contains("#")) && !value.contains("\"")
            return quote ? "\(name)=\"\(value)\"\n" : "\(name)=\(value)\n"
        }.joined()
        return Read(data: Data(text.utf8), field: names.joined(separator: "+"))
    }

    /// A name that reads back as written in a `NAME=value` line.
    public static func envName(_ name: String?) -> String? {
        guard let name, !name.isEmpty, name.utf8.allSatisfy({ $0 == 95 || (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) })
        else { return nil }
        return name
    }

    static func value(of part: BringCandidate.Part, in file: Data, name: String) throws -> String {
        let changed = CheckError(T("%@ changed after it was read. Look for keys again.", name))
        if let span = part.span, span.count == 2 {
            let (from, to) = (span[0], span[1])
            guard from >= 0, from < to, to <= file.count,
                let text = String(data: file.subdata(in: from..<to), encoding: .utf8),
                !text.isEmpty, !text.contains(where: \.isNewline)
            else { throw changed }
            return text
        }
        if let path = part.json, !path.isEmpty {
            var node: Any? = try? JSONSerialization.jsonObject(with: file)
            for key in path { node = (node as? [String: Any])?[key] }
            guard let text = node as? String, !text.isEmpty, !text.contains(where: \.isNewline) else { throw changed }
            return text
        }
        throw changed
    }
}
