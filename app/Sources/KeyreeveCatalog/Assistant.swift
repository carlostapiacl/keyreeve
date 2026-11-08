import Foundation

/// An AI the person already uses in their terminal, such as Claude Code, Codex or OpenCode, on their own
/// subscription. keyreeve has no AI and no key of its own: it hands the assistant words and reads back
/// words. It never hands it a key.
public struct Assistant: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var name: String
    /// The command, with `{prompt}` for the words, and `{out}` when the answer comes back in a file.
    public var command: [String]
    /// Whether it can read files on this Mac while it works. keyreeve says so before it is chosen.
    public var readsFiles: Bool

    public init(id: String, name: String, command: [String], readsFiles: Bool) {
        self.id = id
        self.name = name
        self.command = command
        self.readsFiles = readsFiles
    }

    public static let settingsKey = "assistant"
    public static let customKey = "assistantCommand"
}

public enum Assistants {
    /// The ones keyreeve knows how to call. Claude Code is limited to web search, so it cannot read a file.
    static func presets(home: String) -> [(Assistant, [String])] {
        let common = ["/opt/homebrew/bin", "/usr/local/bin", "\(home)/.local/bin"]
        let node = (try? FileManager.default.contentsOfDirectory(atPath: "\(home)/.nvm/versions/node"))?
            .sorted().reversed().map { "\(home)/.nvm/versions/node/\($0)/bin" } ?? []
        return [
            (Assistant(
                id: "claude", name: "Claude Code",
                command: ["claude", "-p", "--output-format", "text", "--tools", "WebSearch,WebFetch", "--no-session-persistence", "{prompt}"],
                readsFiles: false),
             common + ["\(home)/.claude/local"]),
            (Assistant(
                id: "codex", name: "Codex",
                command: ["codex", "exec", "--skip-git-repo-check", "-s", "read-only", "-o", "{out}", "{prompt}"],
                readsFiles: true),
             common + node),
            (Assistant(
                id: "opencode", name: "OpenCode",
                command: ["opencode", "run", "--pure", "{prompt}"],
                readsFiles: true),
             common + ["\(home)/.opencode/bin"]),
        ]
    }

    /// The assistants found on this Mac, with their programs' full paths. Apps opened from the Finder have
    /// a short PATH, so the usual places are searched by name.
    public static func available(home: String = NSHomeDirectory()) -> [Assistant] {
        presets(home: home).compactMap { preset, places in
            let program = preset.command[0]
            guard let found = places.map({ "\($0)/\(program)" }).first(where: FileManager.default.isExecutableFile) else { return nil }
            var assistant = preset
            assistant.command[0] = found
            return assistant
        }
    }

    /// A command a person wrote, split on spaces, such as `mycli ask {prompt}`. It is assumed to read files.
    public static func custom(_ line: String) -> Assistant? {
        let words = line.split(separator: " ").map(String.init)
        guard let first = words.first, words.contains("{prompt}") else { return nil }
        return Assistant(id: "custom", name: URL(fileURLWithPath: first).lastPathComponent, command: words, readsFiles: true)
    }

    /// Runs it in an empty folder of its own with a small environment, no input and a deadline, and returns
    /// what it answered. Nothing from keyreeve's folder or vault is in reach of the command line.
    public static func ask(_ assistant: Assistant, _ prompt: String, seconds: TimeInterval = 300) throws -> String {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-assistant-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let out = folder.appendingPathComponent("answer.txt")
        let arguments = assistant.command.dropFirst().map { word in
            word.replacingOccurrences(of: "{prompt}", with: prompt).replacingOccurrences(of: "{out}", with: out.path)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: assistant.command[0])
        process.arguments = Array(arguments)
        process.currentDirectoryURL = folder
        let program = URL(fileURLWithPath: assistant.command[0]).deletingLastPathComponent().path
        let parent = ProcessInfo.processInfo.environment
        // What it needs to find its own login and its runtime, and nothing of keyreeve's.
        process.environment = [
            "HOME": NSHomeDirectory(),
            "PATH": "\(program):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "LANG": parent["LANG"] ?? "en_US.UTF-8",
            "USER": parent["USER"] ?? NSUserName(),
            "TMPDIR": folder.path,
        ]
        let output = Pipe()
        let errors = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
        } catch {
            throw CheckError(T("%@ could not be started", assistant.name))
        }
        CheckRunner.watch(process, seconds: seconds)
        final class Box: @unchecked Sendable { var data = Data() }
        let problem = Box()
        let read = DispatchGroup()
        read.enter()
        DispatchQueue.global().async {
            problem.data = errors.fileHandleForReading.readDataToEndOfFile()
            read.leave()
        }
        let said = output.fileHandleForReading.readDataToEndOfFile()
        read.wait()
        process.waitUntilExit()
        let answer = assistant.command.contains("{out}") ? ((try? String(contentsOf: out, encoding: .utf8)) ?? "") : String(decoding: said, as: UTF8.self)
        guard process.terminationStatus == 0, !answer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            let why = String(decoding: problem.data, as: UTF8.self).split(separator: "\n").last.map(String.init) ?? ""
            throw CheckError(why.isEmpty ? T("%@ did not answer", assistant.name) : "\(assistant.name): \(why)")
        }
        return answer
    }

    /// A provider file drafted from the person's description, and checked. When the check fails, the
    /// assistant is shown what failed and tries once more; then the person sees what is left. Never saved here.
    public static func draftRecipe(
        _ assistant: Assistant, describing text: String, check: (String) throws -> CheckRunner.RecipeReport
    ) throws -> (yaml: String, report: CheckRunner.RecipeReport) {
        var yaml = RecipeSpec.extractYAML(try ask(assistant, RecipeSpec.guide + "\n\n" + text))
        var report = try check(yaml)
        if !report.ok {
            let again = RecipeSpec.guide + "\n\n" + text + "\n\nYour last file did not pass keyreeve's check. It said:\n"
                + report.lines.joined(separator: "\n") + "\n\nThe file was:\n" + yaml + "\n\nAnswer with the corrected file only."
            yaml = RecipeSpec.extractYAML(try ask(assistant, again))
            report = try check(yaml)
        }
        return (yaml, report)
    }
}
