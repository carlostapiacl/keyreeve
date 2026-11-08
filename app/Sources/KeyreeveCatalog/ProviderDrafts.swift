import Foundation

/// Which assistant the person chose in Settings, if any. None is the default: keyreeve asks no AI unless told to.
public enum AssistantChoice {
    public static let none = "none"
    public static let custom = "custom"
    /// Set once the person has read what goes to the assistant.
    public static let consentKey = "assistantConsent"

    public static func current(defaults: UserDefaults = .standard, available: [Assistant]) -> Assistant? {
        let chosen = defaults.string(forKey: Assistant.settingsKey) ?? none
        if chosen == custom { return Assistants.custom(defaults.string(forKey: Assistant.customKey) ?? "") }
        return available.first { $0.id == chosen }
    }
}

/// A provider file put in words a person reads before saving it: where the key may go, how it travels,
/// and what is asked to check it. Read from the file's text, without a YAML library, and so only the
/// common shapes; anything it cannot read is left out rather than guessed.
public struct RecipeSummary: Equatable, Sendable {
    public var provider: String?
    public var name: String?
    public var hosts: [String] = []
    public var auth: String?
    public var verify: String?
    public var rotates = false
    public var runsPrograms = false

    public init(_ text: String) {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        func value(_ key: String) -> String? {
            guard let line = lines.first(where: { $0.hasPrefix(key + ":") }) else { return nil }
            let rest = line.dropFirst(key.count + 1).trimmingCharacters(in: .whitespaces)
            return rest.isEmpty ? nil : rest.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        }
        /// A key's block: its own line and the indented or listed ones under it.
        func block(_ key: String) -> String? {
            guard let start = lines.firstIndex(where: { $0.hasPrefix(key + ":") }) else { return nil }
            var text = lines[start]
            for line in lines[(start + 1)...] {
                guard line.hasPrefix(" ") || line.hasPrefix("\t") || line.hasPrefix("- ") else { break }
                text += "\n" + line
            }
            return text
        }
        func field(_ name: String, in text: String) -> String? {
            let pattern = "\\b\(name):\\s*\"?([^,}\"\\n]+)"
            guard let regex = try? NSRegularExpression(pattern: pattern),
                let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
                let range = Range(match.range(at: 1), in: text)
            else { return nil }
            return text[range].trimmingCharacters(in: .whitespaces)
        }
        provider = value("provider")
        name = value("name")
        if let hostsBlock = block("hosts") {
            if let open = hostsBlock.firstIndex(of: "[") {
                hosts = hostsBlock[hostsBlock.index(after: open)...].prefix { $0 != "]" }.split(separator: ",")
                    .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " \"'")) }.filter { !$0.isEmpty }
            } else {
                hosts = hostsBlock.split(separator: "\n").dropFirst()
                    .map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("- ") }
                    .map { String($0.dropFirst(2)).trimmingCharacters(in: CharacterSet(charactersIn: " \"'")) }
            }
        }
        if let authBlock = block("auth") {
            if let type = field("type", in: authBlock) {
                auth = type
            } else if let header = field("header", in: authBlock) {
                auth = "header " + header
            }
        }
        if let verifyBlock = block("verify"), let method = field("method", in: verifyBlock), let path = field("path", in: verifyBlock) {
            verify = "\(method) \(path)"
        }
        rotates = lines.contains { $0.hasPrefix("create:") } && lines.contains { $0.hasPrefix("revoke:") }
        runsPrograms = text.contains("program:")
    }
}

extension ProviderDirectory {
    /// A provider keyreeve ships whose id or name is one of the words of a description, so a person who
    /// writes "Sentry" is offered the one that exists before a new one is drafted.
    public func shipped(matching description: String) -> ProviderInfo? {
        let words = Set(description.lowercased().split { !$0.isLetter && !$0.isNumber && $0 != "-" }.map(String.init))
        return all.first { info in
            info.source != "local" && info.problem == nil
                && (words.contains(info.id.lowercased()) || (!info.name.isEmpty && words.contains(info.name.lowercased())))
        }
    }
}
