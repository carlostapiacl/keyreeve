import Foundation

/// Reads `keyreeve://name` references from an env file, so a repository or an agent's working folder
/// can hold the reference and never the value.
public enum EnvReferences {
    public enum Line: Equatable {
        case value(name: String, value: String)
        case reference(name: String, key: String, field: String?)
    }

    public static let scheme = "keyreeve://"

    public static func parse(_ text: String) -> [Line] {
        text.split(whereSeparator: \.isNewline).compactMap { raw in
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { return nil }
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)) }
            guard let separator = line.firstIndex(of: "=") else { return nil }
            let name = line[..<separator].trimmingCharacters(in: .whitespaces)
            let value = cleaned(line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces))
            guard value.hasPrefix(scheme) else { return .value(name: name, value: value) }
            let target = value.dropFirst(scheme.count)
            // A path can hold `#` only in a rotation's own names, which are not keys anyone refers to.
            if let mark = target.lastIndex(of: "#") {
                return .reference(
                    name: name, key: String(target[..<mark]), field: String(target[target.index(after: mark)...]))
            }
            return .reference(name: name, key: String(target), field: nil)
        }
    }

    /// A quoted value ends at its quote, and an unquoted one at a comment after a space.
    private static func cleaned(_ text: String) -> String {
        if let first = text.first, first == "\"" || first == "'",
            let end = text.dropFirst().firstIndex(of: first)
        {
            return String(text[text.index(after: text.startIndex)..<end])
        }
        if let comment = text.range(of: " #") {
            return text[..<comment.lowerBound].trimmingCharacters(in: .whitespaces)
        }
        return text
    }

    /// The value a reference means, from the sealed text of a file: one field, or a one-line file.
    public static func value(in sealed: Data, field: String?) throws -> String {
        guard let text = String(data: sealed, encoding: .utf8) else { throw VaultError("this key is not text") }
        if let field {
            // The last one, as a shell or `env` would end up with.
            for case .value(let name, let value) in parse(text).reversed() where name == field { return value }
            if let data = text.data(using: .utf8),
                let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let value = object[field] as? String
            {
                return value
            }
            for raw in text.split(whereSeparator: \.isNewline).reversed() {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.hasPrefix(field + ":") {
                    return cleaned(String(line.dropFirst(field.count + 1)).trimmingCharacters(in: .whitespaces))
                }
            }
            throw VaultError("this key has no field \(field)")
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: \.isNewline) else {
            throw VaultError("this key's file has several lines, so name a field")
        }
        return trimmed
    }

    /// Variables that change which program runs or what it loads, rather than what it is told. A file
    /// from a repository could set them to run something else, so they need the person's say-so.
    public static func changesWhatRuns(_ name: String) -> Bool {
        let upper = name.uppercased()
        let exact: Set<String> = [
            "PATH", "BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "PS4", "PROMPT_COMMAND", "IFS",
            "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PERL5OPT", "PERL5LIB",
            "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
            "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
            "SSH_AUTH_SOCK", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "HOME",
        ]
        return exact.contains(upper) || upper.hasPrefix("DYLD_") || upper.hasPrefix("LD_")
    }
}
