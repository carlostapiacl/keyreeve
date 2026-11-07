import Foundation

/// Whether Claude Code starts keyreeve's agent server, read from its own settings file. Read only:
/// connecting is a command you run, so the app never edits another program's settings.
public enum AgentConnection: Equatable, Sendable {
    /// Every Claude Code session gets it.
    case everywhere
    /// Only sessions opened in these folders get it.
    case folders([String])
    case none

    public static var claudeSettings: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude.json")
    }

    public static func read(from settings: URL = claudeSettings) -> AgentConnection {
        guard let data = try? Data(contentsOf: settings),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return .none }
        if hasKeyreeve(object["mcpServers"]) { return .everywhere }
        let projects = object["projects"] as? [String: Any] ?? [:]
        let folders = projects.compactMap { path, value in
            hasKeyreeve((value as? [String: Any])?["mcpServers"]) ? path : nil
        }
        return folders.isEmpty ? .none : .folders(folders.sorted())
    }

    /// A server that runs `keyreeve-vault mcp`, under any name.
    static func hasKeyreeve(_ servers: Any?) -> Bool {
        guard let servers = servers as? [String: Any] else { return false }
        return servers.values.contains { value in
            guard let server = value as? [String: Any], let command = server["command"] as? String else { return false }
            let arguments = server["args"] as? [String] ?? []
            return URL(fileURLWithPath: command).lastPathComponent == "keyreeve-vault" && arguments.first == "mcp"
        }
    }
}
