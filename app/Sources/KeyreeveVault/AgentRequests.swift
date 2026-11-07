import Foundation

/// What an agent asks for, shown to the person before the fingerprint. The key and the program come
/// from keyreeve; the reason is the agent's own words, cleaned and cut.
public struct AgentRequest: Equatable, Sendable {
    public let key: String
    public let program: String
    public let reason: String
    /// The whole command, as the agent sent it, on one line and cut.
    public let command: String

    public init(key: String, program: String, reason: String, command: [String] = []) {
        self.key = key
        self.program = URL(fileURLWithPath: program).lastPathComponent
        self.reason = String(Self.oneLine(reason).prefix(200))
        self.command = String(Self.oneLine(Self.shown(command)).prefix(300))
    }

    static func oneLine(_ text: String) -> String {
        String(text.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : Character($0) })
            .trimmingCharacters(in: .whitespaces)
    }

    /// A command as a person would type it, with quotes where a word needs them.
    public static func shown(_ command: [String]) -> String {
        command.map { word in
            word.isEmpty || word.contains(where: { " \"'$`\\".contains($0) }) ? "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'" : word
        }.joined(separator: " ")
    }
}

/// An agent asking for a key that is closed to it. The key and provider come from keyreeve; the reason
/// and the suggestion are the agent's, shown as such.
public struct AccessRequest: Equatable, Sendable {
    public let key: String
    public let provider: String?
    public let agent: String
    public let reason: String
    /// For how long the agent suggests, or nil for always.
    public let hours: Int?

    public init(key: String, provider: String?, agent: String, reason: String, hours: Int?) {
        self.key = key
        self.provider = provider
        self.agent = agent
        self.reason = String(AgentRequest.oneLine(reason).prefix(200))
        self.hours = hours
    }
}

/// A yes to an access request: the key is free to that agent for some hours, or nil for always. One
/// fingerprint opens it, and nothing more is asked until the time is up or the app locks.
public struct AccessDecision: Equatable, Sendable {
    public let hours: Int?
    public init(hours: Int?) { self.hours = hours }

    public static let hourChoices = [1, 4, 8, 24]
    /// What the agent may suggest, as the tool takes it.
    public static func hours(from duration: String) -> Int?? {
        if duration == "always" { return .some(nil) }
        guard duration.hasSuffix("h"), let number = Int(duration.dropLast()), hourChoices.contains(number) else { return nil }
        return .some(number)
    }
}

/// How long the person's yes lasts, for this key and program in this agent's session.
public enum AgentApproval: Equatable, Sendable {
    case once
    case lasting(TimeInterval)

    public static let choices: [(label: String, approval: AgentApproval)] = [
        ("Once", .once), ("1 hour", .lasting(3600)), ("4 hours", .lasting(4 * 3600)),
        ("8 hours", .lasting(8 * 3600)), ("24 hours", .lasting(24 * 3600)),
    ]
}
