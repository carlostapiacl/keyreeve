import Foundation

/// Several keys asked for at once, shown to the person in one window: every key with its account, the program, the
/// agent and the reason. The person unticks what they do not want and chooses how long, then gives one fingerprint.
/// Everything here comes from keyreeve, except `reason`, which is the caller's own words.
public struct KeyBatch: Codable, Equatable, Sendable {
    public struct Item: Codable, Equatable, Sendable {
        public var key: String
        public var account: String?
        public var provider: String?
        public var program: String
        public var agent: String?
        public var reason: String?

        public init(key: String, account: String? = nil, provider: String? = nil, program: String, agent: String? = nil, reason: String? = nil) {
            self.key = key
            self.account = account
            self.provider = provider
            self.program = URL(fileURLWithPath: program).lastPathComponent
            self.agent = agent
            self.reason = reason.map { String(AgentRequest.oneLine($0).prefix(200)) }
        }
    }

    /// How long a yes lasts.
    public enum Lasts: Codable, Equatable, Sendable, Hashable {
        case seconds(Int)
        /// Until the command that asked ends, and at most a day.
        case untilDone
        /// For this program in this folder, across restarts, with no fingerprint again.
        case always
    }

    public var items: [Item]
    /// The set's name, when the keys came from one.
    public var set: String?
    /// The folder the command runs in, if known.
    public var folder: String?
    /// The choices shown, in order, and the one selected to start.
    public var choices: [Lasts]
    public var suggested: Lasts

    public init(items: [Item], set: String? = nil, folder: String? = nil, choices: [Lasts], suggested: Lasts) {
        self.items = items
        self.set = set
        self.folder = folder
        self.choices = choices
        self.suggested = choices.contains(suggested) ? suggested : choices.first ?? .seconds(KeyService.defaultSeconds)
    }

    /// What the person chose. Nil, a closed window or a no, grants nothing.
    public struct Answer: Codable, Equatable, Sendable {
        /// Indexes into `items`, of the keys left ticked.
        public var chosen: [Int]
        public var lasts: Lasts
        public init(chosen: [Int], lasts: Lasts) {
            self.chosen = chosen
            self.lasts = lasts
        }
    }

    /// The choices for keys used from a terminal: 5 minutes, until the command finishes, a day, and, when the program
    /// and the folder are known, always for them. A time the caller asked for that is none of those comes first.
    public static func choices(asked seconds: Int?, canStand: Bool) -> (choices: [Lasts], suggested: Lasts) {
        var choices: [Lasts] = [.seconds(KeyService.defaultSeconds), .untilDone, .seconds(KeyService.maxSeconds)]
        if canStand { choices.append(.always) }
        guard let seconds else { return (choices, choices[0]) }
        let asked = Lasts.seconds(min(max(seconds, 1), KeyService.maxSeconds))
        if !choices.contains(asked) { choices.insert(asked, at: 0) }
        return (choices, asked)
    }

    /// Words for a choice, in English or Spanish.
    public static func label(_ lasts: Lasts, program: String?, folder: String?, spanish: Bool) -> String {
        switch lasts {
        case .seconds(let seconds) where seconds >= 3600 && seconds % 3600 == 0:
            let hours = seconds / 3600
            if hours == 24 { return spanish ? "1 día" : "1 day" }
            return spanish ? "\(hours) h" : "\(hours) h"
        case .seconds(let seconds) where seconds >= 60:
            return "\(seconds / 60) min"
        case .seconds(let seconds):
            return "\(seconds) s"
        case .untilDone:
            return spanish ? "Hasta que termine" : "Until it finishes"
        case .always:
            let where_ = folder.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "-"
            return spanish
                ? "Siempre, para \(program ?? "este programa") en \(where_)"
                : "Always, for \(program ?? "this program") in \(where_)"
        }
    }
}

/// An agent asking for several closed keys at once with `request_access`. The window lists each one; the person
/// unticks what they do not want, chooses for how long, and gives one fingerprint for the rest.
public struct AccessBatch: Equatable, Sendable {
    public struct Item: Equatable, Sendable {
        public let key: String
        public let provider: String?
        public let account: String?
        public init(key: String, provider: String?, account: String?) {
            self.key = key
            self.provider = provider
            self.account = account
        }
    }

    public let items: [Item]
    public let agent: String
    public let reason: String
    /// What the agent suggests, nil for always.
    public let hours: Int?

    public init(items: [Item], agent: String, reason: String, hours: Int?) {
        self.items = items
        self.agent = agent
        self.reason = String(AgentRequest.oneLine(reason).prefix(200))
        self.hours = hours
    }

    /// The keys left ticked and for how long, or nil for a no.
    public struct Answer: Equatable, Sendable {
        public let keys: [String]
        public let hours: Int?
        public init(keys: [String], hours: Int?) {
            self.keys = keys
            self.hours = hours
        }
    }
}
