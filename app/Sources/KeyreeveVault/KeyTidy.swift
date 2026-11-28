import Foundation

/// Agents tidy the list of keys; the person approves.
///
/// An agent reads each key's gaps and how it is used (`review`), proposes changes by identifier (`check`), and the
/// person applies the ones they want (`apply`). The rules are checked here, not left to the agent's judgment: a
/// change that breaks one comes back refused with the reason, so the agent learns the convention by using it.
public enum KeyTidy {
    /// What an agent may change of one key. Nil leaves a field as it is.
    public struct Change: Codable, Equatable, Sendable {
        public var key: String
        public var id: String?
        public var description: String?
        public var project: String?
        public var provider: String?
        public var variable: String?
        public var account: String?
        public var field: String?
        /// Tags to add. Tags are never taken away here.
        public var tags: [String]?
        public var archive: Bool?
        /// How the agent knows: what it read, where. Shown to the person beside the change.
        public var why: String

        public init(
            key: String, id: String? = nil, description: String? = nil, project: String? = nil, provider: String? = nil,
            variable: String? = nil, account: String? = nil, field: String? = nil, tags: [String]? = nil,
            archive: Bool? = nil, why: String
        ) {
            self.key = key
            self.id = id
            self.description = description
            self.project = project
            self.provider = provider
            self.variable = variable
            self.account = account
            self.field = field
            self.tags = tags
            self.archive = archive
            self.why = why
        }

        /// One field that changes: its name as keys.toml writes it, what it holds now and what it will hold.
        public struct Difference: Equatable, Sendable {
            public var field: String
            public var old: String?
            public var new: String
        }

        /// What changes, field by field, against the key as it is. Tags list only those added; archiving is apart.
        public func differences(from before: KeyIndex.Key?) -> [Difference] {
            var out: [Difference] = []
            func add(_ field: String, _ old: String?, _ new: String?) {
                guard let new, new != old else { return }
                out.append(Difference(field: field, old: old, new: new))
            }
            add("id", before?.id ?? key, id)
            add("description", before?.description, description)
            add("project", before?.project, project)
            add("provider", before?.provider, provider)
            add("variable", before?.variable, variable)
            add("account", before?.account, account)
            add("field", before?.field, field)
            let added = (tags ?? []).filter { !(before?.more.tags ?? []).contains($0) }
            if !added.isEmpty { out.append(Difference(field: "tags", old: nil, new: "+ " + added.joined(separator: ", "))) }
            return out
        }

        /// Whether it archives a key not archived yet.
        public func archives(_ before: KeyIndex.Key?) -> Bool { archive == true && before?.more.archived != true }

        /// What it does, in one line, for the log and the agent.
        public func summary(from before: KeyIndex.Key?) -> String {
            var parts = differences(from: before).map { $0.old == nil && $0.field == "tags"
                ? "tags \($0.new)" : "\($0.field): \($0.old ?? "—") → \($0.new)" }
            if archives(before) { parts.append("archive") }
            return parts.isEmpty ? "no change" : parts.joined(separator: "; ")
        }
    }

    /// How a key was used lately, from the usage log: never a value.
    public struct Use: Equatable, Sendable {
        public var count = 0
        public var last: Date?
        public var agents: Set<String> = []
        public var folders: Set<String> = []
        public var hosts: Set<String> = []
        public init() {}
    }

    /// What tidying reads, gathered once per call.
    public struct Context: Sendable {
        public var index: KeyIndex
        public var entries: [AuditLog.Entry]
        public var digests: ValueDigests
        public init(index: KeyIndex, entries: [AuditLog.Entry], digests: ValueDigests) {
            self.index = index
            self.entries = entries
            self.digests = digests
        }
    }

    /// The kind of request a proposal leaves for the person.
    public static let requestKind = "tidy"

    /// At most this many changes in one proposal, so the person can read them all.
    public static let maxChanges = 60
    /// A key used within these days is not dead: it is not archived from here.
    public static let recentDays = 30
    static var recent: TimeInterval { Double(recentDays) * 86400 }

    /// The convention, as the agent reads it in the tool's description and at the top of a review.
    public static let guide = """
        How keys are named and sorted (the tool refuses what breaks it, and says why):
        - id: lower case, digits and dashes, at most 40. A provider's key starts with the provider: resend-acme, \
        meta-hz, coolify-v2-deploy. A secret of the person's own software starts with its project: \
        shop-api-jwt-secret, desk-token. Then the account or project, then what it is for, only if needed to tell \
        two apart.
        - Renaming keeps the old id working (scripts and permissions that name it go on), so rename only to follow \
        this convention, never to taste.
        - project: one of the projects review_keys lists. A new one is allowed but the person sees it marked new.
        - description: at most 80 characters on what it is and where it is used. Never a value, a URL with a token, \
        or a password.
        - variable: the environment variable its programs read, UPPER_CASE.
        - archive: only a key that is dead (its check failed) or a copy of another (same value), and never one used in \
        the last 30 days.
        - why: say how you know, such as "read /opt/app/.env on VPS1: names RESEND_API_KEY". Leave a key out rather \
        than guess.
        """
}
