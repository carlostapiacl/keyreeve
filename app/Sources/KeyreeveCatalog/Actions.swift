import Foundation

/// What a person can do about a key that asks for attention.
public enum KeyAction: Hashable, Sendable {
    case openProvider(URL)
    case confirmRevoked
    case markRevoked
    case checkAgain
    case notInUse
    case fixPermissions
    case ignore

    public var title: String {
        switch self {
        case .openProvider: return T("Open provider")
        case .confirmRevoked, .markRevoked: return T("I already revoked it")
        case .checkAgain: return T("Check again")
        case .notInUse: return T("Not in use")
        case .fixPermissions: return T("Fix permissions")
        case .ignore: return T("Ignore for 30 days")
        }
    }
}

/// Pages where each provider's keys are managed.
public enum Providers {
    static let pages: [String: String] = [
        "anthropic": "https://console.anthropic.com/settings/keys",
        "aws": "https://console.aws.amazon.com/iam/home",
        "cloudflare": "https://dash.cloudflare.com/profile/api-tokens",
        "github": "https://github.com/settings/tokens",
        "gitlab": "https://gitlab.com/-/user_settings/personal_access_tokens",
        "hetzner": "https://console.hetzner.cloud/projects",
        "instagram": "https://developers.facebook.com/apps",
        "langsmith": "https://smith.langchain.com/settings",
        "meta": "https://developers.facebook.com/apps",
        "netlify": "https://app.netlify.com/user/applications",
        "openai": "https://platform.openai.com/api-keys",
        "sentry": "https://sentry.io/settings/account/api/auth-tokens/",
        "stripe": "https://dashboard.stripe.com/apikeys",
        "supabase": "https://supabase.com/dashboard/account/tokens",
    ]

    /// The places a key can be checked. Each ships with the command as a recipe.
    public static let checkable = [
        "anthropic", "cloudflare", "github", "gitlab", "hetzner", "instagram", "langsmith", "meta",
        "netlify", "openai", "sentry", "stripe", "supabase",
    ]

    public static func displayName(_ name: String) -> String {
        let names = [
            "anthropic": "Anthropic", "cloudflare": "Cloudflare", "github": "GitHub", "gitlab": "GitLab",
            "hetzner": "Hetzner", "instagram": "Instagram", "langsmith": "LangSmith", "meta": "Meta",
            "netlify": "Netlify", "openai": "OpenAI", "sentry": "Sentry", "stripe": "Stripe", "supabase": "Supabase",
        ]
        return names[name] ?? name
    }

    public static func page(for item: CatalogItem) -> URL? {
        let tagged = item.tags.filter { $0.hasPrefix("provider:") }.map { String($0.dropFirst(9)) }
        let names = item.recipes + tagged
        return names.lazy.compactMap { pages[$0] }.first.flatMap(URL.init(string:))
    }
}

/// The buttons for a key, most useful first. Saying a key is revoked is confirmed by a check when
/// a check exists, because a key that still works is not revoked, whatever anyone says.
public func actions(for item: CatalogItem, at now: Date = Date()) -> [KeyAction] {
    guard let rank = item.attentionRanked(at: now)?.rank else { return [] }
    var list: [KeyAction] = []
    switch rank {
    case 0, 1, 2:
        if let page = Providers.page(for: item) { list.append(.openProvider(page)) }
        list.append(item.canCheck ? .confirmRevoked : .markRevoked)
    case 3:
        list += [.checkAgain, .notInUse]
    case 4:
        list.append(.fixPermissions)
    default:
        break
    }
    list.append(.ignore)
    return list
}

public struct KeyEdit: Codable, Equatable, Sendable {
    public var tags: [String]?
    public var level: String?
    public var recipes: [String]?
    public var field: String?

    public init(tags: [String]? = nil, level: String? = nil, recipes: [String]? = nil, field: String? = nil) {
        self.tags = tags
        self.level = level
        self.recipes = recipes
        self.field = field
    }
}

extension KeyreeveFiles {
    public func saveEdit(_ edit: KeyEdit, for path: String) throws {
        var all = (try? JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: edits))) ?? [:]
        var merged = all[path] ?? KeyEdit()
        merged.tags = edit.tags ?? merged.tags
        merged.level = edit.level ?? merged.level
        merged.recipes = edit.recipes ?? merged.recipes
        merged.field = edit.field ?? merged.field
        all[path] = merged
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try writePrivate(try encoder.encode(all), to: edits)
    }

    public func ignoredKeys() -> [String: Date] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([String: Date].self, from: Data(contentsOf: ignored))) ?? [:]
    }

    public func ignore(_ path: String, until: Date) throws {
        var all = ignoredKeys()
        all[path] = until
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try writePrivate(try encoder.encode(all), to: ignored)
    }

    /// Changes who can read the file, and never its contents. It stays inside the folder, and
    /// it does not follow a link, which could point anywhere.
    public func fixPermissions(of path: String, in folder: URL) throws {
        let root = folder.standardizedFileURL.path + "/"
        let target = folder.appendingPathComponent(path).standardizedFileURL
        guard target.path.hasPrefix(root) else { throw CheckError(T("Scan the folder first")) }
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw CheckError(T("Scan the folder first"))
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
    }
}
