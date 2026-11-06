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

/// What keyreeve knows about providers, read from their files through the command. Nothing about
/// any provider is written in this app, so a new file needs no new app.
public struct ProviderInfo: Codable, Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let dashboard: String?
    public let hosts: [String]
    public let source: String
    public let approved: Bool
    public let can_check: Bool
    public let can_identify: Bool
    public let self_hosted: Bool
    public let problem: String?

    public init(
        id: String, name: String, dashboard: String? = nil, hosts: [String] = [], source: String = "builtin",
        approved: Bool = true, can_check: Bool = true, can_identify: Bool = false, self_hosted: Bool = false,
        problem: String? = nil
    ) {
        self.id = id
        self.name = name
        self.dashboard = dashboard
        self.hosts = hosts
        self.source = source
        self.approved = approved
        self.can_check = can_check
        self.can_identify = can_identify
        self.self_hosted = self_hosted
        self.problem = problem
    }

    public var needsApproval: Bool { source == "local" && !approved && problem == nil }
}

public struct ProviderDirectory: Sendable {
    public let all: [ProviderInfo]
    public init(_ all: [ProviderInfo] = []) { self.all = all }

    public static func parse(_ data: Data) -> ProviderDirectory {
        ProviderDirectory((try? JSONDecoder().decode([ProviderInfo].self, from: data)) ?? [])
    }

    /// Those a key may be sent to from the app.
    public var usable: [ProviderInfo] { all.filter { $0.approved && $0.problem == nil } }

    public func name(of id: String) -> String { all.first { $0.id == id }?.name ?? id }

    private func names(for item: CatalogItem) -> [String] {
        item.recipes + item.tags.filter { $0.hasPrefix("provider:") }.map { String($0.dropFirst(9)) }
    }

    public func page(for item: CatalogItem) -> URL? {
        names(for: item).lazy
            .compactMap { id in self.all.first { $0.id == id }?.dashboard }
            .first.flatMap(URL.init(string:))
    }

    /// A provider each person runs needs the address of your server before it can be asked.
    public func needsHost(_ item: CatalogItem) -> Bool {
        item.host.isEmpty && item.recipes.contains { id in all.contains { $0.id == id && $0.self_hosted } }
    }

    public func canCheck(_ item: CatalogItem) -> Bool { item.canCheck && !needsHost(item) }

    public func canIdentify(_ item: CatalogItem) -> Bool {
        guard canCheck(item) else { return false }
        return item.recipes.contains { id in usable.contains { $0.id == id && $0.can_identify } }
    }
}

/// The buttons for a key, most useful first. Saying a key is revoked is confirmed by a check when
/// a check exists, because a key that still works is not revoked, whatever anyone says.
public func actions(
    for item: CatalogItem, providers: ProviderDirectory, at now: Date = Date()
) -> [KeyAction] {
    guard let rank = item.attentionRanked(at: now)?.rank else { return [] }
    var list: [KeyAction] = []
    switch rank {
    case 0, 1, 2:
        if let page = providers.page(for: item) { list.append(.openProvider(page)) }
        list.append(item.canCheck ? .confirmRevoked : .markRevoked)
    case 3:
        list += [.checkAgain, .notInUse]
    case 4:
        list.append(.fixPermissions)
    case 6:
        if let page = providers.page(for: item) { list.append(.openProvider(page)) }
        list.append(item.canCheck ? .confirmRevoked : .markRevoked)
    default:
        break
    }
    list.append(.ignore)
    return list
}

/// Who a provider says a key belongs to. It holds only the fields the provider's file declares.
public struct KeyDetails: Codable, Hashable, Sendable {
    public let at: Double
    public let provider: String
    public let fields: [String: String]
    public let suggested_name: String?

    public init(at: Double = 0, provider: String, fields: [String: String], suggested_name: String? = nil) {
        self.at = at
        self.provider = provider
        self.fields = fields
        self.suggested_name = suggested_name
    }
}

public struct KeyEdit: Codable, Equatable, Sendable {
    public var tags: [String]?
    public var level: String?
    public var recipes: [String]?
    public var field: String?
    public var name: String?
    public var description: String?
    public var criticality: Int?
    public var host: String?

    public init(
        tags: [String]? = nil, level: String? = nil, recipes: [String]? = nil, field: String? = nil,
        name: String? = nil, description: String? = nil, criticality: Int? = nil, host: String? = nil
    ) {
        self.tags = tags
        self.level = level
        self.recipes = recipes
        self.field = field
        self.name = name
        self.description = description
        self.criticality = criticality
        self.host = host
    }
}

/// How long a fingerprint stays good for the app's own actions. Zero means asking every time.
public struct ConfirmationWindow: Sendable {
    public private(set) var confirmedAt: Date?

    public init() {}

    public mutating func confirm(at now: Date = Date()) { confirmedAt = now }
    public mutating func close() { confirmedAt = nil }

    public func isOpen(minutes: Int, at now: Date = Date()) -> Bool {
        guard minutes > 0, let confirmedAt else { return false }
        let elapsed = now.timeIntervalSince(confirmedAt)
        return elapsed >= 0 && elapsed < Double(minutes) * 60
    }
}

/// Words for each criticality, from a harmless leak to a serious one.
public func criticalityName(_ value: Int) -> String {
    switch value {
    case 1: return T("Minimal")
    case 2: return T("Low")
    case 3: return T("Medium")
    case 4: return T("High")
    case 5: return T("Critical")
    default: return T("Not rated")
    }
}

extension KeyreeveFiles {
    public func allDetails() -> [String: KeyDetails] {
        (try? JSONDecoder().decode([String: KeyDetails].self, from: Data(contentsOf: details))) ?? [:]
    }

    public func saveEdit(_ edit: KeyEdit, for path: String) throws {
        var all = (try? JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: edits))) ?? [:]
        var merged = all[path] ?? KeyEdit()
        merged.tags = edit.tags ?? merged.tags
        merged.level = edit.level ?? merged.level
        merged.recipes = edit.recipes ?? merged.recipes
        merged.field = edit.field ?? merged.field
        merged.name = edit.name ?? merged.name
        merged.description = edit.description ?? merged.description
        merged.criticality = edit.criticality ?? merged.criticality
        merged.host = edit.host ?? merged.host
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
