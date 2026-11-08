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

/// A button of your own, declared in a provider file of yours.
public struct CustomAction: Codable, Hashable, Identifiable, Sendable {
    public struct Run: Codable, Hashable, Sendable {
        public let program: String
    }

    public let id: String
    public let label: String
    public let label_es: String?
    public let open: String?
    public let run: Run?
    public let needs_key: Bool

    public init(
        id: String, label: String, label_es: String? = nil, open: String? = nil, run: Run? = nil,
        needs_key: Bool = false
    ) {
        self.id = id
        self.label = label
        self.label_es = label_es
        self.open = open
        self.run = run
        self.needs_key = needs_key
    }

    /// The label in the chosen language, as the file wrote it.
    public var title: String {
        Language.current.resolved == .spanish ? (label_es ?? label) : label
    }
}

/// What keyreeve knows about providers, read from their files through the command. Nothing about
/// any provider is written in this app, so a new file needs no new app.
/// When a provider's file was last tried against the real service.
public struct Tested: Codable, Hashable, Sendable {
    public let check: String?
    public let rotate: String?
    public init(check: String? = nil, rotate: String? = nil) {
        self.check = check
        self.rotate = rotate
    }
}

public struct ProviderInfo: Codable, Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let dashboard: String?
    public let hosts: [String]
    public let source: String
    public let approved: Bool
    public let can_check: Bool
    public let can_identify: Bool
    public let can_rotate: Bool
    public let can_rotate_by_hand: Bool
    public let single_rotation: Bool
    public let tested: Tested
    public let env_var: String?
    public let self_hosted: Bool
    public let problem: String?
    public let programs: [String]?
    public let actions: [CustomAction]?
    /// How this provider's keys start, from its recipe.
    public let prefixes: [String]?

    public init(
        id: String, name: String, dashboard: String? = nil, hosts: [String] = [], source: String = "builtin",
        approved: Bool = true, can_check: Bool = true, can_identify: Bool = false, can_rotate: Bool = false,
        can_rotate_by_hand: Bool = false, single_rotation: Bool = false, tested: Tested = Tested(), env_var: String? = nil,
        self_hosted: Bool = false,
        problem: String? = nil, programs: [String]? = nil, actions: [CustomAction]? = nil, prefixes: [String]? = nil
    ) {
        self.id = id
        self.name = name
        self.dashboard = dashboard
        self.hosts = hosts
        self.source = source
        self.approved = approved
        self.can_check = can_check
        self.can_identify = can_identify
        self.can_rotate = can_rotate
        self.can_rotate_by_hand = can_rotate_by_hand
        self.single_rotation = single_rotation
        self.tested = tested
        self.env_var = env_var
        self.self_hosted = self_hosted
        self.problem = problem
        self.programs = programs
        self.actions = actions
        self.prefixes = prefixes
    }

    public var needsApproval: Bool { source == "local" && !approved && problem == nil }
}

public struct ProviderDirectory: Sendable {
    public let all: [ProviderInfo]
    public init(_ all: [ProviderInfo] = []) { self.all = all }

    /// The provider a pasted key belongs to, by the longest prefix any recipe declares, so `sk_live_`
    /// is Stripe even though `sk_` is ElevenLabs. Nil when no prefix matches.
    public func recognize(_ value: String) -> ProviderInfo? {
        all.flatMap { info in (info.prefixes ?? []).filter { value.hasPrefix($0) }.map { (info, $0.count) } }
            .max { $0.1 < $1.1 }?.0
    }

    /// Shown in place of a key: its known start and its length, and nothing that would let it be used.
    public static func hint(of value: String, provider: ProviderInfo?) -> String {
        let prefix = (provider?.prefixes ?? []).filter { value.hasPrefix($0) }.max { $0.count < $1.count } ?? ""
        return "\(prefix)… (\(value.count))"
    }

    public static func parse(_ data: Data) -> ProviderDirectory {
        ProviderDirectory((try? JSONDecoder().decode([ProviderInfo].self, from: data)) ?? [])
    }

    /// Those a key may be sent to from the app.
    public var usable: [ProviderInfo] { all.filter { $0.approved && $0.problem == nil } }

    public func name(of id: String) -> String { all.first { $0.id == id }?.name ?? id }

    private func names(for item: CatalogItem) -> [String] {
        item.recipes + item.tags.filter { $0.hasPrefix("provider:") }.map { String($0.dropFirst(9)) }
    }

    /// The provider that can rotate this key, when the key names exactly one.
    public func rotator(of item: CatalogItem) -> ProviderInfo? {
        guard item.recipes.count == 1 else { return nil }
        return usable.first { $0.id == item.recipes[0] && ($0.can_rotate || $0.can_rotate_by_hand) }
    }

    public func page(for item: CatalogItem) -> URL? {
        names(for: item).lazy
            .compactMap { id in self.all.first { $0.id == id }?.dashboard }
            .first.flatMap(URL.init(string:))
    }

    /// Buttons of your own for this key, from an approved file of yours.
    public func customActions(for item: CatalogItem) -> [(provider: String, action: CustomAction)] {
        item.recipes.flatMap { id -> [(provider: String, action: CustomAction)] in
            guard let info = usable.first(where: { $0.id == id }) else { return [] }
            return (info.actions ?? []).map { (provider: id, action: $0) }
        }
    }

    /// A provider each person runs needs the address of your server before it can be asked.
    public func needsHost(_ item: CatalogItem) -> Bool {
        item.host.isEmpty && item.recipes.contains { id in all.contains { $0.id == id && $0.self_hosted } }
    }

    public func canCheck(_ item: CatalogItem) -> Bool { item.canCheck && !needsHost(item) }

    /// The provider a key with none probably belongs to: what its prefix proved first, then what your
    /// tags say, if they name just one. It is only an offer, since a wrong one would send the key to
    /// the wrong company, and a person presses the button.
    public func likelyProvider(of item: CatalogItem) -> ProviderInfo? {
        guard item.recipes.isEmpty, item.whyNoCheck == T("Choose where to check it") else { return nil }
        let names = { (prefix: String) in item.tags.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) } }
        for list in [names("kind:"), names("provider:")] where list.count == 1 {
            if let found = usable.first(where: { $0.id == list[0] && $0.can_check }) { return found }
        }
        return nil
    }

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

/// What a batch of checks found.
public struct RunSummary: Equatable, Sendable {
    public let checked: Int
    public let works: Int
    public let rejected: Int
    public let noAnswer: Int

    public init(items: [CatalogItem], checked paths: Set<String>) {
        let done = items.filter { paths.contains($0.path) }
        checked = paths.count
        works = done.filter { $0.lastResult == "works" }.count
        rejected = done.filter { $0.lastResult == "rejected" }.count
        noAnswer = done.filter { $0.lastResult == "no_result" || $0.lastResult == "forbidden" }.count
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

    /// Changes one of keyreeve's own JSON files under a lock, so two windows or processes never undo each
    /// other. Only a file that is not there counts as empty: one that is there and does not read is left
    /// as it is and the change is refused, since writing over it would lose everything else it holds.
    public func updateJSON<Value: Codable>(
        _ url: URL, as type: [String: Value].Type, decoder: JSONDecoder = JSONDecoder(), encoder: JSONEncoder = JSONEncoder(),
        _ change: (inout [String: Value]) -> Void
    ) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let lock = open(url.path + ".lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lock >= 0 else { throw CheckError(T("%@ could not be saved", url.lastPathComponent)) }
        defer { close(lock) }
        guard flock(lock, LOCK_EX) == 0 else { throw CheckError(T("%@ could not be saved", url.lastPathComponent)) }
        defer { flock(lock, LOCK_UN) }
        var all: [String: Value] = [:]
        if FileManager.default.fileExists(atPath: url.path) {
            guard let data = try? Data(contentsOf: url), let read = try? decoder.decode(type, from: data) else {
                throw CheckError(T("%@ is damaged, so nothing was changed. Keyreeve left it as it is.", url.lastPathComponent))
            }
            all = read
        }
        change(&all)
        encoder.outputFormatting.formUnion([.sortedKeys, .prettyPrinted])
        try writePrivate(try encoder.encode(all), to: url)
    }

    public func saveEdit(_ edit: KeyEdit, for path: String) throws {
        try updateJSON(edits, as: [String: KeyEdit].self) { all in
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
        }
    }

    public func ignoredKeys() -> [String: Date] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([String: Date].self, from: Data(contentsOf: ignored))) ?? [:]
    }

    public func ignore(_ path: String, until: Date) throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try updateJSON(ignored, as: [String: Date].self, decoder: decoder, encoder: encoder) { $0[path] = until }
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
