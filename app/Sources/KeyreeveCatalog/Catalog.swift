import Foundation

/// One row of `catalog.csv`. It has names and results, never a key's value.
public struct CatalogItem: Identifiable, Hashable, Sendable {
    /// Whether the vault holds this file, which it knows with no fingerprint.
    public enum VaultCopy: Hashable, Sendable {
        case none, sealed, outdated
        /// Sealed from a different folder, where this same path can be another key. It is left alone.
        case otherFolder
    }

    public var vault: VaultCopy = .none
    /// The file was moved out of the keys folder, so the vault's copy is the one in use.
    public var originalMoved = false
    public var path: String
    public var level: String
    public var tags: [String]
    public var format: String
    public var modified: String
    public var mode: String
    public var reviewed: Bool
    public var lastResult: String
    public var lastChecked: String
    public var recipes: [String]
    public var field: String
    public var labels: [String]
    /// When "ignore" ends. Until then the key asks for no attention.
    public var ignoredUntil: Date?
    public var name: String
    public var description: String
    public var details: KeyDetails?
    /// 1 to 5, or 0 if nobody rated it.
    public var criticality: Int
    /// True if the number came from the provider's file, and not from a person.
    public var criticalitySuggested: Bool
    /// How often the provider's file suggests changing this key, or 0.
    public var rotateDays: Int
    /// The server, for a provider each person runs themselves.
    public var host: String
    /// Why the last check gave no answer, in the tool's own words.
    public var lastReason: String
    /// The day it stops working, `yyyy-mm-dd`, as the person or an agent wrote it.
    public var expires: String
    public var id: String { path }

    /// A secret with no provider, such as a signing key, so there is nowhere to check it.
    public var isInternal: Bool { tags.contains("internal") }
    /// Kept and sealed, with nothing a provider could answer about it: a login, a database, a document, a
    /// public key. It is not offered for checks and does not count as unchecked.
    public var isUntestable: Bool { tags.contains("untestable") }

    /// True if the file has not changed for longer than its provider suggests for a key.
    public func isOlderThanSuggested(at now: Date = Date()) -> Bool {
        guard rotateDays > 0, !isArchived, isSecret, let date = catalogDate(modified) else { return false }
        return now.timeIntervalSince(date) > Double(rotateDays) * 86_400
    }

    /// What a person calls this key: their name for it, or else the file's.
    public var title: String { name.isEmpty ? path : name }
    public var isArchived: Bool { tags.contains("status:archived") }

    public init(
        path: String, level: String = "ask", tags: [String] = [], format: String = "",
        modified: String = "", mode: String = "600", reviewed: Bool = true,
        lastResult: String = "", lastChecked: String = "", recipes: [String] = [], field: String = "",
        labels: [String] = [], ignoredUntil: Date? = nil, name: String = "", description: String = "",
        details: KeyDetails? = nil, criticality: Int = 0, criticalitySuggested: Bool = false,
        rotateDays: Int = 0, host: String = "", lastReason: String = "", expires: String = ""
    ) {
        self.path = path
        self.level = level
        self.tags = tags
        self.format = format
        self.modified = modified
        self.mode = mode
        self.reviewed = reviewed
        self.lastResult = lastResult
        self.lastChecked = lastChecked
        self.recipes = recipes
        self.field = field
        self.labels = labels
        self.ignoredUntil = ignoredUntil
        self.name = name
        self.description = description
        self.details = details
        self.criticality = criticality
        self.criticalitySuggested = criticalitySuggested
        self.rotateDays = rotateDays
        self.host = host
        self.lastReason = lastReason
        self.expires = expires
    }

    /// A key at level `never` is for a person alone, and a key with no recipe must not be guessed.
    public var canCheck: Bool { (level == "free" || level == "ask") && !recipes.isEmpty && !isInternal && !isUntestable }

    /// Why a check is not offered, for the button's help text.
    public var whyNoCheck: String? {
        if level == "never" { return T("Only you use this key") }
        if level == "none" { return T("This is not a secret") }
        if isInternal { return T("An internal secret has no provider to ask") }
        if recipes.isEmpty { return T("Choose where to check it") }
        return nil
    }

    public var isDone: Bool { tags.contains("status:revoked") || tags.contains("status:retired") }

    /// Why this file deserves a look and how urgent it is, most urgent first.
    public var attentionRanked: (rank: Int, text: String)? { attentionRanked(at: Date()) }

    public func attentionRanked(at now: Date) -> (rank: Int, text: String)? {
        if let until = ignoredUntil, until > now { return nil }
        // Archiving hides a key from view, and it does not stop a key that still works.
        if isArchived { return lastResult == "works" ? (6, T("Archived, but it still works")) : nil }
        let isBackup = tags.contains("status:backup")
        let revoke = tags.contains("revoke")
        if revoke && lastResult == "works" { return (0, T("Still works: revoke it")) }
        if revoke { return (1, T("Marked to revoke")) }
        if lastResult == "works" && isBackup { return (2, T("An old copy that still works")) }
        // A key that ends breaks what uses it: said before, and loudly once it has.
        if isSecret, let days = daysLeft(at: now) {
            if days < 0 { return (1, T("Expired on %@: renew it", expiryDay ?? "")) }
            if days <= 14 { return (3, days == 0 ? T("Expires today") : days == 1 ? T("Expires tomorrow") : T("Expires in %d days", days)) }
        }
        // A value that is not secret answers to nobody, so an old refusal is no reason to look at it.
        if lastResult == "rejected" && !isBackup && !isDone && isSecret { return (3, T("The last check was rejected")) }
        if needsField { return (3, T("Choose which field holds the key")) }
        if holdsSeveralKeys { return (3, T("This file holds several keys: split it")) }
        if level != "none" && mode != "600" && !mode.isEmpty { return (4, T("Others can read this file")) }
        if !reviewed { return (5, T("Not sorted yet")) }
        return nil
    }

    public var attention: String? { attentionRanked?.text }

    public var isSecret: Bool { level != "none" }

    /// The day it stops working: what the person or an agent wrote, else what the provider said.
    public var expiryDay: String? {
        if !expires.isEmpty { return expires }
        guard let said = details?.fields["expires"], said.count >= 10 else { return nil }
        let day = String(said.prefix(10))
        return catalogDate(day) == nil ? nil : day
    }

    /// Whole days from today to the day it stops working: negative once it has.
    public func daysLeft(at now: Date = Date()) -> Int? {
        guard let day = expiryDay, let end = catalogDate(day) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.dateComponents([.day], from: calendar.startOfDay(for: now), to: end).day
    }

    /// The last check could not tell which value of the file is the key, and the file names its fields.
    public var needsField: Bool {
        field.isEmpty && labels.filter { !$0.isEmpty }.count > 1 && lastReason.contains("more than one value")
    }

    /// The last check found more than one key of the provider in the file, with no names to tell them apart.
    public var holdsSeveralKeys: Bool { field.isEmpty && lastReason.contains("several keys of this provider") }
}

public enum CatalogError: Error, Equatable {
    case missingColumn(String)
}

public enum CatalogParser {
    public static func parse(_ text: String) throws -> [CatalogItem] { try parseCounting(text).items }

    /// The rows, and how many could not be read: a row cut short is left out, and that is said, not hidden.
    public static func parseCounting(_ text: String) throws -> (items: [CatalogItem], skipped: Int) {
        let rows = table(text)
        let items = try rowsToItems(rows)
        return (items, max(0, rows.count - 1 - items.count))
    }

    private static func rowsToItems(_ rows: [[String]]) throws -> [CatalogItem] {
        guard let header = rows.first else { return [] }
        func column(_ name: String) throws -> Int {
            guard let index = header.firstIndex(of: name) else {
                throw CatalogError.missingColumn(name)
            }
            return index
        }
        let path = try column("path")
        let level = try column("level")
        let tags = try column("tags")
        let format = try column("format")
        let modified = try column("modified")
        let mode = try column("mode")
        let reviewed = try column("reviewed")
        let result = header.firstIndex(of: "last_result")
        let checked = header.firstIndex(of: "last_checked")
        let recipes = header.firstIndex(of: "recipes")
        let field = header.firstIndex(of: "field")
        let labels = header.firstIndex(of: "labels")
        let name = header.firstIndex(of: "name")
        let description = header.firstIndex(of: "description")
        let criticality = header.firstIndex(of: "criticality")
        let suggested = header.firstIndex(of: "criticality_suggested")
        let rotateDays = header.firstIndex(of: "rotate_days")
        let host = header.firstIndex(of: "host")
        let reason = header.firstIndex(of: "last_reason")
        let expires = header.firstIndex(of: "expires")
        return rows.dropFirst().compactMap { row in
            guard row.count == header.count else { return nil }
            return CatalogItem(
                path: unguard(row[path]),
                level: row[level],
                tags: row[tags].split(separator: " ").map(String.init),
                format: row[format],
                modified: row[modified],
                mode: row[mode],
                reviewed: row[reviewed] == "true",
                lastResult: result.map { row[$0] } ?? "",
                lastChecked: checked.map { row[$0] } ?? "",
                recipes: recipes.map { row[$0].split(separator: " ").map(String.init) } ?? [],
                field: field.map { row[$0] } ?? "",
                labels: labels.map { row[$0].split(separator: "|").map(String.init) } ?? [],
                name: name.map { row[$0] } ?? "",
                description: description.map { row[$0] } ?? "",
                criticality: criticality.flatMap { Int(row[$0]) } ?? 0,
                criticalitySuggested: suggested.map { row[$0] == "true" } ?? false,
                rotateDays: rotateDays.flatMap { Int(row[$0]) } ?? 0,
                host: host.map { row[$0] } ?? "",
                lastReason: reason.map { row[$0] } ?? "",
                expires: expires.map { row[$0] } ?? "")
        }
    }

    /// `keyreeve catalog` prefixes a quote to a cell that a spreadsheet would run as a formula.
    private static func unguard(_ cell: String) -> String {
        guard cell.hasPrefix("'"), let next = cell.dropFirst().first, "=+-@".contains(next) else {
            return cell
        }
        return String(cell.dropFirst())
    }

    private static func table(_ text: String) -> [[String]] {
        var rows: [[String]] = []
        var row: [String] = []
        var cell = ""
        var quoted = false
        var characters = Array(text)[...]
        while let character = characters.popFirst() {
            if quoted {
                if character == "\"" {
                    if characters.first == "\"" {
                        cell.append("\"")
                        characters.removeFirst()
                    } else {
                        quoted = false
                    }
                } else {
                    cell.append(character)
                }
            } else if character == "\"" {
                quoted = true
            } else if character == "," {
                row.append(cell)
                cell = ""
            } else if character.isNewline {
                row.append(cell)
                rows.append(row)
                row = []
                cell = ""
            } else {
                cell.append(character)
            }
        }
        if !cell.isEmpty || !row.isEmpty {
            row.append(cell)
            rows.append(row)
        }
        return rows
    }
}

public enum Sidebar: Hashable, Sendable {
    case home
    case all
    case attention
    case archive
    case checkable
    case critical
    case stale
    case internalOnly
    case expiring
    case result(String)
    case level(String)
    case tag(String)
    case vault
    case agents
    /// Tools: rotations in progress or waiting on you, and the whole usage log.
    case rotation
    case log
    /// Tools: the providers keyreeve knows, and yours to add and approve.
    case providers
}

public func filter(_ items: [CatalogItem], by selection: Sidebar, search: String) -> [CatalogItem] {
    let chosen = items.filter { item in
        switch selection {
        case .home, .all: return !item.isArchived
        case .attention: return item.attention != nil
        case .archive: return item.isArchived
        case .vault: return item.vault != .none && item.vault != .otherFolder && !item.isArchived
        case .agents, .rotation, .log, .providers: return false
        case .checkable: return item.canCheck && !item.isArchived
        case .critical: return item.criticality >= 4 && !item.isArchived
        case .stale: return item.isOlderThanSuggested()
        case .internalOnly: return item.isInternal && !item.isArchived
        case .expiring: return !item.isArchived && item.isSecret && (item.daysLeft() ?? Int.max) <= 30
        case .result(let result):
            guard !item.isArchived, item.isSecret else { return false }
            if result == "no_answer" { return item.lastResult == "no_result" || item.lastResult == "forbidden" }
            return item.lastResult == result
        case .level(let level): return item.level == level && !item.isArchived
        case .tag(let tag): return item.tags.contains(tag) && !item.isArchived
        }
    }
    let needle = search.trimmingCharacters(in: .whitespaces).lowercased()
    let found = needle.isEmpty ? chosen : chosen.filter { item in
        item.path.lowercased().contains(needle)
            || item.name.lowercased().contains(needle)
            || item.description.lowercased().contains(needle)
            || (item.details?.fields.values.contains { $0.lowercased().contains(needle) } ?? false)
            || item.tags.contains { $0.lowercased().contains(needle) }
    }
    // The most critical keys come first, and the sort keeps the rest in their order.
    return found.enumerated()
        .sorted { ($1.element.criticality, $0.offset) < ($0.element.criticality, $1.offset) }
        .map(\.element)
}

/// Project-style tags: those without a `type:` prefix, most used first.
public func projectTags(in items: [CatalogItem]) -> [(tag: String, count: Int)] {
    var counts: [String: Int] = [:]
    for item in items {
        for tag in item.tags where !tag.contains(":") && !["confirm", "revoke", "internal"].contains(tag) { counts[tag, default: 0] += 1 }
    }
    return counts.map { (tag: $0.key, count: $0.value) }
        .sorted { ($0.count, $1.tag) > ($1.count, $0.tag) }
}


/// Reads `yyyy-MM-dd` as UTC midnight. Lists call this for every key on every draw, so it does no
/// date formatting, which costs far more than this arithmetic.
private func catalogDate(_ text: String) -> Date? {
    let parts = text.split(separator: "-")
    guard parts.count == 3, let year = Int(parts[0]), let month = Int(parts[1]), let day = Int(parts[2]),
        (1...12).contains(month), (1...31).contains(day)
    else { return nil }
    // Days from the civil calendar, by Howard Hinnant's published algorithm.
    let y = month <= 2 ? year - 1 : year
    let era = (y >= 0 ? y : y - 399) / 400
    let yearOfEra = y - era * 400
    let dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
    let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
    return Date(timeIntervalSince1970: Double((era * 146_097 + dayOfEra - 719_468) * 86_400))
}

/// The figures on the home screen, worked out from the catalog alone.
public struct CatalogStats: Sendable {
    public struct Bucket: Identifiable, Sendable {
        public let label: String
        public let count: Int
        public let target: Sidebar?
        public var id: String { label }
    }

    public let total: Int
    public let secrets: Int
    public let needLook: [CatalogItem]
    public let works: Int
    public let rejected: Int
    public let noAnswer: Int
    public let neverChecked: Int
    public let canCheck: Int
    public let archived: Int
    public let critical: Int
    public let stale: Int
    public let internalSecrets: Int
    public let identified: Int
    public let projects: [Bucket]
    public let ages: [Bucket]

    public var checked: Int { works + rejected + noAnswer }

    public init(items all: [CatalogItem], now: Date = Date(), maxProjects: Int = 8) {
        let items = all.filter { !$0.isArchived }
        let secretItems = items.filter(\.isSecret)
        archived = all.count - items.count
        identified = secretItems.filter { $0.details != nil }.count
        total = items.count
        secrets = secretItems.count
        needLook = all.filter { $0.attention != nil }.sorted {
            ($0.attentionRanked?.rank ?? 9, -$0.criticality, $0.path)
                < ($1.attentionRanked?.rank ?? 9, -$1.criticality, $1.path)
        }
        critical = items.filter { $0.criticality >= 4 }.count
        stale = items.filter { $0.isOlderThanSuggested(at: now) }.count
        internalSecrets = secretItems.filter(\.isInternal).count
        works = secretItems.filter { $0.lastResult == "works" }.count
        rejected = secretItems.filter { $0.lastResult == "rejected" }.count
        noAnswer = secretItems.filter { $0.lastResult == "forbidden" || $0.lastResult == "no_result" }.count
        // Only what could be checked: a key with no way to check it is not waiting on anything.
        neverChecked = secretItems.filter { $0.canCheck && $0.lastResult.isEmpty }.count
        canCheck = items.filter(\.canCheck).count

        let tags = projectTags(in: secretItems)
        var buckets = tags.prefix(maxProjects).map {
            Bucket(label: $0.tag, count: $0.count, target: .tag($0.tag))
        }
        let rest = tags.dropFirst(maxProjects).reduce(0) { $0 + $1.count }
        if rest > 0 { buckets.append(Bucket(label: T("Other"), count: rest, target: nil)) }
        projects = buckets

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        var counts = [0, 0, 0, 0]
        for item in secretItems {
            guard let date = formatter.date(from: item.modified) else { continue }
            let days = now.timeIntervalSince(date) / 86_400
            counts[days < 30 ? 0 : days < 90 ? 1 : days < 365 ? 2 : 3] += 1
        }
        ages = zip(
            [T("Under 30 days"), T("30 to 90 days"), T("90 days to a year"), T("Over a year")], counts
        ).map {
            Bucket(label: $0, count: $1, target: nil)
        }
    }
}

/// One thing that happened to a key: a check, or a use through the vault. It holds no value.
public struct ActivityItem: Identifiable, Hashable, Sendable {
    public let at: Date
    public let key: String
    public let kind: Kind
    public var id: String { "\(at.timeIntervalSince1970)-\(key)-\(kind)" }

    public enum Kind: Hashable, Sendable {
        case checked(result: String)
        case used(by: String)
    }

    public init(at: Date, key: String, kind: Kind) {
        self.at = at
        self.key = key
        self.kind = kind
    }

    /// With several recipes for one file in one run, a pass from any of them counts.
    public static func parse(history: String, usage: String, limit: Int = 8) -> [ActivityItem] {
        struct Check: Decodable { let at: Double; let file: String; let result: String }
        struct Use: Decodable { let at: Double; let name: String; let command: String }
        let decoder = JSONDecoder()
        let checks = history.split(whereSeparator: \.isNewline).compactMap {
            try? decoder.decode(Check.self, from: Data($0.utf8))
        }
        var merged: [String: Check] = [:]
        for check in checks {
            let id = "\(check.at)-\(check.file)"
            if merged[id] == nil || check.result == "works" { merged[id] = check }
        }
        let uses = usage.split(whereSeparator: \.isNewline).compactMap {
            try? decoder.decode(Use.self, from: Data($0.utf8))
        }
        let all =
            merged.values.map {
                ActivityItem(at: Date(timeIntervalSince1970: $0.at), key: $0.file, kind: .checked(result: $0.result))
            }
            + uses.map {
                ActivityItem(at: Date(timeIntervalSince1970: $0.at), key: $0.name, kind: .used(by: $0.command))
            }
        return Array(all.sorted { ($0.at, $0.key) > ($1.at, $1.key) }.prefix(limit))
    }
}

/// Keys a person could put in the vault first: live ones they would miss least if something went
/// wrong while they learn it. A key with no rating comes after the rated ones.
public func vaultCandidates(_ items: [CatalogItem]) -> [CatalogItem] {
    let rank = { (item: CatalogItem) in item.criticality == 0 ? 6 : item.criticality }
    return items
        .filter { $0.vault == .none && !$0.originalMoved && $0.isSecret && !$0.isArchived && $0.format != "binary" }
        .sorted {
            let first = ($0.lastResult == "works" ? 0 : 1, rank($0), $0.path)
            let second = ($1.lastResult == "works" ? 0 : 1, rank($1), $1.path)
            return first < second
        }
}

/// What the lists count, worked out once when the keys change instead of on every draw: with a few
/// hundred keys, counting them for each chip and each row made a redraw take a noticeable moment.
public struct CatalogSummary: Sendable {
    /// The filters with a chip above the list.
    public static let chips: [Sidebar] = [
        .all, .checkable, .critical, .result("rejected"), .result("works"), .result("no_answer"), .result(""), .stale, .expiring, .archive,
    ]

    public let active: Int
    public let toReview: Int
    public let counts: [Sidebar: Int]
    public let stats: CatalogStats
    public let projects: [(tag: String, count: Int)]
    /// Keys whose provider said the same account of them, by path: each may be another copy of one key.
    public let sameAccount: [String: [String]]

    public init(items: [CatalogItem], now: Date = Date()) {
        let unarchived = items.filter { !$0.isArchived }
        active = unarchived.count
        toReview = items.filter { $0.attention != nil }.count
        counts = Dictionary(uniqueKeysWithValues: Self.chips.map { ($0, filter(items, by: $0, search: "").count) })
        stats = CatalogStats(items: items, now: now)
        projects = projectTags(in: unarchived)
        var groups: [String: [String]] = [:]
        for item in unarchived {
            guard let provider = item.recipes.first, let reaches = item.reaches, !reaches.isEmpty else { continue }
            groups["\(provider)\u{0}\(reaches.lowercased())", default: []].append(item.path)
        }
        var same: [String: [String]] = [:]
        for paths in groups.values where paths.count > 1 {
            for path in paths { same[path] = paths.filter { $0 != path }.sorted() }
        }
        sameAccount = same
    }

    public func count(_ target: Sidebar) -> Int { counts[target] ?? 0 }
}

extension CatalogItem {
    /// The accounts or organizations the provider said this key reaches, for telling apart several keys
    /// of one provider.
    public var reaches: String? {
        guard let fields = details?.fields else { return nil }
        return fields["organizations"] ?? fields["account"] ?? fields["email"]
    }

    /// How well this key fits the account an agent named: 2 when what the provider said of the key names
    /// it, 1 when a tag, the key's name or its path does, 0 otherwise. Whole words only, so "hub" does not
    /// fit "github".
    public func fit(account hint: String?) -> Int {
        func words(_ text: String) -> Set<String> {
            Set(text.lowercased().split { !($0.isLetter || $0.isNumber) }.map(String.init))
        }
        func joined(_ text: String) -> String { text.lowercased().filter { $0.isLetter || $0.isNumber } }
        guard let hint, !joined(hint).isEmpty else { return 0 }
        let wanted = joined(hint)
        let said = (details?.fields ?? [:]).filter { ["account", "organizations", "name", "email"].contains($0.key) }.values
            .flatMap { $0.split(separator: ",").map { joined(String($0)) } }
        if said.contains(wanted) { return 2 }
        let own = tags.map { joined(String($0.split(separator: ":").last ?? "")) } + [joined(name)]
        if own.contains(wanted) || words(path).union(words(name)).contains(wanted) || words(path).contains(hint.lowercased()) { return 1 }
        return 0
    }
}
