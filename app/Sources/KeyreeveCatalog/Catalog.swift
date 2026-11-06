import Foundation

/// One row of `catalog.csv`. It has names and results, never a key's value.
public struct CatalogItem: Identifiable, Hashable, Sendable {
    public var path: String
    public var level: String
    public var tags: [String]
    public var format: String
    public var modified: String
    public var mode: String
    public var reviewed: Bool
    public var lastResult: String
    public var lastChecked: String
    public var id: String { path }

    public init(
        path: String, level: String = "ask", tags: [String] = [], format: String = "",
        modified: String = "", mode: String = "600", reviewed: Bool = true,
        lastResult: String = "", lastChecked: String = ""
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
    }

    /// Why this file deserves a look, or nil. These are the same for anyone's keys.
    public var attention: String? {
        let isBackup = tags.contains("status:backup")
        if lastResult == "works" && isBackup { return "An old copy that still works" }
        if tags.contains("revoke") { return "Marked to revoke" }
        if lastResult == "rejected" && !isBackup { return "The last check was rejected" }
        if level != "none" && mode != "600" && !mode.isEmpty { return "Others can read this file" }
        if !reviewed { return "Not covered by your rules" }
        return nil
    }

    public var isSecret: Bool { level != "none" }
}

public enum CatalogError: Error, Equatable {
    case missingColumn(String)
}

public enum CatalogParser {
    public static func parse(_ text: String) throws -> [CatalogItem] {
        let rows = table(text)
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
                lastChecked: checked.map { row[$0] } ?? "")
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
    case all
    case attention
    case level(String)
    case tag(String)
}

public func filter(_ items: [CatalogItem], by selection: Sidebar, search: String) -> [CatalogItem] {
    let chosen = items.filter { item in
        switch selection {
        case .all: return true
        case .attention: return item.attention != nil
        case .level(let level): return item.level == level
        case .tag(let tag): return item.tags.contains(tag)
        }
    }
    let needle = search.trimmingCharacters(in: .whitespaces).lowercased()
    guard !needle.isEmpty else { return chosen }
    return chosen.filter { item in
        item.path.lowercased().contains(needle)
            || item.tags.contains { $0.lowercased().contains(needle) }
    }
}

/// Project-style tags: those without a `type:` prefix, most used first.
public func projectTags(in items: [CatalogItem]) -> [(tag: String, count: Int)] {
    var counts: [String: Int] = [:]
    for item in items {
        for tag in item.tags where !tag.contains(":") && tag != "confirm" { counts[tag, default: 0] += 1 }
    }
    return counts.map { (tag: $0.key, count: $0.value) }
        .sorted { ($0.count, $1.tag) > ($1.count, $0.tag) }
}
