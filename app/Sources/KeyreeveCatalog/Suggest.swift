import Foundation

/// What keyreeve can propose for a key it cannot check yet, from what it already knows about the file:
/// its tags, the names of the fields inside it, and the providers it knows. It never reads a value.
public struct Suggestion: Identifiable, Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        /// This provider's recipe, and the field inside the file when it holds several.
        case provider(String, field: String?)
        /// Kept and sealed; nothing to check.
        case untestable
        case internalSecret
        /// Not a secret at all, such as an account id or a public key.
        case notSecret
        /// Only what it is, in a few words.
        case described
    }

    public var id: String { path }
    public let path: String
    public var kind: Kind
    /// Why, in a few words, such as the tag it came from.
    public let why: String
    /// What the key is, in a few words, such as "Cloudflare account ID". Kept as its description when it has none.
    public var what: String?

    public init(path: String, kind: Kind, why: String, what: String? = nil) {
        self.path = path
        self.kind = kind
        self.why = why
        self.what = what
    }

    /// The change it makes, keeping the file's other tags.
    public func edit(for item: CatalogItem) -> KeyEdit {
        var edit: KeyEdit
        switch kind {
        case .provider(let id, let field):
            // No field named keeps the one the key has: a proposal that only names a provider must not
            // take away the field the person chose.
            edit = KeyEdit(tags: item.tags.filter { $0 != "untestable" }, recipes: [id], field: field)
        case .untestable:
            edit = KeyEdit(tags: item.tags.filter { $0 != "untestable" } + ["untestable"], recipes: [])
        case .internalSecret:
            edit = KeyEdit(tags: item.tags.filter { $0 != "internal" } + ["internal"], recipes: [])
        case .notSecret:
            edit = KeyEdit(level: "none", recipes: [])
        case .described:
            edit = KeyEdit()
        }
        // What the person wrote is kept; a description only fills an empty one.
        if item.description.isEmpty, let what { edit.description = what }
        return edit
    }
}

public enum Suggester {
    /// Kinds of secret no provider can answer for. Both the words a person's rules use and plain English.
    public static let untestableTypes: Set<String> = [
        "login", "password", "base-de-datos", "database", "documento", "document", "llave-publica", "public-key",
        "firma", "signature", "dsn", "webhook",
    ]
    public static let internalTypes: Set<String> = ["secreto-interno", "internal-secret"]

    /// Keys with no recipe, not archived, and not already sorted, each with what keyreeve can say about it.
    public static func suggest(_ items: [CatalogItem], providers: ProviderDirectory) -> [Suggestion] {
        let known = Dictionary(providers.all.filter { $0.problem == nil }.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return items.compactMap { item in
            guard item.recipes.isEmpty, !item.isArchived, !item.isInternal, !item.isUntestable, item.isSecret else { return nil }
            let tags = Dictionary(item.tags.compactMap { tag -> (String, String)? in
                let parts = tag.split(separator: ":", maxSplits: 1).map(String.init)
                return parts.count == 2 ? (parts[0], parts[1]) : nil
            }, uniquingKeysWith: { a, _ in a })
            if let type = tags["type"], internalTypes.contains(type) {
                return Suggestion(path: item.path, kind: .internalSecret, why: "type:\(type)")
            }
            if let id = tags["provider"], let provider = known[id] {
                return Suggestion(path: item.path, kind: .provider(id, field: field(in: item, for: provider)), why: "provider:\(id)")
            }
            if let type = tags["type"], untestableTypes.contains(type) {
                return Suggestion(path: item.path, kind: .untestable, why: "type:\(type)")
            }
            return nil
        }
    }

    /// Whether a file with these fields holds `field`: one name, or several joined with `+` for a key in
    /// parts, each of them in the file.
    public static func holds(_ labels: [String], field: String) -> Bool {
        let parts = field.split(separator: "+", omittingEmptySubsequences: false).map(String.init)
        return !parts.isEmpty && parts.allSatisfy { !$0.isEmpty && labels.contains($0) }
    }

    /// The field that holds this provider's key, when the file has several and one name says so: its usual
    /// variable, or one that names the provider. Nil when it has one value, or when it cannot tell.
    public static func field(in item: CatalogItem, for provider: ProviderInfo) -> String? {
        let fields = item.labels.filter { !$0.isEmpty }
        guard fields.count > 1 else { return nil }
        if let variable = provider.env_var, let exact = fields.first(where: { $0.uppercased() == variable.uppercased() }) { return exact }
        let name = provider.id.uppercased().replacingOccurrences(of: "-", with: "_")
        let matching = fields.filter { $0.uppercased().contains(name) }
        return matching.count == 1 ? matching[0] : nil
    }
}

extension Suggester {
    /// What is sent to an assistant for each key: where it is, its tags and the names of its fields. Never
    /// a value, and never the file.
    public static func describe(_ items: [CatalogItem]) -> String {
        let rows = items.map { item -> [String: Any] in
            ["path": item.path, "tags": item.tags, "fields": item.labels.filter { !$0.isEmpty }]
        }
        let data = (try? JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys])) ?? Data("[]".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    public static func prompt(for items: [CatalogItem], providers: ProviderDirectory) -> String {
        let ids = providers.all.filter { $0.problem == nil }.map(\.id).sorted().joined(separator: ", ")
        let language = Language.current.resolved == .spanish ? "Spanish" : "English"
        return """
            You sort API keys for keyreeve. For each key below you get its file path, its tags and the names of the fields
            inside the file. You never see a value. Answer with one JSON array and nothing else, one object per key:
            {"path": "<as given>", "kind": "provider" | "untestable" | "internal" | "public" | "unknown", "provider": "<id>", "field": "<name>", "what": "<a few words>"}

            - what: in \(language), at most eight words saying what the file holds, such as "Cloudflare account ID" or
              "Login for the Instagram account". Give it for every key you can tell anything about.
            - public: not a secret at all, such as an account or project id, a public key or a site key meant for browsers.

            - provider: the key belongs to one of these providers, by id: \(ids). Give "field" only when the file has
              several fields and one of the given names holds that provider's key.
            - untestable: a login, password, database URL, document, public key, signature or webhook, which no provider
              can be asked about.
            - internal: a secret of the person's own software, with no outside provider.
            - unknown: when you cannot tell. Prefer unknown to a guess.

            The keys, as data:
            \(describe(items))
            """
    }

    /// The assistant's answer, kept only where it names a provider keyreeve knows and a field the file has.
    public static func read(_ answer: String, items: [CatalogItem], providers: ProviderDirectory) -> [Suggestion] {
        let text = RecipeSpec.extractYAML(answer)
        guard let start = text.firstIndex(of: "["), let end = text.lastIndex(of: "]"),
            let rows = try? JSONSerialization.jsonObject(with: Data(text[start...end].utf8)) as? [[String: Any]]
        else { return [] }
        let byPath = Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        let known = Set(providers.all.filter { $0.problem == nil }.map(\.id))
        return rows.compactMap { row in
            guard let path = row["path"] as? String, let item = byPath[path], let kind = row["kind"] as? String else { return nil }
            // Words of the assistant's, kept short and on one line.
            let what = (row["what"] as? String).map { $0.split(whereSeparator: \.isNewline).joined(separator: " ") }
                .map { String($0.trimmingCharacters(in: .whitespaces).prefix(80)) }.flatMap { $0.isEmpty ? nil : $0 }
            switch kind {
            case "provider":
                guard let id = row["provider"] as? String, known.contains(id) else { return nil }
                let field = (row["field"] as? String).flatMap { Suggester.holds(item.labels, field: $0) ? $0 : nil }
                return Suggestion(path: path, kind: .provider(id, field: field), why: "assistant", what: what)
            case "untestable": return Suggestion(path: path, kind: .untestable, why: "assistant", what: what)
            case "internal": return Suggestion(path: path, kind: .internalSecret, why: "assistant", what: what)
            case "public": return Suggestion(path: path, kind: .notSecret, why: "assistant", what: what)
            default: return what.map { Suggestion(path: path, kind: .described, why: "assistant", what: $0) }
            }
        }
    }
}
