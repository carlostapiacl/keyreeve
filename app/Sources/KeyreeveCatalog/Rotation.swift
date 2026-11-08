import Foundation

public struct RotationPlan: Encodable, Sendable {
    public var key: String
    public var recipe: String
    public var field: String?
    public var host: String?
    public var admin: String?
    public var admin_field: String?
    public var overlap_secs: Int
    public var known_id: String?
    public var issued_name: String
    public var original: String?
    public var place_files: [String]
    public var place_actions: [String]
    public var expected_events: Int?

    public init(
        item: CatalogItem, places: KeyPlaces, admin: CatalogItem?, original: String?, now: Date = Date()
    ) {
        key = item.path
        recipe = item.recipes.first ?? ""
        field = item.field.isEmpty ? nil : item.field
        host = item.host.isEmpty ? nil : item.host
        self.admin = admin?.path
        admin_field = admin.flatMap { $0.field.isEmpty ? nil : $0.field }
        overlap_secs = places.overlapMinutes * 60
        known_id = item.details?.fields["key_id"]
        // The provider shows this name, and a file's path is private.
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.dateFormat = "yyyy-MM-dd"
        issued_name = "keyreeve-\(format.string(from: now))"
        self.original = original
        place_files = places.files
        place_actions = places.actions
    }
}

public struct RotationReport: Decodable, Equatable, Sendable {
    public let outcome: String
    public let reason: String?
    public let revoke_after: Double?
    public let manual: [String]
}

public struct RotationStatus: Decodable, Equatable, Identifiable, Sendable {
    public let key: String
    public let events: Int
    public let admin: String?
    public let phase: String
    public let at: Double
    public let revoke_after: Double?
    public let reason: String?
    public let manual: [String]
    public var id: String { key }

    /// A person still has to revoke the old key, which the app can then confirm.
    public var waitsForManualRevoke: Bool { manual.contains("revoke the old key at the provider") }

    public init(key: String, events: Int = 0, admin: String? = nil, phase: String, at: Double = 0, revoke_after: Double? = nil, reason: String? = nil, manual: [String] = []) {
        self.key = key
        self.events = events
        self.admin = admin
        self.phase = phase
        self.at = at
        self.revoke_after = revoke_after
        self.reason = reason
        self.manual = manual
    }

    public var isOpen: Bool { ["waiting", "unfinished", "rolling_back"].contains(phase) }
}

/// Where a key is used, chosen by you. The rotation updates each place before the old key goes.
public struct KeyPlaces: Codable, Equatable, Sendable {
    public var files: [String] = []
    /// `provider/action`, from a provider file you approved.
    public var actions: [String] = []
    /// You said nothing else holds this key, so it is safe with no places.
    public var nothingElse = false
    /// How long the old key keeps working after the new one is in place.
    public var overlapMinutes = 1440
    /// Another key that creates and revokes, when this one cannot.
    public var admin: String?
    /// The exact page where this key is revoked by hand, such as an integration's settings, when it is not
    /// the provider's usual page. The app opens it when the old key is left for the person to revoke.
    public var revokePage: String?

    public init() {}

    public var isDecided: Bool { nothingElse || !files.isEmpty || !actions.isEmpty }
}

extension KeyreeveFiles {
    public func allPlaces() -> [String: KeyPlaces] {
        guard let data = try? Data(contentsOf: places) else { return [:] }
        return (try? JSONDecoder().decode([String: KeyPlaces].self, from: data)) ?? [:]
    }

    public func savePlaces(_ value: KeyPlaces, for path: String) throws {
        try updateJSON(places, as: [String: KeyPlaces].self) { $0[path] = value }
    }
}
