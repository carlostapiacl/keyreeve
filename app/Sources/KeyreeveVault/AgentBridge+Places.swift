import Foundation

/// Agents and the places where keys live. An agent can list the places of keys offered to it, and propose new
/// ones, which wait for the person to approve with one fingerprint. It never gets a value, or a hash of one.
extension AgentBridge {
    /// The keys an agent may hear of: those offered to agents. A key not offered is a name that is not there.
    private var offeredKeys: Set<String> { Set(describe().keys) }

    func listPlaces(_ arguments: [String: Any]) throws -> String {
        let offered = offeredKeys
        let book = places()
        if let key = arguments["key"] as? String, !key.isEmpty {
            guard offered.contains(key) else { throw VaultError("no key called \(key) is offered to agents") }
            let lines = book.places(forKey: key).map(describe(place:))
            return lines.isEmpty
                ? "No place is known for \(key) yet. Propose where it lives with propose_places."
                : lines.joined(separator: "\n")
        }
        let shown = book.places.filter { offered.contains($0.key) }.sorted { ($0.key, $0.label) < ($1.key, $1.label) }
        var lines = shown.map(describe(place:))
        if lines.isEmpty { lines.append("No place is known yet for the keys offered to agents. Propose where they live with propose_places.") }
        let hidden = book.places.count - shown.count
        if hidden > 0 { lines.append("\(hidden) more \(hidden == 1 ? "place belongs" : "places belong") to keys not offered to agents.") }
        let without = offered.subtracting(Set(book.places.map(\.key))).sorted()
        if !without.isEmpty { lines.append("Offered keys with no place known: " + without.joined(separator: ", ")) }
        return lines.joined(separator: "\n")
    }

    /// One place in a line: the label, the procedure and its parameters, whether it is approved, and the last
    /// check's result and time. No value and no hash.
    private func describe(place: PlaceBook.Place) -> String {
        let status: String
        switch PlaceBook.status(of: place, currentPin: currentPin(of: place.procedure, pinned: place.sha256)) {
        case .approved: status = "approved"
        case .waiting: status = "waiting for the person to approve"
        case .changed: status = "its procedure changed, so it waits for the person to approve it again"
        case .missing: status = "its procedure is missing"
        }
        let params = place.params.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
        var line = "\(place.key): \(place.label) (\(place.procedure)\(params.isEmpty ? "" : " " + params)); \(status)"
        if let check = place.lastCheck {
            let words: String
            switch check.result {
            case .same: words = "holds the value in the vault"
            case .old: words = "holds an earlier value of this key"
            case .different: words = "holds another value"
            case .absent: words = "has no value"
            case .present: words = "has a value it does not show"
            case .notCompared: words = "not compared with the vault yet"
            case .changed: words = "not run, the procedure changed"
            case .error: words = "could not be checked"
            }
            line += "; last check \(ISO8601DateFormatter().string(from: check.at)): \(words)"
        } else {
            line += "; never checked"
        }
        return line
    }

    /// The hash of a procedure of the person's as it is now. One that ships changes only with keyreeve itself, and
    /// the app and the engine check it; here it counts as the one approved.
    private func currentPin(of procedure: String, pinned: String?) -> String? {
        if PlaceBook.builtinProcedures.contains(procedure) { return pinned ?? "" }
        guard let folder = proceduresFolder, let data = PlaceBook.folderProcedure(procedure, in: folder) else { return nil }
        return PlaceBook.sha256(data)
    }

    /// Leaves places for the person to review in one list. Nothing is added until they approve with their finger.
    func proposePlaces(_ arguments: [String: Any]) throws -> String {
        guard let reason = arguments["reason"] as? String, !reason.isEmpty else { throw VaultError("this needs reason and places") }
        let checked = try Self.checkPlaces(arguments["places"], offered: offeredKeys, by: agent)
        var notes: [String] = []
        if let folder = proceduresFolder {
            for name in Set(checked.places.map(\.procedure)).sorted() where !PlaceBook.procedureExists(name, in: folder) {
                notes.append("\(name) is not a procedure yet: write it in \(folder.path) first, or the person cannot approve its places")
            }
        }
        let known = places().places
        for place in checked.places where known.contains(where: { $0.isSame(as: place) && $0.sha256 != nil }) {
            notes.append("\(place.key) at \(place.label) is already known")
        }
        // One list at a time from each agent, so the person is not asked twice about the same places.
        let all = requests()
        if let last = all.filter({ $0.kind == "places" && $0.agent == agent }).last,
            !all.contains(where: { $0.id == last.id && $0.event != .asked })
        {
            return "Still waiting: the person has not answered your last proposal of places yet. Call list_places later to see them."
        }
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: now(), event: .asked, agent: agent, provider: "keyreeve",
            reason: reason, key: nil, kind: "places")
        try saveProposal(entry.id, checked.data)
        try addRequest(entry)
        log("requested", "\(checked.places.count) places", "places", reason)
        let told = notes.isEmpty ? "" : " Note: " + notes.prefix(20).joined(separator: "; ") + "."
        switch announce(entry) {
        case .deny:
            try addRequest(AccessRequests.Entry(id: entry.id, at: now(), event: .declined, agent: agent, provider: "keyreeve", kind: "places"))
            throw VaultError("the person said no to these places")
        case .open, .later:
            return "\(checked.places.count) places are waiting in Keyreeve for the person to review and approve with their fingerprint. Call list_places later to see them."
                + told
        }
    }

    /// An agent's places, each for a key offered to agents, with a procedure name, plain parameters and a label.
    /// Anything else is refused whole, so a proposal is never half kept.
    public static func checkPlaces(_ value: Any?, offered: Set<String>, by agent: String? = nil) throws -> (data: Data, places: [PlaceBook.Place]) {
        guard let list = value as? [[String: Any]], !list.isEmpty else {
            throw VaultError("places must be a list of objects, each with key, procedure, params and label")
        }
        guard list.count <= PlaceBook.maxPlaces else { throw VaultError("at most \(PlaceBook.maxPlaces) places at once") }
        var places: [PlaceBook.Place] = []
        for item in list {
            guard let key = item["key"] as? String, let procedure = item["procedure"] as? String,
                let label = (item["label"] as? String)?.trimmingCharacters(in: .whitespaces), !label.isEmpty
            else { throw VaultError("each place needs key, procedure and label") }
            guard offered.contains(key) else { throw VaultError("no key called \(key) is offered to agents") }
            guard PlaceBook.isValidProcedureName(procedure) else {
                throw VaultError("\(procedure) is not a procedure name: lower case letters, digits and dashes")
            }
            guard label.count <= 120, !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw VaultError("a label is one line of at most 120 characters")
            }
            var params: [String: String] = [:]
            if let given = item["params"] {
                guard let object = given as? [String: Any] else { throw VaultError("params is an object of names and text") }
                for (name, value) in object {
                    guard let text = value as? String else { throw VaultError("the parameter \(name) must be text") }
                    params[name] = text
                }
            }
            try PlaceBook.checkParams(params)
            let why = (item["why"] as? String).map { String($0.prefix(300)) }
            places.append(PlaceBook.Place(key: key, procedure: procedure, params: params, label: label, by: agent, why: why))
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return (try encoder.encode(places), places)
    }

    /// The places of a proposal, as the agent's server kept them.
    public static func proposedPlaces(_ data: Data) -> [PlaceBook.Place] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([PlaceBook.Place].self, from: data)) ?? []
    }
}
