import Foundation
import KeyreeveCatalog
import KeyreeveVault

/// Key sets: the person makes, changes and removes them here. Agents cannot: a set is the person's word.
extension AppModel {
    var setsFile: URL { files.directory.appendingPathComponent(KeySets.fileName) }

    func loadSets() -> KeySets {
        do {
            return try KeySets.loadStrict(from: setsFile)
        } catch {
            message = "\(error)"
            return KeySets()
        }
    }

    /// Saves a set with only keys offered to agents, so a set never names one that is not.
    @discardableResult
    func saveSet(_ set: KeySets.Set, replacing old: String? = nil) -> Bool {
        var clean = set
        clean.keys = set.keys.filter { keyIndex.key($0) != nil }
        clean.folder = set.folder.flatMap { $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 }
        do {
            try KeySets.update(at: setsFile) { sets in
                if let old, old != clean.name { sets.sets.removeAll { $0.name == old } }
                try sets.save(clean)
            }
            audit([(clean.name, "set: " + clean.keys.joined(separator: " "))], event: "set")
            return true
        } catch {
            message = T("The set could not be saved") + ": \(error)"
            return false
        }
    }

    func removeSet(_ name: String) {
        do {
            try KeySets.update(at: setsFile) { $0.sets.removeAll { $0.name == name } }
            audit([(name, "set removed")], event: "set")
        } catch {
            message = T("The set could not be saved") + ": \(error)"
        }
    }

    /// Ends a standing permission. A key no other one names, and not set to "always" for agents, loses its copy that
    /// asks nothing, so nothing can open it with no fingerprint any more.
    func removeStanding(_ standing: KeySets.Standing) {
        do {
            let after = try KeySets.update(at: setsFile) { $0.standing.removeAll { $0.id == standing.id } }
            let still = after.standingKeys
            for id in standing.keys where !still.contains(id) && agentPolicy.levels[id] != .always {
                if let key = keyIndex.key(id) ?? keyIndex.unoffered.first(where: { $0.id == id }) {
                    try? vaultStore.update { $0.dropUnattended(name: key.source) }
                }
                revoke(key: id)
            }
            audit([(standing.keys.joined(separator: " "), "always for \(URL(fileURLWithPath: standing.program).lastPathComponent) in \(standing.folder) removed")], event: "standing")
        } catch {
            message = T("The set could not be saved") + ": \(error)"
        }
    }

    /// What projects used in the last hour, by folder and program: a suggestion the person confirms.
    var setSuggestions: [KeySets.Suggestion] {
        KeySets.suggestions(from: usage.entries, offered: Set(keyIndex.keys.map(\.id)))
    }
}
