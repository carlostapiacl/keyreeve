import Foundation
import KeyreeveCatalog
import KeyreeveVault

extension AppModel {
    /// The changes an agent proposed to tidy keys, as it left them.
    public func tidyChanges(for request: AccessRequests.Entry) -> [KeyTidy.Change] {
        guard let data = AgentSorting.load(id: request.id, home: files.directory) else { return [] }
        return (try? JSONDecoder().decode([KeyTidy.Change].self, from: data)) ?? []
    }

    /// Projects the keys already name, to mark a proposed one that is new.
    public var knownProjects: Set<String> { KeyTidy.knownProjects(keyIndex) }

    /// The key as it is now, to show each change beside what it replaces.
    public func tidyKey(_ id: String) -> KeyIndex.Key? {
        let current = keyIndex.current(id)
        return (keyIndex.keys + keyIndex.unoffered).first { $0.id == current }
    }

    /// Applies the chosen changes: names, descriptions, projects and archiving. Only words about keys change, never a
    /// value, so it takes a click and no fingerprint. keys.toml and agents.toml are copied beside them first.
    public func applyTidy(_ changes: [KeyTidy.Change], for request: AccessRequests.Entry) {
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "")
        let done: [String]
        do {
            done = try KeyTidy.apply(changes, home: files.directory, stamp: stamp)
        } catch {
            message = T("The changes could not be applied: %@", "\(error)")
            return
        }
        audit([("\(done.count) keys", "tidy \(request.id) from \(request.agent)")], event: "allowed")
        try? AccessRequests.append(
            AccessRequests.Entry(
                id: request.id, at: Date(), event: .allowed, agent: request.agent, provider: request.provider,
                kind: KeyTidy.requestKind, result: "applied \(done.count): " + done.prefix(20).joined(separator: " | ")),
            to: requestsFile)
        message = T("%d keys tidied. A copy of the list from before is beside it.", done.count)
        reloadRequests()
        load()
    }
}
