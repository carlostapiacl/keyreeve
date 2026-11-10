import Foundation

/// Agents finding keys on this Mac and proposing which to bring in. Finding only reads, and proposing only
/// writes a request: the person checks and seals in the app, with their fingerprint.
extension AgentBridge {
    /// The providers a proposal may name: those the app lets the person save a key for, and those the search named.
    func knownProviders(_ scan: AgentBringing.Scan) -> Set<String> {
        Set(offered()).union(scan.found.flatMap { [$0.provider].compactMap { $0 } + $0.guessed })
    }

    func findKeys(_ arguments: [String: Any]) throws -> String {
        let scope = try AgentBringing.Scope.read(arguments)
        let offset = arguments["offset"] as? Int ?? 0
        let limit = arguments["limit"] as? Int ?? AgentBringing.defaultLimit
        let scan: AgentBringing.Scan
        // A later page of the same search reads the one kept, so its numbers stay the same.
        if offset > 0, let kept = held.scan, kept.scope == scope {
            scan = kept
        } else {
            scan = try AgentBringing.read(try scanKeys(scope.arguments), scope: scope)
            held.scan = scan
            let place = scope.folder.map { "folder \($0)" } ?? "places" + (scope.projects.isEmpty ? "" : " and \(scope.projects.count) project folders")
            let secrets = scan.found.filter(\.isSecret).count
            log("scanned", "\(secrets) keys", "\(place): \(scan.files) files, \(scan.found.count - secrets) other pieces", nil)
        }
        return AgentBringing.report(
            scan, sealed: sealedSources(), known: Array(knownProviders(scan)), offset: offset, limit: limit)
    }

    func proposeBring(_ arguments: [String: Any]) throws -> String {
        guard let reason = arguments["reason"] as? String, !reason.isEmpty else { throw VaultError("this needs reason, and seal or skip") }
        guard let scan = held.scan else { throw VaultError("call find_keys first: a proposal names candidates from it") }
        let checked = try AgentBringing.check(
            seal: arguments["seal"], skip: arguments["skip"], scan: scan, known: knownProviders(scan), sealed: sealedSources())
        // One proposal at a time from each agent, so the person is not asked twice about the same keys.
        let all = requests()
        let mine = all.filter { $0.kind == AgentBringing.kind && $0.agent == agent && $0.event == .asked }
        var before = ""
        if let last = mine.last {
            guard let answer = all.last(where: { $0.id == last.id && $0.event != .asked }) else {
                return "Still waiting: the person has not reviewed your last proposal yet. Nothing was sealed. Ask them to open Keyreeve, under Agents."
            }
            before = answer.event == .declined
                ? "The person declined your last proposal. "
                : "Your last proposal: \(answer.result ?? "reviewed"). "
        }
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: now(), event: .asked, agent: agent, provider: "keyreeve", reason: reason,
            kind: AgentBringing.kind)
        try saveProposal(entry.id, try AgentBringing.encode(checked.proposal))
        try addRequest(entry)
        let sealing = checked.proposal.sealCount
        let skipping = checked.proposal.items.count - sealing
        log("requested", "\(sealing) keys", "bring in, \(skipping) skipped", reason)
        let told = checked.notes.isEmpty ? "" : " Notes: " + checked.notes.prefix(40).joined(separator: "; ") + "."
        switch announce(entry) {
        case .deny:
            try addRequest(AccessRequests.Entry(
                id: entry.id, at: now(), event: .declined, agent: agent, provider: "keyreeve", kind: AgentBringing.kind))
            throw VaultError("the person said no to bringing in these keys")
        case .open, .later:
            return before
                + "Pending in Keyreeve: \(sealing) keys to seal and \(skipping) to skip, as your suggestions. Nothing is sealed until the person reviews them under Agents, changes what they want and gives their fingerprint; Keyreeve checks each key with its own provider then. The person decides. Sealed keys get identifiers but are not offered to agents, so list_keys will not show them until the person offers them."
                + told
        }
    }
}
