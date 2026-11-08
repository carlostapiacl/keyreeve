import Foundation

/// Agents asking for a key: one that is closed to them, or one for a provider not saved yet.
extension AgentBridge {
    /// A permission never outlasts the time the key was opened for.
    func bounded(_ seconds: Int, key: String, policy: AgentPolicy) -> Int {
        guard let closes = policy.until[key] else { return seconds }
        return max(1, min(seconds, Int(closes.timeIntervalSince(now()))))
    }

    /// Asks the person to open a closed key to this agent. What they choose is saved, so the next
    /// use_key follows it with no new question here.
    func requestAccess(_ arguments: [String: Any]) throws -> String {
        guard let key = arguments["key"] as? String,
            let reason = arguments["reason"] as? String, !reason.isEmpty
        else { throw VaultError("this needs key and reason") }
        guard let hours = AccessDecision.hours(from: arguments["duration"] as? String ?? "1h") else {
            throw VaultError("duration is 1h, 4h, 8h, 24h or always")
        }
        // Checked first, so nothing is asked for a key that is not there or already open.
        guard try names().contains(key) else {
            guard offered().contains(key) else { throw VaultError("no key called \(key) is in the vault, and none can be saved for that provider") }
            return try requestUnsaved(provider: key, reason: reason, hours: hours, account: arguments["account"] as? String)
        }
        let date = now()
        let current = policy
        if let level = current.level(of: key, at: date), current.admits(agent: agent, for: key) {
            return "\(key) is already open to \(agent)"
                + (level == .free ? ". Use use_key." : ". Use use_key; the person is asked there, and can say yes for some hours.")
        }
        // Open to other agents on terms the person chose for them. A yes here would change those terms
        // for everyone, so the person adds this agent in the app instead.
        if current.level(of: key, at: date) != nil {
            log("refused", key, "open to other agents", reason)
            throw VaultError("\(key) is open to other agents. Ask the person to add \(agent) in Keyreeve, under Agents")
        }
        guard !held.refused.contains(key) else {
            log("refused", key, "asked again after a no", reason)
            throw VaultError("the person already said no to \(key) in this session. Ask them in the conversation instead")
        }
        let request = AccessRequest(
            key: key, provider: describe()[key]?.provider, agent: agent, reason: reason, hours: hours)
        let started = Date()
        func kept(_ output: String) {
            transcript(AgentTranscript.Entry(
                at: started, agent: agent, key: key, command: "request_access \(key)", reason: reason, exit: 0,
                output: output, milliseconds: Int(Date().timeIntervalSince(started) * 1000)))
        }
        guard let decision = decideAccess(request) else {
            held.refused.insert(key)
            log("denied", key, "access request", reason)
            kept("the person said no")
            throw VaultError("the person said no to opening \(key)")
        }
        // Changed as the file is now, so what the app changed while the window was open is kept.
        let closes = decision.hours.map { now().addingTimeInterval(TimeInterval($0 * 3600)) }
        let requester = agent
        let asked = now()
        final class Outcome: @unchecked Sendable { var stale = false }
        let outcome = Outcome()
        try updatePolicy { policy in
            // The yes was for the key as it was when the window opened. If the person changed it meanwhile,
            // that change stands and this yes is dropped.
            guard policy.level(of: key, at: asked) == nil else {
                outcome.stale = true
                return
            }
            policy.levels[key] = .free
            // A key opened at an agent's request is open to that agent alone.
            policy.agents[key] = [requester]
            policy.until[key] = closes
        }
        guard !outcome.stale else {
            log("refused", key, "changed while the window was open", reason)
            kept("not opened: the key changed while the person was asked")
            throw VaultError("\(key) changed while the person was asked, so nothing was opened. Call list_keys to see it now")
        }
        let how = closes.map { "free until \(ISO8601DateFormatter().string(from: $0))" } ?? "free, always"
        log("opened", key, "\(how), for \(agent)", reason)
        kept("opened: \(how)")
        return "The person opened \(key) to \(agent): \(how). Use use_key; it asks nothing more than one fingerprint."
    }

    /// A key for a provider that is not saved yet. The person saves and allows it in the app, so this
    /// only writes the request down and tells them; the agent asks again, or lists, to learn the answer.
    func requestUnsaved(provider: String, reason: String, hours: Int?, account: String? = nil) throws -> String {
        if let last = AccessRequests.latest(agent: agent, provider: provider, in: requests()) {
            switch last.answer?.event {
            case .allowed?:
                if let key = last.answer?.key, policy.level(of: key, at: now()) != nil, policy.admits(agent: agent, for: key) {
                    return "The person saved a \(provider) key as \(key) and opened it to \(agent). Use use_key with key \(key)."
                }
            case .declined? where now().timeIntervalSince(last.answer?.at ?? .distantPast) < 3600:
                throw VaultError("the person said no to a \(provider) key within the hour. Ask them in the conversation instead")
            case nil:
                return "Still waiting: the person saves the \(provider) key in Keyreeve. Ask them in the conversation, then call request_access again."
            default:
                break
            }
        }
        guard !held.refused.contains(provider) else {
            throw VaultError("the person already said no to a \(provider) key in this session. Ask them in the conversation instead")
        }
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: now(), event: .asked, agent: agent, provider: provider, reason: reason, hours: hours,
            account: account)
        try addRequest(entry)
        log("requested", provider, "not saved yet", reason)
        switch announce(entry) {
        case .deny:
            held.refused.insert(provider)
            try addRequest(AccessRequests.Entry(id: entry.id, at: now(), event: .declined, agent: agent, provider: provider))
            log("denied", provider, "access request", reason)
            throw VaultError("the person said no to a \(provider) key")
        case .open, .later:
            return "Waiting: no \(provider) key is saved yet, and the request is in Keyreeve for the person to save one and allow it. Ask them in the conversation, then call request_access again."
        }
    }

    /// Asks the person to rotate a key. The app rotates it, with their fingerprint, where they said the key
    /// is used; this only writes the request down, and tells the agent how it went when it asks again.
    func rotateKey(_ arguments: [String: Any]) throws -> String {
        guard let key = arguments["key"] as? String,
            let reason = arguments["reason"] as? String, !reason.isEmpty
        else { throw VaultError("this needs key and reason") }
        guard try names().contains(key) else { throw VaultError("no key called \(key) is in the vault") }
        // A try that did not finish is said once, with a new request in its place, so the person can try
        // again at once instead of waiting out the hour.
        var lastTry: String?
        if let last = AccessRequests.latestRotation(agent: agent, key: key, in: requests()) {
            let since = now().timeIntervalSince(last.answer?.at ?? .distantPast)
            let result = last.answer?.result ?? "no words were kept"
            switch last.answer?.event {
            case nil:
                return "Still waiting: the person decides in Keyreeve, under Agents. Call rotate_key again later to learn how it went."
            case .declined? where since < 3600:
                throw VaultError("the person said no to rotating \(key) within the hour. Ask them in the conversation instead")
            case .allowed? where since < 3600 && Self.rotationDone(result):
                return "The person rotated \(key). How it went: \(result)"
            case .allowed? where since < 3600:
                lastTry = result
            default:
                break
            }
        }
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: now(), event: .asked, agent: agent, provider: describe()[key]?.provider ?? key,
            reason: reason, key: key, kind: "rotate")
        try addRequest(entry)
        log("requested", key, "rotation", reason)
        switch announce(entry) {
        case .deny:
            try addRequest(AccessRequests.Entry(
                id: entry.id, at: now(), event: .declined, agent: agent, provider: entry.provider, key: key, kind: "rotate"))
            log("denied", key, "rotation", reason)
            throw VaultError("the person said no to rotating \(key)")
        case .open, .later:
            let waiting = "The request to rotate \(key) is in Keyreeve, where the person decides with their fingerprint. Call rotate_key again later to learn how it went."
            return lastTry.map { "The last try did not finish: \($0). A new request is waiting. " + waiting } ?? "Waiting: " + waiting
        }
    }

    /// A rotation that ended with the new key in place, whatever is left for the person to do by hand.
    static func rotationDone(_ result: String) -> Bool { result.hasPrefix("completed") || result.hasPrefix("waiting") }

    static let sortingOff =
        "the person has not let agents sort keys. They turn it on in Keyreeve, under Agents: Agents can sort my keys"

    /// Leaves many changes for the person to review in one list. Nothing changes until they apply them.
    func propose(_ arguments: [String: Any]) throws -> String {
        guard let reason = arguments["reason"] as? String, !reason.isEmpty else { throw VaultError("this needs reason and changes") }
        guard let list = inventory() else { throw VaultError(Self.sortingOff) }
        let checked = try AgentSorting.check(arguments["changes"], paths: AgentSorting.paths(inInventory: list))
        // One list at a time from each agent, so the person is not asked twice about the same files.
        let waiting = requests().filter { $0.kind == "sort" && $0.agent == agent }
        if let last = waiting.last, !requests().contains(where: { $0.id == last.id && $0.event != .asked }) {
            return "Still waiting: the person has not answered your last proposal yet. Call inventory later to see what changed."
        }
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: now(), event: .asked, agent: agent, provider: "keyreeve",
            reason: reason, key: nil, kind: "sort")
        try saveProposal(entry.id, checked.data)
        try addRequest(entry)
        log("requested", "\(checked.count) keys", "sorting", reason)
        switch announce(entry) {
        case .deny:
            try addRequest(AccessRequests.Entry(id: entry.id, at: now(), event: .declined, agent: agent, provider: "keyreeve", kind: "sort"))
            throw VaultError("the person said no to these changes")
        case .open, .later:
            return "\(checked.count) changes are waiting in Keyreeve for the person to review. Call inventory later to see what changed."
        }
    }
}

