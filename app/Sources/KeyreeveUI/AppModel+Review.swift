import Foundation
import KeyreeveCatalog
import KeyreeveVault

/// Clearing what the list asks of many keys at once, and opening many keys to agents at once.
extension AppModel {
    /// What reviewing these keys does, worked out before, so the person reads it before it happens.
    public struct ReviewPlan: Equatable {
        /// New keys an agent or a program added: marked reviewed. Offering them stays its own choice.
        public var new: [CatalogItem] = []
        /// Files others can read: closed to you alone.
        public var openFiles: [CatalogItem] = []
        /// Any other notice (a refused check, an expiry, a copy that still works): hidden for 30 days.
        public var quieted: [CatalogItem] = []
        /// A new value waiting is never accepted in bulk: each needs the person's look.
        public var left: [CatalogItem] = []
        public var isEmpty: Bool { new.isEmpty && openFiles.isEmpty && quieted.isEmpty }
    }

    public func reviewPlan(for items: [CatalogItem]) -> ReviewPlan {
        var plan = ReviewPlan()
        for item in items where item.attention != nil {
            if item.waitingFrom != nil { plan.left.append(item) }
            else if item.newFrom != nil { plan.new.append(item) }
            else if Self.othersCanRead(item) && keysFolder != nil { plan.openFiles.append(item) }
            else { plan.quieted.append(item) }
        }
        return plan
    }

    nonisolated static func othersCanRead(_ item: CatalogItem) -> Bool {
        item.level != "none" && item.mode != "600" && !item.mode.isEmpty
    }

    /// Reviews the keys as the plan says: new ones marked reviewed, open files closed, other notices quiet for 30 days.
    public func review(_ items: [CatalogItem]) {
        let plan = reviewPlan(for: items)
        guard !plan.isEmpty else { return }
        if !plan.new.isEmpty { markReviewed(plan.new, reload: false) }
        let closed = closePermissions(of: plan.openFiles)
        var quiet = 0
        let until = Date().addingTimeInterval(30 * 86_400)
        for item in plan.quieted where (try? files.ignore(item.path, until: until)) != nil { quiet += 1 }
        message = T("Reviewed: %d new, %d files closed to you alone, %d notices hidden for 30 days.", plan.new.count, closed, quiet)
            + (plan.left.isEmpty ? "" : " " + T("%d with a new value waiting are left for you to look at.", plan.left.count))
        if closed > 0 { refresh() } else { load() }
    }

    /// Makes each file readable by you alone, as a review does on its own. Returns how many were closed.
    @discardableResult
    func closePermissions(of items: [CatalogItem]) -> Int {
        guard let folder = keysFolder else { return 0 }
        var closed = 0
        for item in items where Self.othersCanRead(item) {
            if (try? files.fixPermissions(of: item.path, in: folder)) != nil { closed += 1 }
        }
        return closed
    }

    /// The keys of these files that agents can use through the proxy: sealed, with a provider.
    public func agentReachable(_ items: [CatalogItem]) -> [KeyIndex.Key] {
        items.filter { $0.vault == .sealed || $0.vault == .outdated }
            .flatMap { allKeys(forSource: $0.path) }
            .filter { $0.provider != nil && $0.provider != KeyService.sshProvider }
    }

    /// One level for many keys at once. "Always" is left out: each key needs its own fingerprint for it.
    public func setAgentLevel(_ level: AgentPolicy.Level?, forKeysOf items: [CatalogItem]) {
        let keys = agentReachable(items)
        for key in keys { setAgentLevel(level, for: key.id) }
        let skipped = items.count - Set(keys.map(\.source)).count
        message = T("%d keys set to %@.", keys.count, level?.label ?? T("Only me"))
            + (skipped > 0 ? " " + T("%d left out: only sealed keys with a provider go through the proxy.", skipped) : "")
    }

    /// Which agents may use many keys at once. Empty means any.
    public func setAgents(_ agents: [String], forKeysOf items: [CatalogItem]) {
        let keys = agentReachable(items)
        updatePolicy { policy in for key in keys { policy.agents[key.id] = agents.isEmpty ? nil : agents } }
        message = T("%d keys open to %@.", keys.count, agents.isEmpty ? T("Any agent") : agents.joined(separator: ", "))
    }
}
