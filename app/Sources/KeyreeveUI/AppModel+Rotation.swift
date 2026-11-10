import AppKit
import KeyreeveCatalog
import KeyreeveVault

@MainActor
extension AppModel {
    /// Shown as saved only once it is: a rotation must never start from a plan that was not kept.
    @discardableResult
    public func savePlaces(_ value: KeyPlaces, for item: CatalogItem) -> Bool {
        do {
            try files.savePlaces(value, for: item.path)
        } catch {
            message = (error as? CheckError)?.description ?? T("%@ could not be saved", files.places.lastPathComponent)
            return false
        }
        places[item.path] = value
        return true
    }

    public func chooseFile(then: (String) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        panel.message = T("Choose a file that holds this key")
        panel.prompt = T("Choose")
        if panel.runModal() == .OK, let url = panel.url { then(url.path) }
    }

    var vaultTool: URL? {
        binary.map { $0.deletingLastPathComponent().appendingPathComponent("keyreeve-vault") }
    }

    /// A task the journal asked of you stays listed until you say it is done. The journal keeps it.
    func isDismissed(_ status: RotationStatus) -> Bool {
        let done = UserDefaults.standard.dictionary(forKey: SettingsKey.doneRotations) as? [String: Double]
        return done?[status.key] == status.at
    }

    func dismiss(_ status: RotationStatus) {
        var done = UserDefaults.standard.dictionary(forKey: SettingsKey.doneRotations) as? [String: Double] ?? [:]
        done[status.key] = status.at
        UserDefaults.standard.set(done, forKey: SettingsKey.doneRotations)
        objectWillChange.send()
    }

    public func rotate(_ item: CatalogItem, handedOver: String? = nil) {
        runRotation(item, resume: false, handedOver: handedOver)
    }

    /// Opens the copy a rotation replaced and asks the provider about it, so "revoked" is not only
    /// your word. Nothing goes in the history: this is an old key's fate, not this key's state.
    public func confirmOldKeyDead(_ status: RotationStatus) {
        guard !busy, let binary, let item = items.first(where: { $0.path == status.key }),
            let recipe = item.recipes.first
        else { return }
        openVault(reason: T("check that an old key is dead")) { unlocked in
            guard let unlocked else {
                self.message = T("Not checked: it was not confirmed")
                return
            }
            self.busy = true
            let store = self.vaultStore
            let key = status.key
            let field = item.field
            Task.detached {
                let result = Result { () throws -> CheckRunner.KeyCheck in
                    let vault = try store.load()
                    // The newest copy that differs from the key in use. A rotation resumed after a
                    // crash can save the new key twice, and testing that would say the old one lives.
                    let identity = try unlocked.recipient(store)
                    let current = try vault.open(name: key, with: identity)
                    for index in (vault.replaced?[key]?.indices ?? 0..<0).reversed() {
                        let value = try vault.openReplaced(name: key, index: index, with: identity)
                        if value != current {
                            return try CheckRunner.checkText(
                                String(decoding: value, as: UTF8.self), recipe: recipe, field: field, binary: binary)
                        }
                    }
                    return .unknown
                }
                await MainActor.run {
                    self.busy = false
                    switch result {
                    case .success(.rejected):
                        self.dismiss(status)
                        self.message = T("The old key is dead. Done.")
                    case .success(.works): self.message = T("The old key still works: revoke it at the provider.")
                    default: self.message = T("Could not tell whether the old key is dead.")
                    }
                }
            }
        }
    }

    /// Finishes from the plan the rotation started with. The key may no longer be on the list, since
    /// its original can be gone, and the old key must still be revocable.
    public func finishRotation(of key: String) {
        guard !busy, let binary, let vaultTool else { return }
        if let item = items.first(where: { $0.path == key }), item.vault == .sealed || item.vault == .outdated {
            runRotation(item, resume: true)
            return
        }
        guard (try? vaultStore.load())?.entries[key] != nil else { return }
        let stub = RotationPlan(item: CatalogItem(path: key), places: KeyPlaces(), admin: nil, original: nil)
        run(plan: stub, admin: nil, resume: true, binary: binary, vaultTool: vaultTool)
    }

    /// `done` hears how it went, in words, whether it rotated, stopped or was never confirmed.
    func runRotation(_ item: CatalogItem, resume: Bool, handedOver: String? = nil, done: ((String) -> Void)? = nil) {
        guard !busy, let binary, let vaultTool, item.vault == .sealed || item.vault == .outdated else {
            done?(T("Not rotated: the key is not sealed, or the app is busy"))
            return
        }
        // A rotation keeps its new key under the name where a waiting value is.
        guard resume || item.waitingFrom == nil else {
            message = T("Accept or discard the new value waiting for this key first")
            done?(T("Accept or discard the new value waiting for this key first"))
            return
        }
        let places = self.places[item.path] ?? KeyPlaces()
        let admin = places.admin.flatMap { name in items.first { $0.path == name } }
        let original = keysFolder?.appendingPathComponent(item.path).path
        let plan = RotationPlan(
            item: item, places: places, admin: admin,
            original: original.flatMap { FileManager.default.fileExists(atPath: $0) ? $0 : nil })
        run(plan: plan, admin: admin?.path, resume: resume, handedOver: handedOver, binary: binary, vaultTool: vaultTool, done: done)
    }

    private func run(
        plan: RotationPlan, admin: String?, resume: Bool, handedOver: String? = nil, binary: URL, vaultTool: URL,
        done: ((String) -> Void)? = nil
    ) {
        let key = plan.key
        // Pressing the button is a person saying the old key can go, which ends a waiting overlap.
        let revokeNow = resume
        let reason = resume ? T("finish rotating a key") : T("rotate a key with its provider")
        openVault(reason: reason) { unlocked in
            guard let unlocked else {
                self.message = T("Not rotated: it was not confirmed")
                done?(T("Not rotated: it was not confirmed"))
                return
            }
            self.confirmation.confirm()
            self.busy = true
            self.message = T("Rotating…")
            let store = self.vaultStore
            let files = self.files
            Task.detached {
                let result = Result { () throws -> RotationReport in
                    // Counted before opening: if another window rotates this key in between, the
                    // command sees a different count and refuses a copy that may be revoked.
                    var plan = plan
                    let status = CheckRunner.rotations(binary: binary, files: files).first { $0.key == key }
                    plan.expected_events = status?.events ?? 0
                    let vault = try store.load()
                    // An open rotation goes on with the admin key it started with.
                    let wanted = [key, resume ? status?.admin ?? admin : admin, "\(key)#pending", "\(key)#previous"]
                        .compactMap { $0 }.filter { vault.entries[$0] != nil }
                    var sealed = try VaultKeeper.open(
                        names: wanted, recipient: try unlocked.recipient(store), store: store, by: "rotate")
                    if let handedOver { sealed["\(key)#incoming"] = handedOver }
                    return try CheckRunner.rotate(
                        plan: plan, resume: resume, revokeNow: revokeNow, sealed: sealed, binary: binary, vaultTool: vaultTool,
                        files: files)
                }
                await MainActor.run {
                    self.busy = false
                    self.load()
                    switch result {
                    case .success(let report):
                        self.message = rotationMessage(report)
                        self.note("rotated", path: key, detail: report.outcome)
                        done?(([report.outcome, rotationMessage(report)] + report.manual).joined(separator: ". "))
                    case .failure(let error):
                        self.message = (error as? CheckError)?.description ?? T("The vault could not be opened")
                        done?(self.message ?? "")
                    }
                }
            }
        }
    }

    /// Copies the chosen files into the vault. This needs no fingerprint, and originals stay.
    public func seal(_ chosen: [CatalogItem]) {
        guard !busy, !chosen.isEmpty, let folder = keysFolder else { return }
        busy = true
        vaultComparison = nil
        let store = vaultStore
        let paths = chosen.map(\.path)
        Task.detached {
            let result = Result { try VaultKeeper.seal(paths: paths, folder: folder, store: store) }
            await MainActor.run {
                self.busy = false
                self.load()
                switch result {
                case .success(let report):
                    for path in report.sealed { self.note("sealed", path: path) }
                    self.recordSealed(chosen.filter { report.sealed.contains($0.path) })
                    self.message =
                        report.skipped.isEmpty
                        ? (report.sealed.count == 1 ? T("1 key sealed") : T("%d keys sealed", report.sealed.count))
                        : T("%d keys sealed, %d could not be read as text", report.sealed.count, report.skipped.count)
                case .failure:
                    self.message = T("The vault could not be saved")
                }
            }
        }
    }

    /// Opens each sealed copy and compares it with its file, so you can trust the vault.
    public func compareVault() {
        let names = items.filter { $0.vault != .none && !$0.originalMoved }.map(\.path)
        guard !busy, !names.isEmpty, let folder = keysFolder else { return }
        openVault(reason: T("compare %d sealed keys with their files", names.count)) { unlocked in
            guard let unlocked else {
                self.message = T("Not checked: it was not confirmed")
                return
            }
            self.busy = true
            let store = self.vaultStore
            Task.detached {
                let result = Result {
                    try VaultKeeper.compare(names: names, folder: folder, recipient: try unlocked.recipient(store), store: store)
                }
                await MainActor.run {
                    self.busy = false
                    switch result {
                    case .success(let report):
                        self.vaultComparison = report
                        self.message = nil
                    case .failure:
                        self.message = T("The vault could not be opened")
                    }
                    self.load()
                }
            }
        }
    }
}


/// The result of a rotation in a person's words, which depend on what is left for them to do.
public func rotationMessage(_ report: RotationReport) -> String {
    let oldStillAlive = report.manual.contains { $0.contains("revoke it by hand") || $0.contains("revoke the old key") }
    let newStillAlive = report.manual.contains { $0.contains("revoke the unused key") || $0.contains("delete the new key") }
    switch report.outcome {
    case "completed":
        if report.manual.isEmpty { return T("Rotated. The old key is revoked.") }
        return oldStillAlive
            ? T("Rotated. The old key still works: revoke it at the provider.")
            : T("Rotated. Some steps need you: see Vault.")
    case "waiting": return T("The new key is in place. The old one keeps working until you finish.")
    case "new_key_failing": return T("The new key stopped working, so the old one was kept. Try again later.")
    case "revoke_pending": return T("The new key is in place, but the provider refused to revoke the old one. Try again.")
    case "rolled_back":
        if report.manual.isEmpty { return T("Nothing changed: the rotation was undone (%@).", report.reason ?? "") }
        return newStillAlive
            ? T("Undone, but the new key is still alive at the provider: revoke it by hand (see Vault).")
            : T("Undone, but check the provider: see Vault.")
    case "rollback_blocked": return T("Stopped: %@ could not go back to the old key.", report.reason ?? "")
    default: return T("Nothing to do")
    }
}
