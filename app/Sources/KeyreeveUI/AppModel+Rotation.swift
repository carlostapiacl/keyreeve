import AppKit
import KeyreeveCatalog
import KeyreeveVault

@MainActor
extension AppModel {
    public func savePlaces(_ value: KeyPlaces, for item: CatalogItem) {
        try? files.savePlaces(value, for: item.path)
        places[item.path] = value
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

    public func rotate(_ item: CatalogItem) { runRotation(item, resume: false) }

    /// Finishes from the plan the rotation started with. The key may no longer be on the list, since
    /// its original can be gone, and the old key must still be revocable.
    public func finishRotation(of key: String) {
        guard !busy, let binary, let vaultTool else { return }
        if let item = items.first(where: { $0.path == key }) {
            runRotation(item, resume: true)
            return
        }
        guard (try? vaultStore.load())?.entries[key] != nil else { return }
        let stub = RotationPlan(item: CatalogItem(path: key), places: KeyPlaces(), admin: nil, original: nil)
        run(plan: stub, admin: nil, resume: true, binary: binary, vaultTool: vaultTool)
    }

    func runRotation(_ item: CatalogItem, resume: Bool) {
        guard !busy, let binary, let vaultTool, item.vault == .sealed || item.vault == .outdated else { return }
        let places = self.places[item.path] ?? KeyPlaces()
        let admin = places.admin.flatMap { name in items.first { $0.path == name } }
        let original = keysFolder?.appendingPathComponent(item.path).path
        let plan = RotationPlan(
            item: item, places: places, admin: admin,
            original: original.flatMap { FileManager.default.fileExists(atPath: $0) ? $0 : nil })
        run(plan: plan, admin: admin?.path, resume: resume, binary: binary, vaultTool: vaultTool)
    }

    private func run(plan: RotationPlan, admin: String?, resume: Bool, binary: URL, vaultTool: URL) {
        let key = plan.key
        let reason = resume ? T("finish rotating a key") : T("rotate a key with its provider")
        openVault(reason: reason) { unlocked in
            guard let unlocked else {
                self.message = T("Not rotated: it was not confirmed")
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
                    let sealed = try VaultKeeper.open(
                        names: wanted, recipient: try unlocked.recipient(store), store: store, by: "rotate")
                    return try CheckRunner.rotate(
                        plan: plan, resume: resume, sealed: sealed, binary: binary, vaultTool: vaultTool, files: files)
                }
                await MainActor.run {
                    self.busy = false
                    self.load()
                    switch result {
                    case .success(let report): self.message = rotationMessage(report)
                    case .failure(let error):
                        self.message = (error as? CheckError)?.description ?? T("The vault could not be opened")
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


/// The result of a rotation in a person's words.
public func rotationMessage(_ report: RotationReport) -> String {
    switch report.outcome {
    case "completed":
        return report.manual.isEmpty
            ? T("Rotated. The old key is revoked.")
            : T("Rotated. The old key still works: revoke it at the provider.")
    case "waiting": return T("The new key is in place. The old one keeps working until you finish.")
    case "new_key_failing": return T("The new key stopped working, so the old one was kept. Try again later.")
    case "revoke_pending": return T("The new key is in place, but the provider refused to revoke the old one. Try again.")
    case "rolled_back":
        return report.manual.isEmpty
            ? T("Nothing changed: the rotation was undone (%@).", report.reason ?? "")
            : T("Undone, but the new key is still alive at the provider: revoke it by hand (see Vault).")
    case "rollback_blocked": return T("Stopped: %@ could not go back to the old key.", report.reason ?? "")
    default: return T("Nothing to do")
    }
}
