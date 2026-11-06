import AppKit
import CryptoKit
import KeyreeveCatalog
import KeyreeveVault
import LocalAuthentication
import SwiftUI

public enum SettingsKey {
    public static let lockMinutes = "lockMinutes"
    public static let scanOnOpen = "scanOnOpen"
    public static let appearance = "appearance"
    public static let fingerprintMinutes = "fingerprintMinutes"
}

@MainActor
public final class AppModel: ObservableObject {
    @Published public var unlocked = false
    @Published public var lockMessage: String?
    @Published public var items: [CatalogItem] = []
    @Published public var hasCatalog = false
    @Published public var busy = false
    @Published public var message: String?
    @Published public var activity: [ActivityItem] = []
    @Published public var providers = ProviderDirectory()
    /// How far the current batch got, as done and total.
    @Published public var progress: (done: Int, total: Int)?
    @Published public var lastRun: RunSummary?
    @Published public var hasVault = false
    /// A new vault waiting for its recovery key to be written down. Nothing is on disk yet.
    @Published public var vaultDraft: VaultDraft?
    @Published public var vaultComparison: VaultKeeper.CompareReport?
    public let files: KeyreeveFiles
    public let vaultStore: VaultStore
    private let binary: URL?
    private var lockTask: Task<Void, Never>?
    private var confirmation = ConfirmationWindow()

    public init(files: KeyreeveFiles = KeyreeveFiles(), binary: URL? = Bundle.main.url(forAuxiliaryExecutable: "keyreeve-cli")) {
        self.files = files
        self.binary = binary
        vaultStore = VaultStore(directory: files.directory.appendingPathComponent("vault"))
    }

    public var keysFolder: URL? { files.keysFolder() }
    public var commandURL: URL? { binary }

    // MARK: Lock

    /// This lock covers the window. Keys kept in the vault ask for a fingerprint on their own.
    public func unlock() {
        confirm(reason: T("open your key catalog")) { success in
            guard success else {
                self.lockMessage = T("Not unlocked. Try again.")
                return
            }
            self.confirmation.confirm()
            self.lockMessage = nil
            self.unlocked = true
            self.load()
            let scan = UserDefaults.standard.object(forKey: SettingsKey.scanOnOpen) as? Bool ?? true
            if scan && self.keysFolder != nil { self.refresh() }
        }
    }

    public func lock() {
        lockTask?.cancel()
        confirmation.close()
        vaultDraft = nil
        vaultComparison = nil
        unlocked = false
        items = []
        activity = []
        message = nil
    }

    public func windowLostFocus() {
        lockTask?.cancel()
        let saved = UserDefaults.standard.object(forKey: SettingsKey.lockMinutes) as? Int ?? 5
        lockTask = Task {
            try? await Task.sleep(for: .seconds(max(1, saved) * 60))
            if !Task.isCancelled { self.lock() }
        }
    }

    public func windowGotFocus() { lockTask?.cancel() }

    private func confirm(reason: String, then: @escaping @MainActor (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            lockMessage = T("This Mac has no way to confirm it is you.")
            then(false)
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            Task { @MainActor in then(success) }
        }
    }

    // MARK: Data

    public func load() {
        let ignored = files.ignoredKeys()
        let details = files.allDetails()
        let text = try? String(contentsOf: files.catalog, encoding: .utf8)
        hasCatalog = text != nil
        var parsed = (try? CatalogParser.parse(text ?? "")) ?? []
        for index in parsed.indices {
            parsed[index].ignoredUntil = ignored[parsed[index].path]
            parsed[index].details = details[parsed[index].path]
        }
        // Reading the names and dates needs no fingerprint.
        hasVault = vaultStore.exists
        if let vault = try? vaultStore.load() {
            let folder = keysFolder
            for index in parsed.indices {
                guard let entry = vault.entries[parsed[index].path] else { continue }
                let changed = folder.map { VaultKeeper.isOutdated(entry, path: parsed[index].path, folder: $0) } ?? false
                parsed[index].vault = changed ? .outdated : .sealed
            }
        }
        items = parsed
        activity = files.activity()
        if let binary { providers = CheckRunner.providers(binary: binary) }
    }

    public func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.message = T("Choose the folder that holds your key files")
        panel.prompt = T("Choose")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? files.saveKeysFolder(url)
        refresh()
    }

    public func refresh() {
        guard !busy, let folder = keysFolder, let binary else {
            if binary == nil { message = T("This app was built without its command") }
            return
        }
        busy = true
        message = T("Scanning…")
        let files = self.files
        Task.detached {
            let result = Result { try CheckRunner.refresh(binary: binary, keysFolder: folder, files: files) }
            await MainActor.run {
                self.busy = false
                self.load()
                switch result {
                case .success: self.message = T("Up to date")
                case .failure(let error):
                    self.message = (error as? CheckError)?.description ?? T("The scan did not finish")
                }
            }
        }
    }

    // MARK: Checks and identification

    private func gated(_ list: [CatalogItem], reason: String, run: @escaping @MainActor () -> Void) {
        let minutes = UserDefaults.standard.object(forKey: SettingsKey.fingerprintMinutes) as? Int ?? 5
        guard list.contains(where: { $0.level == "ask" }), !confirmation.isOpen(minutes: minutes) else {
            run()
            return
        }
        confirm(reason: reason) { success in
            if success { self.confirmation.confirm() }
            if success { run() } else { self.message = T("Not checked: it was not confirmed") }
        }
    }

    /// Gets what these keys need before they can run. Keys in the vault ask for one fingerprint
    /// for the whole list, and that also answers for the "Ask me" keys in it. A file that changed
    /// after sealing is read from disk, because the sealed copy may be an old key.
    private func withKeys(
        _ list: [CatalogItem], reason: String, by command: String,
        run: @escaping @MainActor (_ sealed: [String: String]) -> Void
    ) {
        let names = list.filter { $0.vault == .sealed }.map(\.path)
        guard !names.isEmpty else {
            gated(list, reason: reason) { run([:]) }
            return
        }
        openVault(reason: reason) { unlocked in
            guard let unlocked else {
                self.message = T("Not checked: it was not confirmed")
                return
            }
            self.confirmation.confirm()
            let store = self.vaultStore
            self.busy = true
            self.message = T("Opening the vault…")
            Task.detached {
                let result = Result {
                    try VaultKeeper.open(names: names, recipient: try unlocked.recipient(store), store: store, by: command)
                }
                await MainActor.run {
                    self.busy = false
                    switch result {
                    case .success(let sealed): run(sealed)
                    case .failure: self.message = T("The vault could not be opened")
                    }
                }
            }
        }
    }

    /// Asks for the finger once. The chip accepts this same confirmation for each key that follows.
    private func openVault(reason: String, then: @escaping @MainActor (UnlockedVault?) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            message = T("The fingerprint sensor is not available. Open the lid, or check your Mac's settings.")
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            let unlocked = UnlockedVault(context: context)
            Task { @MainActor in then(success ? unlocked : nil) }
        }
    }

    public func check(_ chosen: [CatalogItem], then done: (@MainActor () -> Void)? = nil) {
        let list = chosen.filter(providers.canCheck)
        guard !list.isEmpty, !busy, let folder = keysFolder, let binary else { return }
        let reason =
            list.count == 1
            ? T("check 1 key with its provider") : T("check %d keys with their providers", list.count)
        withKeys(list, reason: reason, by: "check") { sealed in
            self.busy = true
            self.lastRun = nil
            self.progress = (0, list.count)
            self.message = T("Checking…")
            let files = self.files
            Task.detached {
                let result = Result {
                    try CheckRunner.run(list, binary: binary, keysFolder: folder, files: files, sealed: sealed) { finished, total in
                        Task { @MainActor in self.progress = (finished, total) }
                    }
                }
                await MainActor.run {
                    self.busy = false
                    self.progress = nil
                    self.load()
                    switch result {
                    case .success:
                        let paths = Set(list.map(\.path))
                        let summary = RunSummary(items: self.items, checked: paths)
                        if list.count > 1 { self.lastRun = summary }
                        self.message = T("%d checked: %d work", list.count, summary.works)
                        done?()
                    case .failure(let error):
                        self.message = (error as? CheckError)?.description ?? T("The check did not finish")
                    }
                }
            }
        }
    }

    public func identify(_ chosen: [CatalogItem]) {
        let list = chosen.filter(providers.canIdentify)
        guard !list.isEmpty, !busy, let folder = keysFolder, let binary else { return }
        withKeys(list, reason: T("identify %d keys with their providers", list.count), by: "identify") { sealed in
            self.busy = true
            self.message = T("Identifying…")
            let files = self.files
            let providers = self.providers
            Task.detached {
                let result = Result {
                    try CheckRunner.identify(list, providers: providers, binary: binary, keysFolder: folder, files: files, sealed: sealed)
                }
                await MainActor.run {
                    self.busy = false
                    self.load()
                    switch result {
                    case .success:
                        let paths = Set(list.map(\.path))
                        let found = self.items.filter { paths.contains($0.path) && $0.details != nil }.count
                        self.message = T("Identified %d", found)
                    case .failure(let error):
                        self.message = (error as? CheckError)?.description ?? T("The check did not finish")
                    }
                }
            }
        }
    }

    /// You typed this address, for a provider you run, so approving it is part of saving it.
    public func setHost(_ host: String, on item: CatalogItem) {
        let host = host.trimmingCharacters(in: .whitespaces)
        guard let binary, let provider = item.recipes.first else { return }
        do {
            if !host.isEmpty { try CheckRunner.approveHost(host, for: provider, binary: binary) }
            save(KeyEdit(host: host), for: item)
        } catch {
            message = (error as? CheckError)?.description
        }
    }

    public func run(_ custom: CustomAction, provider: String, on item: CatalogItem) {
        if let page = custom.open.flatMap(URL.init(string:)) {
            NSWorkspace.shared.open(page)
            return
        }
        guard !busy, let binary else { return }
        let folder = keysFolder
        let start: @MainActor ([String: String]) -> Void = { sealed in
            self.busy = true
            self.message = custom.title
            Task.detached {
                let result = Result {
                    try CheckRunner.runAction(
                        provider: provider, action: custom, item: item, binary: binary, keysFolder: folder,
                        sealed: sealed[item.path])
                }
                await MainActor.run {
                    self.busy = false
                    switch result {
                    case .success(let text): self.message = text.isEmpty ? T("Done") : text
                    case .failure: self.message = T("The action did not finish")
                    }
                }
            }
        }
        if custom.needs_key {
            var asking = item
            asking.level = "ask"
            withKeys([asking], reason: custom.title, by: custom.id, run: start)
        } else {
            start([:])
        }
    }

    public func approve(_ provider: ProviderInfo) {
        guard let binary else { return }
        try? CheckRunner.approve(provider.id, binary: binary)
        load()
    }

    // MARK: Vault

    /// Makes the chip's key and the recovery key, and keeps both in memory for the next screen.
    public func startVault() {
        guard !vaultStore.exists else { return }
        do {
            let (enclave, blob) = try EnclaveRecipient.create()
            vaultDraft = VaultDraft(enclave: enclave, blob: blob, recovery: P256.KeyAgreement.PrivateKey())
        } catch {
            message = T("This Mac could not create a key in its chip")
        }
    }

    public func finishVault() {
        guard let draft = vaultDraft else { return }
        do {
            try draft.save(to: vaultStore)
            message = T("Your vault is ready")
        } catch {
            message = T("The vault could not be saved")
        }
        vaultDraft = nil
        load()
    }

    public func cancelVault() { vaultDraft = nil }

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
        let names = items.filter { $0.vault != .none }.map(\.path)
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

    // MARK: Actions and edits

    public func actionsFor(_ item: CatalogItem) -> [KeyAction] { actions(for: item, providers: providers) }

    public func perform(_ action: KeyAction, on item: CatalogItem) {
        switch action {
        case .openProvider(let url):
            NSWorkspace.shared.open(url)
        case .confirmRevoked:
            check([item]) { self.finishRevocation(of: item) }
        case .markRevoked:
            setDone(item, tag: "status:revoked")
            message = T("You marked it as revoked")
        case .checkAgain:
            check([item])
        case .notInUse:
            setDone(item, tag: "status:retired")
        case .fixPermissions:
            guard let folder = keysFolder else { return }
            do {
                try files.fixPermissions(of: item.path, in: folder)
                message = T("Permissions fixed")
                refresh()
            } catch {
                message = T("The scan did not finish")
            }
        case .ignore:
            try? files.ignore(item.path, until: Date().addingTimeInterval(30 * 86_400))
            load()
        }
    }

    public func archive(_ item: CatalogItem) {
        save(KeyEdit(tags: item.tags + ["status:archived"]), for: item)
    }

    public func restore(_ item: CatalogItem) {
        save(KeyEdit(tags: item.tags.filter { $0 != "status:archived" }), for: item)
    }

    private func finishRevocation(of item: CatalogItem) {
        guard let fresh = items.first(where: { $0.path == item.path }) else { return }
        if fresh.lastResult == "rejected" {
            setDone(fresh, tag: "status:revoked")
            message = T("Revoked: the provider rejects it now")
        } else {
            message = T("It still works: revoke it at the provider")
        }
    }

    private func setDone(_ item: CatalogItem, tag: String) {
        let tags = item.tags.filter { $0 != "revoke" } + [tag]
        save(KeyEdit(tags: tags), for: item)
    }

    public func save(_ edit: KeyEdit, for item: CatalogItem) {
        guard let binary else { return }
        try? files.saveEdit(edit, for: item.path)
        do {
            try CheckRunner.rebuildCatalog(binary: binary, files: files)
        } catch {
            message = (error as? CheckError)?.description
        }
        load()
    }
}

/// A fingerprint already given, carried to where the chip is used.
private struct UnlockedVault: @unchecked Sendable {
    let context: LAContext

    func recipient(_ store: VaultStore) throws -> EnclaveRecipient {
        try EnclaveRecipient.load(blob: try store.loadBlob(), context: context)
    }
}
