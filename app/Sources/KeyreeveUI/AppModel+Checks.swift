import AppKit
import KeyreeveCatalog
import KeyreeveVault
import LocalAuthentication

@MainActor
extension AppModel {
    func gated(_ list: [CatalogItem], reason: String, run: @escaping @MainActor () -> Void) {
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
    func withKeys(
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
            let epoch = self.lockEpoch
            self.busy = true
            self.message = T("Opening the vault…")
            Task.detached {
                let result = Result {
                    try VaultKeeper.open(names: names, recipient: try unlocked.recipient(store), store: store, by: command)
                }
                await MainActor.run {
                    self.busy = false
                    // Locked while the chip was working: the opened copies go no further.
                    guard epoch == self.lockEpoch else { return }
                    switch result {
                    case .success(let sealed): run(sealed)
                    case .failure: self.message = T("The vault could not be opened")
                    }
                }
            }
        }
    }

    /// Asks for the finger once. The chip accepts this same confirmation for each key that follows.
    func openVault(reason: String, then: @escaping @MainActor (UnlockedVault?) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            message = T("The fingerprint sensor is not available. Open the lid, or check your Mac's settings.")
            return
        }
        let epoch = lockEpoch
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            let unlocked = UnlockedVault(context: context)
            Task { @MainActor in then(success && epoch == self.lockEpoch ? unlocked : nil) }
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
                    self.load {
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
                    self.load {
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
}


/// A fingerprint already given, carried to where the chip is used.
struct UnlockedVault: @unchecked Sendable {
    let context: LAContext

    func recipient(_ store: VaultStore) throws -> EnclaveRecipient {
        try EnclaveRecipient.load(blob: try store.loadBlob(), context: context)
    }
}
