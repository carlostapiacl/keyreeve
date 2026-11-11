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
                    // A check or an identify only asks the provider about the key: it is not a use.
                    try VaultKeeper.open(
                        names: names, recipient: try unlocked.recipient(store), store: store, by: command,
                        event: ["check", "identify"].contains(command) ? "checked" : "used")
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
        let epoch = lockEpoch
        let unlocked = UnlockedVault(context: context)
        let started = askFinger(context, .deviceOwnerAuthenticationWithBiometrics, reason) { success in
            then(success && epoch == self.lockEpoch ? unlocked : nil)
        }
        if !started {
            message = T("The fingerprint sensor is not available. Open the lid, or check your Mac's settings.")
        }
    }

    /// `done` follows once the message says how the check, and the identifying after it, went, whatever the result.
    public func check(_ chosen: [CatalogItem], then done: (@MainActor () -> Void)? = nil) {
        let list = chosen.filter(providers.canCheck)
        guard let (folder, binary) = readyToRun(list, none: T("None of these keys can be checked from here")) else { return }
        let providers = self.providers
        let alsoIdentify = Self.alsoIdentify(list, providers: providers)
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
                // Checking many keys at once also asks their providers whose they are, with the copies already
                // opened: that is how a key's account and the day it stops working stay current. It runs even when
                // the list could not be rebuilt after the check, and how it went is said apart.
                var identified: Result<Void, Error>?
                if !alsoIdentify.isEmpty {
                    await MainActor.run {
                        self.progress = nil
                        self.message = T("Identifying…")
                    }
                    identified = Result {
                        try CheckRunner.identify(
                            alsoIdentify, providers: providers, binary: binary, keysFolder: folder, files: files, sealed: sealed)
                    }
                }
                let identifiedNote = identified.map { Self.identifyNote($0, count: alsoIdentify.count) }
                await MainActor.run {
                    // How identifying went stays in the log too, so it can be told later without the window.
                    if let identifiedNote { self.audit([("\(alsoIdentify.count) keys", identifiedNote)], event: "identify") }
                    self.busy = false
                    self.progress = nil
                    self.load {
                        switch result {
                        case .success:
                            let paths = Set(list.map(\.path))
                            let summary = RunSummary(items: self.items, checked: paths)
                            if list.count > 1 { self.lastRun = summary }
                            self.message = [T("%d checked: %d work", list.count, summary.works), identifiedNote]
                                .compactMap { $0 }.joined(separator: ". ")
                        case .failure(let error):
                            self.message = [(error as? CheckError)?.description ?? T("The check did not finish"), identifiedNote]
                                .compactMap { $0 }.joined(separator: ". ")
                        }
                        done?()
                    }
                }
            }
        }
    }

    /// How the identifying after a check went, in words for the message.
    nonisolated static func identifyNote(_ result: Result<Void, Error>, count: Int) -> String {
        switch result {
        case .success: return T("%d identified with their providers", count)
        case .failure(let error):
            return T("Identifying did not finish: %@", (error as? CheckError)?.description ?? error.localizedDescription)
        }
    }

    /// The keys of a run of several whose provider can also say whose they are. A single check stays a check.
    nonisolated static func alsoIdentify(_ list: [CatalogItem], providers: ProviderDirectory) -> [CatalogItem] {
        list.count > 1 ? list.filter(providers.canIdentify) : []
    }

    /// The folder and the command, when work can start now. Otherwise it says why, never nothing.
    func readyToRun(_ list: [CatalogItem], none: String) -> (URL, URL)? {
        guard let binary else {
            message = T("This app was built without its command")
            return nil
        }
        guard let folder = keysFolder else {
            message = T("Choose the folder that holds your key files")
            return nil
        }
        guard !busy else {
            message = T("Keyreeve is busy. Try again when it finishes.")
            return nil
        }
        guard !list.isEmpty else {
            message = none
            return nil
        }
        return (folder, binary)
    }

    public func identify(_ chosen: [CatalogItem]) {
        let list = chosen.filter(providers.canIdentify)
        guard let (folder, binary) = readyToRun(list, none: T("None of these keys can be identified: their provider cannot say whose they are, or they cannot be checked from here")) else { return }
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
                    self.audit([("\(list.count) keys", Self.identifyNote(result, count: list.count))], event: "identify")
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

    /// A server that came as a suggestion, approved by your click, and the key checked there right after.
    /// Approving is what lets the key travel to that server, so it never happens on its own.
    public func approveHostAndCheck(_ item: CatalogItem) {
        guard let binary, let waiting = providers.unapprovedHost(of: item) else { return }
        do {
            try CheckRunner.approveHost(waiting.host, for: waiting.provider, binary: binary)
        } catch {
            message = (error as? CheckError)?.description
            return
        }
        note("allowed", path: item.path, detail: "server \(waiting.host) approved for \(waiting.provider)")
        load {
            guard let current = self.items.first(where: { $0.path == item.path }) else { return }
            self.check([current])
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
