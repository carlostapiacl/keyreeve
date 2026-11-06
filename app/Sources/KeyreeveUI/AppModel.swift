import AppKit
import KeyreeveCatalog
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
    public let files: KeyreeveFiles
    private let binary: URL?
    private var lockTask: Task<Void, Never>?
    private var confirmation = ConfirmationWindow()

    public init(files: KeyreeveFiles = KeyreeveFiles(), binary: URL? = Bundle.main.url(forAuxiliaryExecutable: "keyreeve-cli")) {
        self.files = files
        self.binary = binary
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

    public func check(_ chosen: [CatalogItem], then done: (@MainActor () -> Void)? = nil) {
        let list = chosen.filter(providers.canCheck)
        guard !list.isEmpty, !busy, let folder = keysFolder, let binary else { return }
        let reason =
            list.count == 1
            ? T("check 1 key with its provider") : T("check %d keys with their providers", list.count)
        gated(list, reason: reason) {
            self.busy = true
            self.lastRun = nil
            self.progress = (0, list.count)
            self.message = T("Checking…")
            let files = self.files
            Task.detached {
                let result = Result {
                    try CheckRunner.run(list, binary: binary, keysFolder: folder, files: files) { finished, total in
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
        gated(list, reason: T("identify %d keys with their providers", list.count)) {
            self.busy = true
            self.message = T("Identifying…")
            let files = self.files
            let providers = self.providers
            Task.detached {
                let result = Result {
                    try CheckRunner.identify(list, providers: providers, binary: binary, keysFolder: folder, files: files)
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
        let start = {
            self.busy = true
            self.message = custom.title
            Task.detached {
                let result = Result {
                    try CheckRunner.runAction(
                        provider: provider, action: custom, item: item, binary: binary, keysFolder: folder)
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
            gated([CatalogItem(path: item.path, level: "ask")], reason: custom.title, run: start)
        } else {
            start()
        }
    }

    public func approve(_ provider: ProviderInfo) {
        guard let binary else { return }
        try? CheckRunner.approve(provider.id, binary: binary)
        load()
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
