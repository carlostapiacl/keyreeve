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
    public static let doneRotations = "doneRotations"
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
    @Published public var rotations: [RotationStatus] = []
    @Published public var places: [String: KeyPlaces] = [:]
    @Published public var agentPolicy = AgentPolicy()
    public let files: KeyreeveFiles
    public let vaultStore: VaultStore
    let binary: URL?
    private var lockTask: Task<Void, Never>?
    var confirmation = ConfirmationWindow()
    private var generation = 0
    /// Changes on each lock, so a confirmation that arrives afterwards counts for nothing.
    var lockEpoch = 0
    var clipboard = KeyClipboard()
    private var rebuilding: Task<Void, Never>?

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
        generation += 1
        lockEpoch += 1
        lockTask?.cancel()
        confirmation.close()
        vaultDraft = nil
        vaultComparison = nil
        clearClipboardNow()
        agentPolicy = AgentPolicy()
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

    func confirm(reason: String, then: @escaping @MainActor (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            lockMessage = T("This Mac has no way to confirm it is you.")
            then(false)
            return
        }
        let epoch = lockEpoch
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            Task { @MainActor in then(success && epoch == self.lockEpoch) }
        }
    }

    // MARK: Data

    /// Reads the private files away from the screen, then shows them. A newer load or a lock
    /// discards this one, so a load that ends after locking cannot put keys back on the window.
    public func load(then done: (@MainActor () -> Void)? = nil) {
        // Work that ends after locking calls this too, and must not refill the window.
        guard unlocked else { return }
        generation += 1
        let current = generation
        let source = Snapshot.Source(files: files, store: vaultStore, binary: binary, keysFolder: keysFolder)
        Task.detached {
            let snapshot = Snapshot(reading: source)
            await MainActor.run {
                guard current == self.generation else { return }
                self.apply(snapshot)
                done?()
            }
        }
    }

    private func apply(_ snapshot: Snapshot) {
        hasCatalog = snapshot.hasCatalog
        hasVault = snapshot.hasVault
        items = snapshot.items
        activity = snapshot.activity
        places = snapshot.places
        agentPolicy = snapshot.agentPolicy
        if let providers = snapshot.providers { self.providers = providers }
        if let rotations = snapshot.rotations { self.rotations = rotations }
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

    /// Rebuilds the list off the screen, one at a time, so quick edits end with the last of them.
    func rebuildCatalog() {
        guard let binary else { return }
        let files = self.files
        let previous = rebuilding
        rebuilding = Task.detached {
            await previous?.value
            let failure = Result { try CheckRunner.rebuildCatalog(binary: binary, files: files) }
            await MainActor.run {
                if case .failure(let error) = failure { self.message = (error as? CheckError)?.description }
                self.load()
            }
        }
    }
}

/// Everything the window shows, read together.
struct Snapshot: Sendable {
    struct Source: Sendable {
        let files: KeyreeveFiles
        let store: VaultStore
        let binary: URL?
        let keysFolder: URL?
    }

    let hasCatalog: Bool
    let hasVault: Bool
    let items: [CatalogItem]
    let activity: [ActivityItem]
    let places: [String: KeyPlaces]
    let agentPolicy: AgentPolicy
    let providers: ProviderDirectory?
    let rotations: [RotationStatus]?

    init(reading source: Source) {
        let files = source.files
        files.tightenFolders()
        let ignored = files.ignoredKeys()
        let details = files.allDetails()
        let text = try? String(contentsOf: files.catalog, encoding: .utf8)
        hasCatalog = text != nil
        var parsed = (try? CatalogParser.parse(text ?? "")) ?? []
        // Reading the names and dates needs no fingerprint.
        hasVault = source.store.exists
        let vault = try? source.store.load()
        let moved = MovedOriginals(ledger: files.moved, destination: files.originals).paths
        for index in parsed.indices {
            let path = parsed[index].path
            parsed[index].ignoredUntil = ignored[path]
            parsed[index].details = details[path]
            parsed[index].originalMoved = moved.contains(path)
            guard let entry = vault?.entries[path] else { continue }
            if let folder = source.keysFolder, VaultKeeper.isFromAnotherFolder(entry, folder: folder) {
                parsed[index].vault = .otherFolder
                continue
            }
            let changed = source.keysFolder.map { VaultKeeper.isOutdated(entry, path: path, folder: $0) } ?? false
            parsed[index].vault = changed ? .outdated : .sealed
        }
        items = parsed
        activity = files.activity()
        places = files.allPlaces()
        agentPolicy = AgentPolicy.load(from: files.agents)
        providers = source.binary.map { CheckRunner.providers(binary: $0) }
        rotations = source.binary.map { CheckRunner.rotations(binary: $0, files: files) }
    }
}
