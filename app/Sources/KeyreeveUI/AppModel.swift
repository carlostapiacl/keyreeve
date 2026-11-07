import AppKit
import CryptoKit
import KeyreeveCatalog
import KeyreeveVault
import LocalAuthentication
import SwiftUI

/// The system's fingerprint prompt, kept apart so a test can stand in for the sensor.
struct FingerGate {
    var canAsk: (LAContext, LAPolicy, inout NSError?) -> Bool = { $0.canEvaluatePolicy($1, error: &$2) }
    var ask: (LAContext, LAPolicy, String, @escaping @Sendable (Bool) -> Void) -> Void = { context, policy, reason, done in
        context.evaluatePolicy(policy, localizedReason: reason) { success, _ in done(success) }
    }
}

public enum SettingsKey {
    public static let lockMinutes = "lockMinutes"
    public static let scanOnOpen = "scanOnOpen"
    public static let appearance = "appearance"
    public static let fingerprintMinutes = "fingerprintMinutes"
    public static let doneRotations = "doneRotations"
    public static let lastVaultBackup = "lastVaultBackup"
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
    @Published public var keyIndex = KeyIndex()
    /// The usage log, newest first, and what the key service has open now.
    @Published public var usage = UsageSnapshot()
    public let files: KeyreeveFiles
    public let vaultStore: VaultStore
    let binary: URL?
    private var lockTask: Task<Void, Never>?
    private var askingFinger = false
    var fingerGate = FingerGate()
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
        closeServicePermissions()
        agentPolicy = AgentPolicy()
        keyIndex = KeyIndex()
        usage = UsageSnapshot()
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
        let epoch = lockEpoch
        let started = askFinger(LAContext(), .deviceOwnerAuthentication, reason) { success in
            then(success && epoch == self.lockEpoch)
        }
        if !started {
            lockMessage = T("This Mac has no way to confirm it is you.")
            then(false)
        }
    }

    /// One request for the finger at a time. A second one cancels the first, which reads as a sensor that
    /// did not take the touch. A request made while one is open has nothing to add, so it is dropped.
    /// Returns false only if this Mac cannot ask.
    func askFinger(
        _ context: LAContext, _ policy: LAPolicy, _ reason: String, done: @escaping @MainActor (Bool) -> Void
    ) -> Bool {
        guard !askingFinger else { return true }
        var error: NSError?
        guard fingerGate.canAsk(context, policy, &error) else { return false }
        askingFinger = true
        fingerGate.ask(context, policy, reason) { success in
            Task { @MainActor in
                self.askingFinger = false
                done(success)
            }
        }
        return true
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
        keyIndex = snapshot.keyIndex
        usage = snapshot.usage
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
        guard FileManager.default.fileExists(atPath: folder.path) else {
            message = T("The keys folder is gone. Keys in the vault stay on the list.")
            return
        }
        busy = true
        message = T("Scanning…")
        let files = self.files
        let store = vaultStore
        Task.detached {
            let before = try? Data(contentsOf: files.inventory)
            let result = Result {
                try CheckRunner.refresh(binary: binary, keysFolder: folder, files: files)
                try Self.keepSealed(before: before, folder: folder, files: files, store: store, binary: binary)
            }
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

    /// A sealed key whose file left the folder stays on the list, since the vault still holds it.
    nonisolated static func keepSealed(before: Data?, folder: URL, files: KeyreeveFiles, store: VaultStore, binary: URL) throws {
        guard let vault = try? store.load() else { return }
        let sealed = Set(vault.entries.filter { !VaultKeeper.isFromAnotherFolder($0.value, folder: folder) }.keys)
        let ledger = MovedOriginals(ledger: files.moved, destination: files.originals)
        if try !ledger.keepSealed(sealed, before: before, inventory: files.inventory).isEmpty {
            try CheckRunner.rebuildCatalog(binary: binary, files: files)
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

/// What the usage log says and what is in force. Asking the service starts nothing: with no socket, nothing is open.
public struct UsageSnapshot: Sendable, Equatable {
    public var entries: [AuditLog.Entry] = []
    public var grants: [KeyService.GrantInfo] = []
    /// The first line that does not fit the chain, if something changed the log.
    public var brokenLine: Int?

    public init() {}

    init(files: KeyreeveFiles) {
        let log = AuditLog(url: files.audit)
        entries = Array(((try? log.entries()) ?? []).suffix(500).reversed())
        brokenLine = log.firstBrokenLine()
        if FileManager.default.fileExists(atPath: files.keySocket.path) {
            grants = (try? KeySocket.send(KeyService.Request(op: "grants"), path: files.keySocket.path, timeout: 1))?.grants ?? []
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
    let keyIndex: KeyIndex
    let usage: UsageSnapshot
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
        keyIndex = (try? KeyIndex.load(from: files.keyIndex)) ?? KeyIndex()
        usage = UsageSnapshot(files: files)
        providers = source.binary.map { CheckRunner.providers(binary: $0) }
        rotations = source.binary.map { CheckRunner.rotations(binary: $0, files: files) }
    }
}
