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
    /// Whether opening the list of keys asks for a fingerprint. On unless the person turns it off.
    public static let askToOpen = "askToOpen"
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
    @Published public var items: [CatalogItem] = [] {
        didSet {
            summary = CatalogSummary(items: items)
            itemsVersion &+= 1
        }
    }
    /// Counts for the lists, kept with the keys so a redraw does not count them again.
    public private(set) var summary = CatalogSummary(items: [])
    /// Changes whenever the keys or the providers do, so a view can keep what it worked out until then.
    public private(set) var itemsVersion = 0
    @Published public var hasCatalog = false
    @Published public var busy = false
    @Published public var message: String?
    @Published public var activity: [ActivityItem] = []
    @Published public var providers = ProviderDirectory() { didSet { itemsVersion &+= 1 } }
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
    /// Sources whose sealed copy for use with no fingerprint is in the vault.
    @Published var unattendedSources: Set<String> = []
    /// Agents' requests for keys not saved yet, with no answer.
    @Published public var pendingRequests: [AccessRequests.Entry] = []
    /// The emergency stop is on: every agent is refused.
    @Published public var agentsPaused = false
    /// Bumped to bring the window to the requests.
    @Published public var showRequests = 0
    /// Read from the settings each time; a test sets its own.
    var asksToOpenSetting: () -> Bool = { UserDefaults.standard.object(forKey: SettingsKey.askToOpen) as? Bool ?? true }
    /// The person chose to start with no keys folder, so the welcome is not shown again.
    @Published public var startedWithoutFolder = UserDefaults.standard.bool(forKey: "startedWithoutFolder")

    /// The welcome is for someone with nothing yet: no list, no vault, no pasted key.
    public var needsWelcome: Bool { !hasCatalog && items.isEmpty && !hasVault && !startedWithoutFolder }

    public func startWithoutFolder() {
        UserDefaults.standard.set(true, forKey: "startedWithoutFolder")
        startedWithoutFolder = true
    }

    /// A key being pasted into the vault, while its sheet is open.
    @Published public var addingKey: AddKeyDraft?
    /// The requests file as last read, so an unchanged file is not read again.
    var requestsStamp = ""
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
    /// The read whose list is on screen. Work from an older read that ends after it runs at once.
    private var shownGeneration = 0
    /// Changes on each lock, so a confirmation that arrives afterwards counts for nothing.
    var lockEpoch = 0
    var clipboard = KeyClipboard()
    private var rebuilding: Task<Void, Never>?
    /// True while the list is being rebuilt from the folder, so work that reads it waits.
    var rebuildingNow = false
    /// Reads of the private files not yet shown. A rebuild ends with one, so work that reads the list waits for
    /// it too, or it would run with the list from before an edit.
    var loadsInFlight = 0
    /// What loads that a newer one replaced were to do once the list was shown: the newer one does it, so a
    /// result such as a check's message is never lost to a reload that started after it.
    private var afterLoad: [@MainActor () -> Void] = []
    /// Something is still changing what the list says: work that reads it waits.
    var settling: Bool { busy || rebuildingNow || loadsInFlight > 0 }

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
        // When an agent's request opened the app, the sensor says so.
        reloadRequests()
        let reason = pendingRequests.first.map { T("open Keyreeve: %@ asks for a %@ key", $0.agent, $0.provider) }
            ?? T("open your key catalog")
        let open = { (body: @escaping @MainActor (Bool) -> Void) in
            if self.asksToOpen { self.confirm(reason: reason, then: body) } else { body(true) }
        }
        open { success in
            guard success else {
                // A second unlock while the first prompt is open is told no; the first still decides.
                if !self.askingFinger { self.lockMessage = T("Not unlocked. Try again.") }
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
        // A key pasted and not saved leaves memory and the clipboard with the lock.
        cancelAddingKey()
        clearClipboardNow()
        // Locking hides the window's contents. What agents were allowed lasts while Keyreeve runs, and
        // ends when it quits or with Lock everything.
        agentPolicy = AgentPolicy()
        keyIndex = KeyIndex()
        usage = UsageSnapshot()
        unlocked = false
        items = []
        activity = []
        message = nil
    }

    /// The list holds no value, so asking to open it only keeps out someone at this Mac. A person may turn
    /// it off; every key still asks on its own.
    var asksToOpen: Bool { asksToOpenSetting() }

    public func windowLostFocus() {
        lockTask?.cancel()
        // With no fingerprint to open it, locking on its own would only add a click.
        guard asksToOpen else { return }
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
    /// did not take the touch. A request made while one is open is answered no at once, so whatever waits
    /// on it moves on instead of waiting forever. Returns false only if this Mac cannot ask.
    func askFinger(
        _ context: LAContext, _ policy: LAPolicy, _ reason: String, done: @escaping @MainActor (Bool) -> Void
    ) -> Bool {
        guard !askingFinger else {
            Task { @MainActor in done(false) }
            return true
        }
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
        loadsInFlight += 1
        Task.detached {
            let snapshot = Snapshot(reading: source)
            await MainActor.run {
                self.loadsInFlight -= 1
                guard current == self.generation else {
                    // A newer read is still on its way: its list runs this. If it already showed its list,
                    // the list on screen is newer than this one, so this runs now and is not left waiting.
                    if self.shownGeneration == self.generation {
                        done?()
                    } else if let done {
                        self.afterLoad.append(done)
                    }
                    return
                }
                self.shownGeneration = current
                self.apply(snapshot)
                let waiting = self.afterLoad
                self.afterLoad = []
                for work in waiting { work() }
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
        unattendedSources = snapshot.unattendedSources
        keyIndex = snapshot.keyIndex
        usage = snapshot.usage
        if let providers = snapshot.providers { self.providers = providers }
        if let rotations = snapshot.rotations { self.rotations = rotations }
        if !snapshot.problems.isEmpty { message = snapshot.problems.joined(separator: " ") }
        reloadRequests()
        publishOffered()
        publishInventory()
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
        rebuildingNow = true
        rebuilding = Task.detached {
            await previous?.value
            let failure = Result { try CheckRunner.rebuildCatalog(binary: binary, files: files) }
            await MainActor.run {
                if case .failure(let error) = failure { self.message = (error as? CheckError)?.description }
                self.rebuildingNow = false
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
        let recent = log.recent(500)
        entries = recent.entries.reversed()
        brokenLine = recent.brokenLine
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
    /// Files that are there and could not be read. Each would otherwise look empty, which is a different thing.
    let problems: [String]
    /// The vault's entries with a copy that opens with no fingerprint.
    let unattendedSources: Set<String>
    let providers: ProviderDirectory?
    let rotations: [RotationStatus]?

    init(reading source: Source) {
        let files = source.files
        files.tightenFolders()
        let ignored = files.ignoredKeys()
        let details = files.allDetails()
        var problems: [String] = []
        let text = try? String(contentsOf: files.catalog, encoding: .utf8)
        hasCatalog = text != nil
        var parsed: [CatalogItem] = []
        do {
            let read = try CatalogParser.parseCounting(text ?? "")
            parsed = read.items
            if read.skipped == 1 {
                problems.append(T("1 row of the list could not be read. Scanning the folder again rebuilds it."))
            } else if read.skipped > 1 {
                problems.append(T("%d rows of the list could not be read. Scanning the folder again rebuilds it.", read.skipped))
            }
        } catch {
            problems.append(T("The list of keys could not be read. Scanning the folder again rebuilds it."))
        }
        // Reading the names and dates needs no fingerprint.
        hasVault = source.store.exists
        var vault: VaultFile?
        do {
            vault = hasVault ? try source.store.load() : nil
        } catch {
            // Not an empty vault: the keys may all be there, and nothing should act as if they were gone.
            problems.append(T("The vault is there but could not be opened: %@. Nothing in it was changed.", "\(error)"))
        }
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
        // Keys pasted in the app, or put in the vault from a script with `keyreeve-vault add`, have no file and no
        // catalog line, and are listed from the vault, so each can be checked and named like any other.
        let index = (try? KeyIndex.load(from: files.keyIndex)) ?? KeyIndex()
        let listed = Set(parsed.map(\.path))
        let pasted = (vault?.entries ?? [:]).filter { name, entry in
            !listed.contains(name) && !VaultFile.isTemporary(name) && (name.hasPrefix(AppModel.addedFolder) || entry.source == nil)
        }.keys.sorted()
        // With no catalog line, their last check and their edits are read here, as the catalog would.
        let checked = pasted.isEmpty ? [:] : files.lastResults(for: Set(pasted))
        let edits = pasted.isEmpty ? [:] : ((try? JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: files.edits))) ?? [:])
        for name in pasted {
            let indexed = index.allKeys(forSource: name).first
            var item = CatalogItem(
                path: name, recipes: indexed?.provider.map { [$0] } ?? [], name: indexed?.description ?? indexed?.id ?? "")
            if let edit = edits[name] { item = item.applying(edit) }
            if let last = checked[name] {
                item.lastResult = last.result
                item.lastChecked = last.day
            }
            item.vault = .sealed
            item.originalMoved = true
            parsed.append(item)
        }
        items = parsed
        activity = files.activity()
        places = files.allPlaces()
        do {
            agentPolicy = try AgentPolicy.loadStrict(from: files.agents)
        } catch {
            // Read as allowing nothing, as agents read it; changing it is refused until the file is repaired.
            agentPolicy = AgentPolicy()
            problems.append("\(error)")
        }
        do {
            keyIndex = FileManager.default.fileExists(atPath: files.keyIndex.path) ? try KeyIndex.load(from: files.keyIndex) : KeyIndex()
        } catch {
            keyIndex = KeyIndex()
            problems.append(T("keys.toml could not be read: %@. It was left as it is.", "\(error)"))
        }
        self.problems = problems
        unattendedSources = Set((vault?.entries ?? [:]).filter { $0.value.unattendedSealed != nil }.keys)
        usage = UsageSnapshot(files: files)
        providers = source.binary.map { CheckRunner.providers(binary: $0) }
        rotations = source.binary.map { CheckRunner.rotations(binary: $0, files: files) }
    }
}
