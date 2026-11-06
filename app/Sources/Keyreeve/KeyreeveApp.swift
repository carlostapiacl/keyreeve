import AppKit
import KeyreeveCatalog
import KeyreeveUI
import LocalAuthentication
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var unlocked = false
    @Published var lockMessage: String?
    @Published var items: [CatalogItem] = []
    @Published var problem: String?
    @Published var checking = false
    @Published var message: String?
    @Published var activity: [ActivityItem] = []
    private let files = KeyreeveFiles()
    private var lockTask: Task<Void, Never>?

    static let lockDelay: Duration = .seconds(300)

    var catalogURL: URL { files.catalog }

    func check(_ chosen: [CatalogItem]) {
        guard !chosen.isEmpty, !checking else { return }
        guard let keys = keysFolder() else { return }
        guard let binary = Bundle.main.url(forAuxiliaryExecutable: "keyreeve-cli") else {
            message = "This app was built without the keyreeve command"
            return
        }
        if chosen.contains(where: { $0.level == "ask" }) {
            let count = chosen.count
            LAContext().evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "check \(count == 1 ? "1 key" : "\(count) keys") with their providers"
            ) { success, _ in
                Task { @MainActor in
                    if success {
                        self.runChecks(chosen, binary: binary, keys: keys)
                    } else {
                        self.message = "Not checked: the fingerprint was not confirmed"
                    }
                }
            }
        } else {
            runChecks(chosen, binary: binary, keys: keys)
        }
    }

    /// Scans the folder again, so what the window says matches the disk.
    func refresh() {
        guard !checking else { return }
        guard let keys = keysFolder() else { return }
        guard let binary = Bundle.main.url(forAuxiliaryExecutable: "keyreeve-cli") else {
            load()
            return
        }
        checking = true
        message = "Scanning…"
        let files = self.files
        Task.detached {
            let result = Result { try CheckRunner.refresh(binary: binary, keysFolder: keys, files: files) }
            await MainActor.run {
                self.checking = false
                self.load()
                switch result {
                case .success: self.message = "Up to date"
                case .failure(let error):
                    self.message = (error as? CheckError)?.description ?? "The scan did not finish"
                }
            }
        }
    }

    private func runChecks(_ chosen: [CatalogItem], binary: URL, keys: URL) {
        checking = true
        message = "Checking…"
        let files = self.files
        Task.detached {
            let result = Result { try CheckRunner.run(chosen, binary: binary, keysFolder: keys, files: files) }
            await MainActor.run {
                self.checking = false
                switch result {
                case .success:
                    self.load()
                    let checked = Set(chosen.map(\.path))
                    let done = self.items.filter { checked.contains($0.path) }
                    let works = done.filter { $0.lastResult == "works" }.count
                    self.message = "Checked \(chosen.count): \(works) work"
                case .failure(let error):
                    self.message = (error as? CheckError)?.description ?? "The check did not finish"
                }
            }
        }
    }

    /// The folder of key files. Asked once and remembered, so it is never stored in a repository.
    private func keysFolder() -> URL? {
        if let saved = files.keysFolder() { return saved }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.message = "Choose the folder that holds your key files"
        panel.prompt = "Choose"
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        try? files.saveKeysFolder(url)
        return url
    }

    /// This lock covers the window. The keys themselves are protected by the vault, which asks
    /// for a fingerprint on its own each time one is used.
    func unlock() {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            lockMessage = "This Mac has no way to confirm it is you."
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "open your key catalog") {
            success, _ in
            Task { @MainActor in
                if success {
                    self.lockMessage = nil
                    self.unlocked = true
                    self.load()
                } else {
                    self.lockMessage = "Not unlocked. Try again."
                }
            }
        }
    }

    func lock() {
        lockTask?.cancel()
        unlocked = false
        items = []
        message = nil
    }

    func load() {
        do {
            items = try CatalogParser.parse(String(contentsOf: catalogURL, encoding: .utf8))
            problem = items.isEmpty ? "The catalog is empty" : nil
            activity = files.activity()
        } catch CocoaError.fileReadNoSuchFile {
            problem = "There is no catalog yet"
        } catch {
            problem = "The catalog could not be read"
        }
    }

    func windowLostFocus() {
        lockTask?.cancel()
        lockTask = Task {
            try? await Task.sleep(for: Self.lockDelay)
            if !Task.isCancelled { self.lock() }
        }
    }

    func windowGotFocus() { lockTask?.cancel() }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// A window remembered on a display you are not looking at reads as an app that did not open.
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            guard let window = NSApp.windows.first(where: { $0.canBecomeMain }) else { return }
            let mouse = NSEvent.mouseLocation
            let screen = NSScreen.screens.first { $0.frame.contains(mouse) } ?? NSScreen.main
            if let visible = screen?.visibleFrame, !visible.intersects(window.frame) || screen != window.screen {
                let size = NSSize(
                    width: min(window.frame.width, visible.width), height: min(window.frame.height, visible.height))
                window.setFrame(
                    NSRect(
                        x: visible.midX - size.width / 2, y: visible.midY - size.height / 2,
                        width: size.width, height: size.height),
                    display: true)
            }
            window.makeKeyAndOrderFront(nil)
        }
    }

    /// With no window there is nothing to use, and a running app with no window looks broken.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct KeyreeveApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Keyreeve", id: "main") {
            Group {
                if !model.unlocked {
                    LockedView(message: model.lockMessage, unlock: model.unlock)
                        .onAppear(perform: model.unlock)
                } else if let problem = model.problem {
                    EmptyCatalogView(problem: problem, path: model.catalogURL.path)
                } else {
                    CatalogView(
                        items: model.items, source: model.catalogURL.path, reload: model.refresh,
                        check: model.check, checking: model.checking, message: model.message,
                        activity: model.activity)
                }
            }
            .frame(minWidth: 820, minHeight: 480)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                model.windowLostFocus()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.windowGotFocus()
            }
        }
        .defaultSize(width: 1180, height: 720)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Lock", action: model.lock).keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
    }
}
