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
    private var lockTask: Task<Void, Never>?

    static let lockDelay: Duration = .seconds(300)

    var catalogURL: URL {
        if let custom = ProcessInfo.processInfo.environment["KEYREEVE_CATALOG"] {
            return URL(fileURLWithPath: custom)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".keyreeve/catalog.csv")
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
    }

    func load() {
        do {
            items = try CatalogParser.parse(String(contentsOf: catalogURL, encoding: .utf8))
            problem = items.isEmpty ? "The catalog is empty" : nil
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

@main
struct KeyreeveApp: App {
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
                    CatalogView(items: model.items, source: model.catalogURL.path, reload: model.load)
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
