import AppKit
import KeyreeveCatalog
import KeyreeveUI
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// A window remembered on a display you are not looking at reads as an app that did not open.
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            guard let window = NSApp.windows.first(where: { $0.canBecomeMain }) else { return }
            let mouse = NSEvent.mouseLocation
            let screen = NSScreen.screens.first { $0.frame.contains(mouse) } ?? NSScreen.main
            if let visible = screen?.visibleFrame, screen != window.screen {
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
    @AppStorage(Language.settingsKey) private var language = Language.system.rawValue
    @AppStorage(SettingsKey.appearance) private var appearance = "system"

    private var scheme: ColorScheme? {
        appearance == "light" ? .light : appearance == "dark" ? .dark : nil
    }

    private var chosenLocale: Locale { (Language(rawValue: language) ?? .system).locale }

    var body: some Scene {
        Window("Keyreeve", id: "main") {
            Group {
                if !model.unlocked {
                    LockedView(message: model.lockMessage, unlock: model.unlock)
                        .onAppear(perform: model.unlock)
                } else if !model.hasCatalog || model.items.isEmpty {
                    WelcomeView(busy: model.busy, choose: model.chooseFolder)
                } else {
                    MainView(model: model)
                }
            }
            .frame(minWidth: 860, minHeight: 520)
            .id(language)
            .environment(\.locale, chosenLocale)
            .preferredColorScheme(scheme)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                model.windowLostFocus()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.windowGotFocus()
            }
        }
        .defaultSize(width: 1180, height: 720)
        .commands {
            CommandGroup(after: .newItem) {
                Button(T("Choose folder…"), action: model.chooseFolder)
                Button(T("Scan folder"), action: model.refresh)
                    .keyboardShortcut("r")
                    .disabled(!model.unlocked)
            }
            CommandGroup(after: .appInfo) {
                Button(T("Lock now"), action: model.lock).keyboardShortcut("l", modifiers: [.command, .shift])
            }
            CommandGroup(replacing: .help) {
                Button(T("Keyreeve Help")) {
                    if let url = URL(string: "https://github.com/carlostapiacl/keyreeve#readme") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }

        Settings {
            SettingsView(model: model)
                .environment(\.locale, chosenLocale)
                .preferredColorScheme(scheme)
        }
    }
}
