import AppKit
import KeyreeveCatalog
import KeyreeveUI
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// A window remembered on a display you are not looking at reads as an app that did not open.
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Writing to a command that already ended must be an error to handle, not a signal that ends the
        // app. Set once here, for the whole process, rather than by each call.
        signal(SIGPIPE, SIG_IGN)
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

    /// Keyreeve stays in the menu bar with no window, since what agents were allowed lasts while it runs.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// With its window closed it lives in the menu bar alone, out of the Dock.
    func applicationDidUpdate(_ notification: Notification) {
        let hasWindow = NSApp.windows.contains { $0.isVisible && $0.canBecomeMain }
        let policy: NSApplication.ActivationPolicy = hasWindow ? .regular : .accessory
        if NSApp.activationPolicy() != policy { NSApp.setActivationPolicy(policy) }
    }

    /// Clicking the app again, in Finder or with open, brings the window back.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { true }
}

@main
struct KeyreeveApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.openWindow) private var openWindow
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
                } else if model.needsWelcome {
                    WelcomeView(
                        busy: model.busy, choose: model.chooseFolder, withoutFolder: model.startWithoutFolder,
                        bringIn: model.startBringIn)
                } else {
                    // With no vault yet, it opens where one is made, which a first key needs.
                    MainView(model: model, initial: model.hasVault ? .home : .vault)
                }
            }
            .frame(minWidth: 860, minHeight: 520)
            // Here and not in the list, so a first key can be pasted before any folder is chosen.
            .sheet(item: Binding(
                get: { model.unlocked ? model.addingKey : nil },
                set: { if $0 == nil { model.cancelAddingKey() } })
            ) { _ in AddKeySheet(model: model) }
            .sheet(isPresented: Binding(
                get: { model.unlocked && model.bringing != nil },
                set: { if !$0 { model.cancelBringIn() } })
            ) { BringSheet(model: model) }
            .id(language)
            .environment(\.locale, chosenLocale)
            .preferredColorScheme(scheme)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                model.windowLostFocus()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.windowGotFocus()
            }
            // What agents were allowed ends when the app does.
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                model.closeServicePermissionsBeforeQuitting()
            }
        }
        .defaultSize(width: 1180, height: 720)
        .commands {
            CommandGroup(after: .newItem) {
                Button(T("Bring in keys…"), action: model.startBringIn)
                    .disabled(!model.unlocked)
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

        MenuBarExtra {
            MenuBarView(model: model) {
                NSApp.setActivationPolicy(.regular)
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            .environment(\.locale, chosenLocale)
            .preferredColorScheme(scheme)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(model: model)
                .environment(\.locale, chosenLocale)
                .preferredColorScheme(scheme)
        }
    }
}
