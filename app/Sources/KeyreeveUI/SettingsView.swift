import AppKit
import KeyreeveCatalog
import SwiftUI

/// Settings, in the standard window (Command-comma).
public struct SettingsView: View {
    @ObservedObject var model: AppModel
    @AppStorage(Language.settingsKey) private var language = Language.system.rawValue
    @AppStorage(SettingsKey.appearance) private var appearance = "system"
    @AppStorage(SettingsKey.lockMinutes) private var lockMinutes = 5
    @AppStorage(SettingsKey.scanOnOpen) private var scanOnOpen = true
    @AppStorage(SettingsKey.fingerprintMinutes) private var fingerprintMinutes = 5
    @State private var weekly = WeeklySchedule.isOn

    public init(model: AppModel) { self.model = model }

    public var body: some View {
        TabView {
            general.tabItem { Label(T("General"), systemImage: "gearshape") }
            providers.tabItem { Label(T("Providers"), systemImage: "puzzlepiece.extension") }
        }
        .frame(width: 520, height: 460)
        .id(language)
    }

    private var general: some View {
        Form {
            Section(T("General")) {
                Picker(T("Language"), selection: $language) {
                    Text(T("System")).tag(Language.system.rawValue)
                    Text("English").tag(Language.english.rawValue)
                    Text("Español").tag(Language.spanish.rawValue)
                }
                Picker(T("Appearance"), selection: $appearance) {
                    Text(T("System")).tag("system")
                    Text(T("Light")).tag("light")
                    Text(T("Dark")).tag("dark")
                }
                Picker(T("Lock after"), selection: $lockMinutes) {
                    ForEach([1, 5, 15, 60], id: \.self) { Text("\($0) \(T("minutes"))").tag($0) }
                }
                Toggle(T("Scan when opening"), isOn: $scanOnOpen)
            }
            Section {
                Picker(T("Ask for my fingerprint again after"), selection: $fingerprintMinutes) {
                    Text(T("Every time")).tag(0)
                    ForEach([1, 5, 15, 30], id: \.self) { Text("\($0) \(T("minutes"))").tag($0) }
                }
            } footer: {
                Text(T("While this lasts, the app can check keys without asking. Locking it ends the period, and the vault always asks."))
                    .font(.caption)
            }
            Section {
                Toggle(T("Weekly check"), isOn: $weekly)
                    .onChange(of: weekly) { WeeklySchedule.set(weekly, binary: model.commandURL) }
            } footer: {
                Text(T("Check keys set to Checked without asking every Monday, and notify me if one stops working. It needs no fingerprint, so it covers only those."))
                    .font(.caption)
            }
            Section(T("Files")) {
                LabeledContent(T("Folder")) {
                    HStack {
                        Text(model.keysFolder?.path ?? T("None"))
                            .lineLimit(1)
                            .truncationMode(.head)
                            .foregroundStyle(.secondary)
                        Button(T("Change"), action: model.chooseFolder)
                    }
                }
                Button(T("Show the app's files")) { NSWorkspace.shared.open(model.files.directory) }
            }
            Section(T("About")) {
                Text(T("Version %@", Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"))
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func providerLine(_ provider: ProviderInfo) -> String {
        if let problem = provider.problem { return problem }
        if let programs = provider.programs, !programs.isEmpty {
            return T("Runs %@", programs.joined(separator: ", "))
        }
        return T("Sent only to %@", provider.hosts.joined(separator: ", "))
    }

    /// A file that runs a program gets a plain warning, because this is the one thing that runs code.
    private func approve(_ provider: ProviderInfo) {
        guard let programs = provider.programs, !programs.isEmpty else {
            model.approve(provider)
            return
        }
        let alert = NSAlert()
        alert.messageText = T("This file runs programs on your Mac")
        alert.informativeText = T("Approve only if you wrote it or read it. Programs: %@", programs.joined(separator: ", "))
        alert.alertStyle = .warning
        alert.addButton(withTitle: T("Approve"))
        alert.addButton(withTitle: T("Cancel"))
        if alert.runModal() == .alertFirstButtonReturn { model.approve(provider) }
    }

    private var providers: some View {
        Form {
            Section {
                ForEach(model.providers.all) { provider in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(provider.name.isEmpty ? provider.id : provider.name)
                            Text(providerLine(provider))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                            Text(testedLine(provider))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if provider.needsApproval {
                            Button(T("Approve")) { approve(provider) }
                        } else if provider.source == "local" {
                            Text(T("Your file")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } footer: {
                Text(T("Your files can add more providers, in ~/.keyreeve/providers. Each one needs your approval before it receives a key."))
                    .font(.caption)
            }
        }
        .formStyle(.grouped)
    }

    private func testedLine(_ provider: ProviderInfo) -> String {
        if let date = provider.tested.rotate { return T("Rotated with a real key: %@", date) }
        if let date = provider.tested.check { return T("Tried with a real key: %@", date) }
        return T("Not tried with a real key yet")
    }
}
