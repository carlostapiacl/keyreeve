import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// What is open for a key right now, and who has used it.
struct KeyUsagePanel: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var showingAll = false

    private var identifiers: [KeyIndex.Key] { model.keyIndex.keys(forSource: item.path) }
    private var names: Set<String> { Set(identifiers.map(\.id)).union([item.path]) }
    private var grants: [KeyService.GrantInfo] { model.usage.grants.filter { names.contains($0.key) } }
    private var recent: [AuditLog.Entry] { Array(model.usage.entries.filter { names.contains($0.key) }.prefix(8)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !identifiers.isEmpty { permissions }
            Text(T("Recent use")).font(Theme.caption).foregroundStyle(Theme.muted).padding(.top, 6)
            if let line = model.usage.brokenLine {
                Text((line == 0 ? T("The usage log could not be read.") : T("The usage log was changed at line %d.", line)))
                    .font(Theme.caption).foregroundStyle(Theme.bad)
            }
            if recent.isEmpty {
                Text(T("Nothing has used this key yet.")).font(Theme.caption).foregroundStyle(Theme.muted)
            }
            ForEach(recent, id: \.hash) { UsageRow(entry: $0, showsKey: false) }
            Button(T("All use")) { showingAll = true }
                .buttonStyle(KRButtonStyle())
        }
        .onAppear { model.reloadUsage() }
        .onChange(of: item.path) { model.reloadUsage() }
        .sheet(isPresented: $showingAll) { UsageLogSheet(model: model) }
    }

    private var permissions: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(T("Permissions in force")).font(Theme.caption).foregroundStyle(Theme.muted).padding(.top, 6)
            if grants.isEmpty {
                Text(T("No permission is open for this key.")).font(Theme.caption).foregroundStyle(Theme.muted)
            }
            ForEach(grants, id: \.id) { grant in
                HStack(spacing: 6) {
                    Text(grant.program).font(Theme.code).foregroundStyle(Theme.text).lineLimit(1)
                    Text(T("%dm left", max(0, Int(grant.expires.timeIntervalSinceNow) / 60)))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                    Spacer(minLength: 4)
                    Button(T("End")) { model.endPermissions(of: grant.key) }
                        .buttonStyle(KRButtonStyle())
                }
            }
            ForEach(identifiers) { key in giveMenu(for: key) }
        }
    }

    @ViewBuilder private func giveMenu(for key: KeyIndex.Key) -> some View {
        let programs = model.agentPolicy.commands[key.id] ?? []
        if key.provider == KeyService.sshProvider {
            Menu(T("Give a permission")) { durations(key: key, program: nil) }
                .fixedSize()
        } else if programs.isEmpty {
            Text(T("Allow a program first, so a permission can name it."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Menu(T("Give a permission")) {
                ForEach(programs, id: \.self) { program in
                    Menu(URL(fileURLWithPath: program).lastPathComponent) { durations(key: key, program: program) }
                }
            }
            .fixedSize()
        }
    }

    @ViewBuilder private func durations(key: KeyIndex.Key, program: String?) -> some View {
        Button(T("15 minutes")) { model.grant(key, program: program, duration: "15m") }
        Button(T("1 hour")) { model.grant(key, program: program, duration: "1h") }
        Button(T("8 hours")) { model.grant(key, program: program, duration: "8h") }
    }
}

/// One line of the log. What the system saw comes first, and what the caller says about itself after.
struct UsageRow: View {
    let entry: AuditLog.Entry
    let showsKey: Bool

    static func label(of event: String) -> String {
        switch event {
        case "granted": return T("Permission given")
        case "used": return T("Used")
        case "denied": return T("Finger said no")
        case "refused": return T("Refused")
        case "handed": return T("Real key handed over")
        case "closed": return T("Permission ended")
        case "request": return T("Request sent")
        case "signed": return T("Signed in")
        case "server": return T("Server allowed")
        case "sealed": return T("Sealed")
        case "rotated": return T("Rotated")
        case "copied": return T("Copied")
        default: return event
        }
    }

    private var who: String {
        [
            entry.observed?.chain.prefix(3).joined(separator: " < "),
            entry.declared?.agent, entry.declared?.reason, entry.detail,
        ]
        .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 6) {
                Text(Self.label(of: entry.event)).font(Theme.caption).foregroundStyle(Theme.text)
                if showsKey { Text(entry.key).font(Theme.code).foregroundStyle(Theme.muted).lineLimit(1) }
                Spacer(minLength: 4)
                Text(entry.at, format: .dateTime.day().month().hour().minute())
                    .font(Theme.caption).foregroundStyle(Theme.faint)
            }
            if !who.isEmpty {
                Text(who).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
    }
}

/// The whole log, with the broken-chain warning where it can be seen.
struct UsageLogSheet: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var filter = ""

    private var shown: [AuditLog.Entry] {
        filter.isEmpty ? model.usage.entries : model.usage.entries.filter { $0.key.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(T("Usage log")).font(.headline).foregroundStyle(Theme.text)
                Spacer()
                TextField(T("Filter by key"), text: $filter).textFieldStyle(.roundedBorder).frame(maxWidth: 200)
                Button(T("Close")) { dismiss() }.buttonStyle(KRButtonStyle())
            }
            if let line = model.usage.brokenLine {
                Text((line == 0 ? T("The usage log could not be read.") : T("The usage log was changed at line %d.", line))).font(Theme.caption).foregroundStyle(Theme.bad)
            }
            List(shown, id: \.hash) { UsageRow(entry: $0, showsKey: true) }
        }
        .padding(16)
        .frame(minWidth: 560, minHeight: 420)
        .onAppear { model.reloadUsage() }
    }
}
