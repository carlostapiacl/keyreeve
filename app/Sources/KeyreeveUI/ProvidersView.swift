import AppKit
import KeyreeveCatalog
import SwiftUI

/// Approving a provider file. One that runs a program gets a plain warning first, since that is the one
/// thing here that runs code. Used here and in Settings.
@MainActor
func approveProvider(_ provider: ProviderInfo, model: AppModel) {
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

/// The providers keyreeve knows: the ones it ships and your own, what each may receive and whether it is
/// approved. New ones are made here, by describing them to an assistant or by writing the file.
struct ProvidersView: View {
    @ObservedObject var model: AppModel
    @State private var building: ProviderBuilder?

    private var own: [ProviderInfo] { model.providers.all.filter { $0.source == "local" } }
    private var shipped: [ProviderInfo] { model.providers.all.filter { $0.source != "local" } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text(T("A provider file says where a key may be sent and how to check it. keyreeve ships some, and you can add your own for any service, yours too."))
                        .font(Theme.body).foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 12)
                    Button {
                        building = ProviderBuilder(model: model)
                    } label: {
                        Label(T("New provider"), systemImage: "plus")
                    }
                    .buttonStyle(KRButtonStyle(primary: true))
                }
                Card {
                    VStack(alignment: .leading, spacing: 0) {
                        SectionTitle(T("Yours")).padding(.bottom, 8)
                        if own.isEmpty {
                            Text(T("None yet. Add one with New provider."))
                                .font(Theme.caption).foregroundStyle(Theme.muted)
                        }
                        ForEach(own) { provider in
                            row(provider)
                            if provider.id != own.last?.id { Divider().padding(.vertical, 6) }
                        }
                    }
                    .padding(14)
                }
                Card {
                    VStack(alignment: .leading, spacing: 0) {
                        SectionTitle(T("Shipped with keyreeve")).padding(.bottom, 8)
                        ForEach(shipped) { provider in
                            row(provider)
                            if provider.id != shipped.last?.id { Divider().padding(.vertical, 6) }
                        }
                    }
                    .padding(14)
                }
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .sheet(item: Binding(get: { building.map(BuilderBox.init) }, set: { if $0 == nil { building = nil } })) { box in
            ProviderBuilderView(model: model, builder: box.builder) { building = nil }
        }
    }

    private func row(_ provider: ProviderInfo) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(provider.name.isEmpty ? provider.id : provider.name).font(Theme.rowTitle).foregroundStyle(Theme.text)
                Text(line(provider)).font(Theme.caption).foregroundStyle(provider.problem == nil ? Theme.muted : Theme.bad)
                    .lineLimit(2)
                Text(state(provider)).font(Theme.caption).foregroundStyle(provider.needsApproval ? Theme.warn : Theme.muted)
            }
            Spacer(minLength: 8)
            if provider.needsApproval {
                Button(T("Approve")) { approveProvider(provider, model: model) }.buttonStyle(KRButtonStyle(primary: true))
            }
            if provider.source == "local" {
                Button(T("Edit")) {
                    let builder = ProviderBuilder(model: model)
                    let folder = model.files.directory.appendingPathComponent("providers")
                    builder.edit(ProviderBuilder.ownFile(provider.id, in: folder) ?? "", id: provider.id)
                    building = builder
                }
                .buttonStyle(KRButtonStyle())
            } else {
                Button(T("Make one of mine from it")) {
                    let builder = ProviderBuilder(model: model)
                    builder.start(from: provider)
                    building = builder
                }
                .buttonStyle(KRButtonStyle())
                .help(T("Starts a file of yours with its name, hosts and page. A shipped file cannot be changed."))
            }
        }
    }

    private func line(_ provider: ProviderInfo) -> String {
        if let problem = provider.problem { return problem }
        if let programs = provider.programs, !programs.isEmpty { return T("Runs %@", programs.joined(separator: ", ")) }
        return T("Sent only to %@", provider.hosts.joined(separator: ", "))
    }

    private func state(_ provider: ProviderInfo) -> String {
        if provider.problem != nil { return T("Has a problem, so it receives nothing") }
        if provider.needsApproval { return T("Waiting for your approval") }
        if provider.source == "local" { return T("Your file, approved") }
        if let date = provider.tested.check { return T("Tried with a real key: %@", date) }
        return T("Not tried with a real key yet")
    }
}

/// Identifiable wrapper so a builder can drive a sheet.
private struct BuilderBox: Identifiable {
    let builder: ProviderBuilder
    var id: ObjectIdentifier { ObjectIdentifier(builder) }
}

/// The sheet: basic use first, advanced one click away, and the same check, summary and save for both.
struct ProviderBuilderView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var builder: ProviderBuilder
    let close: () -> Void
    @AppStorage(AssistantChoice.consentKey) private var consented = false
    @State private var assistant: Assistant? = AssistantChoice.current(available: Assistants.available())

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(builder.editing.map { T("Edit %@", $0) } ?? T("New provider")).font(Theme.title).foregroundStyle(Theme.text)
                Spacer()
                Picker("", selection: $builder.advanced) {
                    Text(T("Basic")).tag(false)
                    Text(T("Advanced")).tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if builder.advanced { advanced } else { basic }
                    outcome
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Button(T("Validate")) { builder.check() }.buttonStyle(KRButtonStyle())
                    .disabled(builder.yaml.isEmpty || builder.phase == .asking)
                Spacer()
                Button(T("Close"), action: close).buttonStyle(KRButtonStyle()).keyboardShortcut(.cancelAction)
                Button(T("Save")) {
                    if builder.saveNow() != nil { model.load() }
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .disabled(builder.yaml.isEmpty || builder.phase == .asking)
            }
        }
        .padding(24)
        .frame(width: 680, height: 640)
        .background(Theme.background)
    }

    // MARK: Basic

    @ViewBuilder private var basic: some View {
        Text(T("Say which service it is, in your words. An assistant you use in your terminal drafts the file, and keyreeve checks it before you save it."))
            .font(Theme.body).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
        TextField(T("For example: my Coolify panel at coolify.example.com"), text: $builder.description, axis: .vertical)
            .textFieldStyle(.roundedBorder).lineLimit(2...4)
        if let offered = builder.offered {
            HStack {
                Label(T("keyreeve already knows %@. Use it instead: choose it as the provider of your keys.", offered.name.isEmpty ? offered.id : offered.name), systemImage: "checkmark.seal")
                    .font(Theme.body).foregroundStyle(Theme.good).fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button(T("Draft a new one anyway")) {
                    builder.offered = nil
                    if let assistant { builder.ask(assistant) }
                }
                .buttonStyle(KRButtonStyle())
            }
        }
        if let assistant {
            if !consented {
                Text(T("What you write here goes to %@, with your account. Never a key.", assistant.name))
                    .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if builder.phase == .asking {
                    ProgressView().controlSize(.small)
                    Text(T("%@ is writing it. It can take a minute.", assistant.name)).font(Theme.caption).foregroundStyle(Theme.muted)
                    Spacer()
                    Button(T("Cancel")) { builder.cancel() }.buttonStyle(KRButtonStyle())
                } else {
                    Button(T("Ask %@", assistant.name)) {
                        consented = true
                        if !builder.lookForExisting(in: model.providers) { builder.ask(assistant) }
                    }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(builder.description.trimmingCharacters(in: .whitespaces).isEmpty)
                    Spacer()
                }
            }
        } else {
            Text(T("No assistant is chosen. Choose the one you use in Settings, or write the file in Advanced."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
            HStack {
                SettingsLink { Text(T("Open Settings")) }.buttonStyle(KRButtonStyle())
                Button(T("Write it in Advanced")) { builder.advanced = true }.buttonStyle(KRButtonStyle())
            }
        }
        if !builder.yaml.isEmpty { summaryCard }
    }

    // MARK: Advanced

    @ViewBuilder private var advanced: some View {
        Text(T("The whole file. Each part is explained below; only provider, hosts, auth and verify are needed."))
            .font(Theme.body).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
        TextEditor(text: $builder.yaml)
            .font(Theme.code)
            .frame(minHeight: 220)
            .scrollContentBackground(.hidden)
            .padding(6)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.smallRadius))
            .overlay(RoundedRectangle(cornerRadius: Theme.smallRadius).strokeBorder(Theme.border))
        guide(RecipeSpec.fields.filter(\.basic))
        DisclosureGroup(T("More parts: identify, rotation, actions")) { guide(RecipeSpec.fields.filter { !$0.basic }) }
            .font(Theme.body)
    }

    private func guide(_ fields: [RecipeSpec.Field]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(fields) { field in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(field.path).font(Theme.code).foregroundStyle(Theme.text).frame(width: 150, alignment: .leading)
                    Text(T(field.help)).font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(.top, 4)
    }

    // MARK: Outcome

    private var summaryCard: some View {
        let summary = builder.summary
        return VStack(alignment: .leading, spacing: 4) {
            Text(summary.name ?? summary.provider ?? T("Provider")).font(Theme.rowTitle).foregroundStyle(Theme.text)
            Text(T("The key may go only to: %@", summary.hosts.isEmpty ? "-" : summary.hosts.joined(separator: ", ")))
            Text(T("It travels as: %@", summary.auth ?? "-"))
            Text(T("To check it, keyreeve asks: %@", summary.verify ?? "-"))
            if summary.rotates { Text(T("It can also make a new key and revoke the old one.")) }
            if summary.runsPrograms { Text(T("It runs programs on your Mac, which you approve.")).foregroundStyle(Theme.warn) }
        }
        .font(Theme.caption).foregroundStyle(Theme.muted)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.smallRadius))
    }

    @ViewBuilder private var outcome: some View {
        switch builder.phase {
        case .failed(let why):
            Label(why, systemImage: "exclamationmark.triangle.fill").font(Theme.body).foregroundStyle(Theme.bad)
                .fixedSize(horizontal: false, vertical: true)
        case .ready:
            Label(T("keyreeve checked it: it is valid."), systemImage: "checkmark.circle.fill").font(Theme.body).foregroundStyle(Theme.good)
        case .saved(let id):
            VStack(alignment: .leading, spacing: 6) {
                Label(T("%@ is saved among your providers.", id), systemImage: "checkmark.circle.fill").font(Theme.body).foregroundStyle(Theme.good)
                if let saved = model.providers.all.first(where: { $0.id == id }), saved.needsApproval {
                    HStack {
                        Text(T("It receives no key until you approve it.")).font(Theme.caption).foregroundStyle(Theme.muted)
                        Button(T("Approve")) { approveProvider(saved, model: model) }.buttonStyle(KRButtonStyle(primary: true))
                    }
                }
            }
        case .writing, .asking:
            EmptyView()
        }
        if let report = builder.report, !report.lines.isEmpty, builder.advanced {
            Text(report.lines.joined(separator: "\n")).font(Theme.code).foregroundStyle(Theme.muted)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
}
