import AppKit
import KeyreeveCatalog
import SwiftUI

/// One key's details, which can be edited here. It never holds a value.
struct KeyDetail: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var newTag = ""
    @State private var name = ""
    @State private var note = ""
    @State private var confirmArchive = false
    @State private var host = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if let attention = item.attention {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(attention, systemImage: "exclamationmark.triangle.fill")
                            .font(Theme.body).foregroundStyle(Theme.warn)
                            .fixedSize(horizontal: false, vertical: true)
                        ActionButtons(item: item, model: model)
                    }
                }
                checkButton
                if item.vault != .none { vaultNote }
                if item.vault == .sealed || item.vault == .outdated { KeyAccessPanel(item: item, model: model) }
                if model.hasVault, item.isSecret, !item.isArchived { RotationPanel(item: item, model: model) }
                customActions
                identity
                naming
                criticality
                if item.isSecret { checkPlace }
                fact(T("Who can use it")) {
                    Picker("", selection: levelBinding) {
                        Text(T("Agents can use it")).tag("free")
                        Text(T("Ask me each time")).tag("ask")
                        Text(T("Only me")).tag("never")
                        Text(T("Not secret")).tag("none")
                    }
                    .labelsHidden()
                }
                fact(T("Tags")) { tagEditor }
                fileFacts
                archiveButton
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.surface)
        .onAppear(perform: syncFields)
        .onChange(of: item.path) { syncFields() }
        .confirmationDialog(
            T("Archive this key"), isPresented: $confirmArchive, titleVisibility: .visible
        ) {
            Button(T("Archive anyway"), role: .destructive) { model.archive(item) }
            Button(T("Cancel"), role: .cancel) {}
        } message: {
            Text(T("Archiving hides it from your lists. It does not stop it: this key still works."))
        }
    }

    private var vaultNoteText: String {
        switch item.vault {
        case .sealed: return "In the vault. Checks use the sealed copy."
        case .otherFolder: return "Sealed from another folder. Checks use this folder's file."
        default: return "The file changed after it was sealed. Checks use the file."
        }
    }

    private var vaultNote: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(
                T(vaultNoteText),
                systemImage: "lock.shield"
            )
            .font(Theme.caption)
            .foregroundStyle(item.vault == .sealed ? Theme.muted : Theme.warn)
            .fixedSize(horizontal: false, vertical: true)
            if item.vault == .outdated {
                Button(T("Seal it again")) { model.sealAgain([item]) }
                    .buttonStyle(KRButtonStyle())
                    .disabled(model.busy)
            }
        }
    }

    /// Tests this one key. A key with no place to check says why, instead of hiding the button.
    @ViewBuilder private var checkButton: some View {
        VStack(alignment: .leading, spacing: 5) {
            Button {
                model.check([item])
            } label: {
                Label(T("Check this key"), systemImage: "checkmark.shield")
            }
            .buttonStyle(KRButtonStyle(primary: item.attention == nil))
            .disabled(model.busy || !model.providers.canCheck(item))
            if let likely = model.providers.likelyProvider(of: item) {
                Button(T("Check it with %@", likely.name)) {
                    model.save(KeyEdit(tags: item.tags, recipes: [likely.id]), for: item)
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .disabled(model.busy)
                .help(T("The key is sent to this company to check it. Choose only the company it belongs to."))
            } else if let why = item.whyNoCheck {
                Text(why).font(Theme.caption).foregroundStyle(Theme.muted)
            } else if model.providers.needsHost(item) {
                Text(T("Add your server's address first")).font(Theme.caption).foregroundStyle(Theme.muted)
            }
        }
    }

    private var criticality: some View {
        fact(T("Criticality")) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 4) {
                    ForEach(1...5, id: \.self) { step in
                        Button {
                            model.save(KeyEdit(criticality: step), for: item)
                        } label: {
                            Text("\(step)")
                                .font(.system(size: 12, weight: .medium))
                                .monospacedDigit()
                                .foregroundStyle(chosen(step) ? Theme.onAccent : Theme.text)
                                .frame(width: 30, height: 24)
                                .background(
                                    chosen(step) ? Theme.accent : Theme.raised,
                                    in: RoundedRectangle(cornerRadius: Theme.smallRadius))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help(criticalityName(step))
                    }
                }
                Text(
                    item.criticality == 0
                        ? T("How bad would a leak be?")
                        : criticalityName(item.criticality)
                            + (item.criticalitySuggested ? ". \(T("Suggested by the provider's file"))" : "")
                )
                .font(Theme.caption)
                    .foregroundStyle(Theme.muted)
            }
        }
    }

    private func chosen(_ step: Int) -> Bool { step == item.criticality && !item.criticalitySuggested }

    private func syncFields() {
        name = item.name
        note = item.description
        host = item.host
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(item.title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                .textSelection(.enabled)
            Text(item.path).font(Theme.code).foregroundStyle(Theme.faint).textSelection(.enabled)
            HStack(spacing: 6) {
                ResultBadge(item: item)
                if item.criticality > 0 {
                    CriticalityMeter(value: item.criticality, suggested: item.criticalitySuggested)
                }
                if !item.lastChecked.isEmpty {
                    Text(item.lastChecked).font(Theme.caption).foregroundStyle(Theme.faint).monospacedDigit()
                }
            }
            .padding(.top, 4)
            if !item.lastReason.isEmpty {
                Text(item.lastReason).font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder private var customActions: some View {
        let list = model.providers.customActions(for: item)
        if !list.isEmpty {
            fact(T("Your actions")) {
                FlowRow(spacing: 6) {
                    ForEach(list, id: \.action.id) { entry in
                        Button(entry.action.title) { model.run(entry.action, provider: entry.provider, on: item) }
                            .buttonStyle(KRButtonStyle())
                            .disabled(model.busy)
                    }
                }
            }
        }
    }

    @ViewBuilder private var identity: some View {
        if let details = item.details {
            fact(T("From the provider")) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(details.fields.sorted { $0.key < $1.key }, id: \.key) { field in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(field.key).font(Theme.caption).foregroundStyle(Theme.faint).frame(width: 56, alignment: .leading)
                            Text(field.value).font(Theme.body).foregroundStyle(Theme.text).lineLimit(2).textSelection(.enabled)
                        }
                    }
                    if let suggested = details.suggested_name, suggested != item.name {
                        Button(T("Use") + " “\(suggested)”") {
                            model.save(KeyEdit(name: suggested), for: item)
                            name = suggested
                        }
                        .buttonStyle(KRButtonStyle())
                        .padding(.top, 4)
                    }
                }
            }
        } else if model.providers.canIdentify(item) {
            Button {
                model.identify([item])
            } label: {
                Label(T("Identify"), systemImage: "person.text.rectangle")
            }
            .buttonStyle(KRButtonStyle())
            .disabled(model.busy)
        }
    }

    private var naming: some View {
        VStack(alignment: .leading, spacing: 12) {
            fact(T("Name")) {
                TextField(T("Give it a name"), text: $name)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.save(KeyEdit(name: name), for: item) }
            }
            fact(T("Description")) {
                TextField(T("Add a note about this key"), text: $note, axis: .vertical)
                    .lineLimit(2...4)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.save(KeyEdit(description: note), for: item) }
            }
        }
    }

    private var levelBinding: Binding<String> {
        Binding(get: { item.level }, set: { model.save(KeyEdit(level: $0), for: item) })
    }

    /// One provider, or several set by hand elsewhere, which stay until someone changes them.
    private var recipeBinding: Binding<String> {
        Binding(
            get: { item.isInternal ? internalChoice : item.recipes.joined(separator: " ") },
            set: { value in
                let tags = item.tags.filter { $0 != "internal" }
                if value == internalChoice {
                    model.save(KeyEdit(tags: tags + ["internal"], recipes: []), for: item)
                } else {
                    model.save(KeyEdit(tags: tags, recipes: value.split(separator: " ").map(String.init)), for: item)
                }
            })
    }

    private let internalChoice = "__internal__"

    private var isSelfHosted: Bool {
        item.recipes.contains { id in model.providers.all.contains { $0.id == id && $0.self_hosted } }
    }

    @ViewBuilder private var checkPlace: some View {
        fact(T("Where to check")) {
            VStack(alignment: .leading, spacing: 6) {
                Picker("", selection: recipeBinding) {
                    Text(T("Nobody")).tag("")
                    Text(T("Internal secret, no provider")).tag(internalChoice)
                    Divider()
                    ForEach(model.providers.usable) { Text($0.name).tag($0.id) }
                    if item.recipes.count > 1 {
                        Text(item.recipes.map(model.providers.name(of:)).joined(separator: ", "))
                            .tag(item.recipes.joined(separator: " "))
                    }
                }
                .labelsHidden()
                Text(T("The key is sent to this company to check it. Choose only the company it belongs to."))
                    .font(Theme.caption)
                    .foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        if isSelfHosted {
            fact(T("Server address")) {
                VStack(alignment: .leading, spacing: 6) {
                    TextField("panel.example.com", text: $host)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { model.setHost(host, on: item) }
                    Text(T("Sets the server this key is sent to. It must offer HTTPS."))
                        .font(Theme.caption)
                        .foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        if !item.recipes.isEmpty && !item.labels.isEmpty {
            fact(T("Field that holds the key")) {
                Picker(
                    "",
                    selection: Binding(
                        get: { item.field },
                        set: { model.save(KeyEdit(field: $0), for: item) })
                ) {
                    Text(T("None")).tag("")
                    ForEach(item.labels, id: \.self) { Text($0).tag($0) }
                    if !item.field.isEmpty && !item.labels.contains(item.field) {
                        Text(item.field).tag(item.field)
                    }
                }
                .labelsHidden()
            }
        }
    }

    private var tagEditor: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(item.tags.filter { !$0.hasPrefix("kind:") }, id: \.self) { tag in
                HStack(spacing: 4) {
                    Chip(text: tag)
                    Spacer()
                    Button {
                        model.save(KeyEdit(tags: item.tags.filter { $0 != tag }), for: item)
                    } label: {
                        Image(systemName: "xmark").imageScale(.small).foregroundStyle(Theme.faint)
                    }
                    .buttonStyle(.plain)
                    .help(T("Remove %@", tag))
                }
            }
            TextField(T("Add a tag"), text: $newTag)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    let tag = newTag.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "-")
                    newTag = ""
                    guard !tag.isEmpty, !item.tags.contains(tag) else { return }
                    model.save(KeyEdit(tags: item.tags + [tag]), for: item)
                }
        }
    }

    private var fileFacts: some View {
        HStack(alignment: .top, spacing: 18) {
            fact(T("File changed")) { Text(item.modified).font(Theme.caption).monospacedDigit() }
            if !item.format.isEmpty { fact(T("Format")) { Text(item.format).font(Theme.caption) } }
            fact(T("Permissions")) { Text(item.mode).font(Theme.caption).monospacedDigit() }
        }
    }

    @ViewBuilder private var archiveButton: some View {
        if item.isArchived {
            Button(T("Restore")) { model.restore(item) }.buttonStyle(KRButtonStyle())
        } else {
            Button(T("Archive this key")) {
                if item.lastResult == "works" { confirmArchive = true } else { model.archive(item) }
            }
            .buttonStyle(KRButtonStyle())
        }
    }

    private func fact<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(Theme.caption).foregroundStyle(Theme.muted)
            content()
        }
    }
}

struct ActionButtons: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    var body: some View {
        let list = model.actionsFor(item)
        FlowRow(spacing: 6) {
            ForEach(list, id: \.self) { action in
                Button(action.title) { model.perform(action, on: item) }
                    .buttonStyle(KRButtonStyle(primary: action == list.first && action != .ignore))
                    .disabled(model.busy)
            }
        }
    }
}
