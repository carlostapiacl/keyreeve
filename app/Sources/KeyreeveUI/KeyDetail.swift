import AppKit
import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// One key's details, which can be edited here. It never holds a value. Four tabs, each a question: how is
/// it, how is it used, how is it kept, what happened. The technical parts sit behind a disclosure.
struct KeyDetail: View {
    enum Tab: Hashable { case summary, use, security, history }

    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var newTag = ""
    @State private var name = ""
    @State private var note = ""
    @State private var confirmArchive = false
    @State private var confirmHost = false
    @State private var host = ""
    @State private var expires = ""
    @State private var tab: Tab = .summary
    @State private var showsMore = false

    private var isSealed: Bool { item.vault == .sealed || item.vault == .outdated }
    private var identifiers: [KeyIndex.Key] { model.keyIndex.allKeys(forSource: item.path) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                header
                ArrivalBanner(item: item, model: model)
                Picker(T("Part of the key"), selection: $tab) {
                    Text(T("Summary")).tag(Tab.summary)
                    Text(T("Usage")).tag(Tab.use)
                    Text(T("Security")).tag(Tab.security)
                    Text(T("History")).tag(Tab.history)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            .padding(.horizontal, 18)
            .padding(.top, 18)
            .padding(.bottom, 12)
            Rectangle().fill(Theme.border).frame(height: 1)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    switch tab {
                    case .summary: summary
                    case .use: use
                    case .security: security
                    case .history: history
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
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
        .confirmationDialog(
            T("Approve %@?", model.providers.unapprovedHost(of: item)?.host ?? ""), isPresented: $confirmHost,
            titleVisibility: .visible
        ) {
            Button(T("Approve and check")) { model.approveHostAndCheck(item) }
            Button(T("Cancel"), role: .cancel) {}
        } message: {
            Text(T("The key will be sent to %@ to check it, now and every time after. Approve it only if it is your server.",
                   model.providers.unapprovedHost(of: item)?.host ?? ""))
        }
    }

    /// A server that came as a suggestion waits for you: the key goes nowhere until you approve it.
    @ViewBuilder private var hostWaiting: some View {
        if let waiting = model.providers.unapprovedHost(of: item) {
            VStack(alignment: .leading, spacing: 8) {
                Label(T("%@ is not approved yet, so this key is not checked there.", waiting.host), systemImage: "server.rack")
                    .font(Theme.body).foregroundStyle(Theme.warn)
                    .fixedSize(horizontal: false, vertical: true)
                Button(T("Approve %@ and check", waiting.host)) { confirmHost = true }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(model.busy)
            }
        }
    }

    // MARK: Tabs

    @ViewBuilder private var summary: some View {
        if !item.description.isEmpty {
            Text(item.description).font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
        }
        if item.needsField { fieldChoice }
        hostWaiting
        if item.holdsSeveralKeys {
            VStack(alignment: .leading, spacing: 8) {
                Text(T("Several keys of this provider share this file, so keyreeve cannot tell which to check."))
                    .font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
                Button(T("Split into one file per key")) { model.split(item) }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .help(T("Each key gets its own file beside this one. This file moves to keyreeve's originals folder."))
            }
        }
        if let others = model.summary.sameAccount[item.path], !others.isEmpty {
            Label(T("Same account as %@. It may be the same key: keep one and archive the other.", others.joined(separator: ", ")),
                  systemImage: "square.on.square")
                .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
        }
        if let attention = item.attention, !item.needsField, !item.holdsSeveralKeys {
            VStack(alignment: .leading, spacing: 8) {
                Label(attention, systemImage: "exclamationmark.triangle.fill")
                    .font(Theme.body).foregroundStyle(Theme.warn)
                    .fixedSize(horizontal: false, vertical: true)
                ActionButtons(item: item, model: model)
            }
        }
        HStack(alignment: .top, spacing: 12) {
            box(T("Status")) {
                Label(statusText, systemImage: statusIcon).font(Theme.rowTitle).foregroundStyle(statusColor)
                // The two reasons above already say this in the person's words, with what to do.
                if !item.lastReason.isEmpty && !item.needsField && !item.holdsSeveralKeys {
                    Text(item.lastReason).font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                }
            }
            box(T("Where it is")) {
                Text(isSealed ? T("Sealed in the vault") : T("Only in its file")).font(Theme.rowTitle).foregroundStyle(Theme.text)
                if isSealed && !item.originalMoved {
                    Text(T("The original file is still in the folder")).font(Theme.caption).foregroundStyle(Theme.warn)
                } else if !isSealed {
                    Button(T("See Security")) { tab = .security }.buttonStyle(.link).font(Theme.caption)
                }
            }
        }
        checkButton
        agentsLine
        DisclosureGroup(isExpanded: $showsMore) {
            VStack(alignment: .leading, spacing: 16) {
                naming
                customActions
                identity
                criticality
                if item.isSecret { checkPlace }
                fact(T("Automatic checks")) {
                    Picker("", selection: levelBinding) {
                        Text(T("Checked without asking")).tag("free")
                        Text(T("Ask me each time")).tag("ask")
                        Text(T("Only me")).tag("never")
                        Text(T("Not secret")).tag("none")
                    }
                    .labelsHidden()
                }
                fact(T("Tags")) { tagEditor }
                fact(T("File")) { Text(item.path).font(Theme.code).foregroundStyle(Theme.muted).textSelection(.enabled) }
                fileFacts
            }
            .padding(.top, 10)
        } label: {
            Text(T("More details and options")).font(Theme.section).foregroundStyle(Theme.text)
        }
    }

    /// The fields of a file with several, one click each: the next check reads the one chosen.
    private var fieldChoice: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(T("This file holds several values. Which one is the key?"))
                .font(Theme.body).foregroundStyle(Theme.text)
            FlowRow(spacing: 6) {
                ForEach(item.labels.filter { !$0.isEmpty }, id: \.self) { label in
                    Button(label) { model.setField(label, for: item) }.buttonStyle(KRButtonStyle())
                }
            }
        }
    }

    /// How agents reach this key now, in one line, and where to change it.
    @ViewBuilder private var agentsLine: some View {
        let ids = identifiers.map(\.id)
        let open = model.usage.grants.filter { ids.contains($0.key) }.count
        let level = ids.compactMap { model.agentPolicy.level(of: $0) }.first
        let offered = ids.contains { model.keyIndex.isOffered($0) }
        box(T("Agents")) {
            Text(level?.label ?? (offered || ids.isEmpty ? T("No agent can use this key.") : T("Not offered to agents")))
                .font(Theme.rowTitle).foregroundStyle(Theme.text)
            if open > 0 {
                Text(open == 1 ? T("1 permission open now") : T("%d permissions open now", open))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
            }
            Button(T("See use")) { tab = .use }.buttonStyle(.link).font(Theme.caption)
        }
    }

    @ViewBuilder private var use: some View {
        if isSealed {
            KeyAccessPanel(item: item, model: model)
            KeyUsagePanel(item: item, model: model)
        } else {
            EmptyHint(
                title: T("Seal it to use it"),
                text: T("A sealed key can be copied, and used by agents you allow, without its file."),
                action: T("Seal this key"), run: { model.seal([item]) })
        }
    }

    @ViewBuilder private var security: some View {
        if item.vault != .none {
            vaultNote
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Label(T("Only in its file. Any program running as you can read it."), systemImage: "doc")
                    .font(Theme.body).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
                if model.hasVault {
                    Button(T("Seal this key")) { model.seal([item]) }
                        .buttonStyle(KRButtonStyle(primary: true)).disabled(model.busy)
                }
            }
        }
        if model.hasVault, item.isSecret, !item.isArchived { RotationPanel(item: item, model: model) }
        fileFacts
        archiveButton
    }

    @ViewBuilder private var history: some View {
        let entries = model.activity.filter { $0.key == item.path }
        if entries.isEmpty {
            EmptyHint(title: T("Nothing yet"), text: T("Checks and uses of this key will show here."))
        } else {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(entries) { entry in
                    HStack(spacing: 10) {
                        Text(entry.at, format: .dateTime.day().month(.abbreviated).hour().minute())
                            .font(Theme.caption).monospacedDigit().foregroundStyle(Theme.muted)
                            .frame(width: 120, alignment: .leading)
                        Text(describe(entry.kind)).font(Theme.body).foregroundStyle(Theme.text)
                    }
                }
            }
        }
    }

    private func describe(_ kind: ActivityItem.Kind) -> String {
        switch kind {
        case .checked(let result):
            switch result {
            case "works": return T("Checked: works")
            case "rejected": return T("Checked: rejected")
            default: return T("Checked: no answer")
            }
        case .used(let program): return T("Used by %@", program)
        }
    }

    /// What the last check showed, with its date, and never more than it showed.
    private var statusText: String {
        let date = item.lastChecked
        switch item.lastResult {
        case "works": return date.isEmpty ? T("Checked successfully") : T("Checked successfully · %@", date)
        case "rejected": return date.isEmpty ? T("The provider rejected the check") : T("The provider rejected the check · %@", date)
        case "": return T("Not checked yet")
        default: return date.isEmpty ? T("Could not tell") : T("Could not tell · %@", date)
        }
    }

    private var statusIcon: String {
        switch item.lastResult {
        case "works": return "checkmark.circle.fill"
        case "rejected": return "xmark.circle.fill"
        case "": return "circle.dashed"
        default: return "questionmark.circle"
        }
    }

    private var statusColor: Color {
        switch item.lastResult {
        case "works": return Theme.good
        case "rejected": return Theme.bad
        default: return Theme.text
        }
    }

    private func box<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(Theme.caption).foregroundStyle(Theme.muted)
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.raised, in: RoundedRectangle(cornerRadius: Theme.radius))
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
        expires = item.expires
    }

    /// The key's name, then whose it is: provider, account and the identifier scripts use.
    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(item.title).font(.system(size: 17, weight: .semibold)).foregroundStyle(Theme.text)
                    .textSelection(.enabled)
                Text(subtitle).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(2).textSelection(.enabled)
                if item.criticality > 0 {
                    CriticalityMeter(value: item.criticality, suggested: item.criticalitySuggested).padding(.top, 2)
                }
            }
            Spacer(minLength: 6)
            if isSealed { CopyKeyButton(item: item, model: model) }
        }
    }

    private var subtitle: String {
        var parts: [String] = []
        if let provider = item.recipes.first { parts.append(model.providers.name(of: provider)) }
        if let account = model.account(of: item) { parts.append(account) }
        if let id = identifiers.first?.id { parts.append(id) }
        return parts.isEmpty ? item.path : parts.joined(separator: " · ")
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
                    // What a provider said can change, such as the day a key stops working: it can be asked again.
                    if model.providers.canIdentify(item) {
                        Button {
                            model.identify([item])
                        } label: {
                            Label(T("Identify again"), systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(KRButtonStyle())
                        .disabled(model.busy)
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
            fact(T("Expires")) {
                TextField(T("yyyy-mm-dd, if it has an end"), text: $expires)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit {
                        let day = expires.trimmingCharacters(in: .whitespaces)
                        if day.isEmpty || isDay(day) { model.save(KeyEdit(expires: day), for: item) }
                    }
                if !expires.isEmpty && !isDay(expires.trimmingCharacters(in: .whitespaces)) {
                    Text(T("Write it as 2026-12-31")).font(Theme.caption).foregroundStyle(Theme.warn)
                } else if let days = item.daysLeft() {
                    Text(days < 0 ? T("Expired %d days ago", -days) : T("%d days left", days))
                        .font(Theme.caption).foregroundStyle(days <= 14 ? Theme.warn : Theme.muted)
                }
            }
        }
    }

    private func isDay(_ text: String) -> Bool { CatalogItem(path: "", expires: text).daysLeft() != nil }

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
                    // Once a key has a field, "none" would take it away: only another field replaces it.
                    if item.field.isEmpty { Text(T("None")).tag("") }
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
