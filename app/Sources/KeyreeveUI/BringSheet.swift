import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Bring in, on one screen: where to look, then what was found with values hidden, then one fingerprint.
public struct BringSheet: View {
    @ObservedObject var model: AppModel

    public init(model: AppModel) { self.model = model }

    public var body: some View {
        Group {
            if let draft = model.vaultDraft {
                RecoveryKeyView(draft: draft, model: model)
            } else if let state = model.bringing {
                switch state.step {
                case .choose: ChooseWhere(model: model, state: state)
                case .looking: looking
                case .review: BringReview(model: model, state: state)
                case .done: BringDone(model: model, state: state)
                }
            }
        }
        .frame(width: 760)
        .frame(minHeight: 360)
        .background(Theme.background)
    }

    private var looking: some View {
        VStack(spacing: 12) {
            ProgressView().controlSize(.small)
            Text(T("Looking for keys and asking each provider…")).font(Theme.body).foregroundStyle(Theme.muted)
            Text(T("Only reads. Nothing is copied, moved or changed.")).font(Theme.caption).foregroundStyle(Theme.faint)
        }
        .frame(maxWidth: .infinity, minHeight: 300)
    }
}

private struct ChooseWhere: View {
    @ObservedObject var model: AppModel
    let state: BringState

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(T("Bring in your keys")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("Keyreeve only reads. Nothing is copied, moved or changed, and no value is shown."))
                .font(Theme.body).foregroundStyle(Theme.muted)
            Picker("", selection: Binding(
                get: { state.place },
                set: { place in
                    model.bringing?.place = place
                    model.bringing?.under = []
                })
            ) {
                Text(T("Usual places on this Mac")).tag(BringState.Place.usual)
                Text(T("Everywhere in my home folder")).tag(BringState.Place.everywhere)
                Text(T("Choose a folder")).tag(BringState.Place.folder)
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            if state.place == .everywhere {
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        if state.under.isEmpty {
                            Text(T("Your whole home folder: the usual places, .env files, and files whose name or start says they hold a key. Other files are not opened."))
                                .font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
                        } else {
                            Text(T("Only in these folders, as everywhere:")).font(Theme.body).foregroundStyle(Theme.text)
                            ForEach(state.under, id: \.self) { folder in
                                Text(shortPath(folder.path)).font(Theme.caption).foregroundStyle(Theme.text)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                        }
                        Text(T("Skips Library, the Trash, photo and music libraries, iCloud Drive, apps, dependencies, builds and big files. It stops after two minutes and says which folders it did not finish."))
                            .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                        Label(T("macOS may ask for permission before Keyreeve reads Desktop, Documents and Downloads."), systemImage: "lock.shield")
                            .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(14)
                }
            } else if state.usualPlaces {
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(T("Where tools keep keys: AWS, GitHub CLI, gcloud, .netrc, npm, PyPI, Docker, your shell's exports and your SSH keys."))
                            .font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
                        SectionTitle(T("Also look for .env files in"))
                        if state.projects.isEmpty {
                            Text(T("No project folders here yet.")).font(Theme.caption).foregroundStyle(Theme.muted)
                        }
                        ForEach(state.projects) { project in
                            Toggle(isOn: Binding(
                                get: { project.on },
                                set: { on in
                                    if let at = model.bringing?.projects.firstIndex(where: { $0.url == project.url }) {
                                        model.bringing?.projects[at].on = on
                                    }
                                })
                            ) {
                                Text(shortPath(project.url.path)).font(Theme.body).foregroundStyle(Theme.text)
                            }
                        }
                        Button(T("Add a folder…"), action: model.addBringProject).buttonStyle(KRButtonStyle())
                        Text(T("Skips node_modules, .git, builds and caches. macOS may ask before Keyreeve reads Desktop or Documents."))
                            .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(14)
                }
            } else {
                Card {
                    HStack {
                        Text(state.folder.map { shortPath($0.path) } ?? T("No folder chosen"))
                            .font(Theme.body).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button(T("Choose…"), action: model.chooseBringFolder).buttonStyle(KRButtonStyle())
                    }
                    .padding(14)
                }
            }
            if let error = state.error {
                Label(error, systemImage: "exclamationmark.triangle.fill").font(Theme.body).foregroundStyle(Theme.bad)
            }
            HStack {
                Text(T("A key is checked only by the one provider its start, its variable or its client id names."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                Spacer()
                Button(T("Cancel"), action: model.cancelBringIn).buttonStyle(KRButtonStyle()).keyboardShortcut(.cancelAction)
                Button(T("Look for keys"), action: model.lookForKeys)
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
                    .disabled(state.scope == nil)
            }
        }
        .padding(24)
    }
}

private struct BringReview: View {
    @ObservedObject var model: AppModel
    let state: BringState
    @State private var showOther = false

    private var duplicates: [BringCandidate] { (state.report?.candidates ?? []).filter(\.duplicate) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(T("What was found")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("Values stay hidden. Decide only the doubtful ones; the rest is already chosen."))
                .font(Theme.body).foregroundStyle(Theme.muted)
            if let request = state.request { agentBanner(request) }
            if let unfinished = state.report?.unfinished, !unfinished.isEmpty {
                HStack(alignment: .firstTextBaseline) {
                    Label(T("The search stopped before finishing %d folders: %@", unfinished.count,
                            unfinished.prefix(4).map(shortPath).joined(separator: ", ") + (unfinished.count > 4 ? "…" : "")),
                          systemImage: "clock.badge.exclamationmark")
                        .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Button(T("Look in those"), action: model.lookInUnfinished).buttonStyle(KRButtonStyle())
                }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    group(T("Work"), icon: "checkmark.circle.fill", tone: .good, rows: state.candidates(.works), toggles: true)
                    doubtful
                    if !duplicates.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionTitle(T("Found in more than one place · %d", duplicates.count))
                            Text(T("Each is one key with several origins. It is sealed once."))
                                .font(Theme.caption).foregroundStyle(Theme.muted)
                        }
                    }
                    group(T("Turned down or expired"), icon: "xmark.circle.fill", tone: .bad, rows: state.candidates(.dead), toggles: true)
                    other
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 260, maxHeight: 460)
            if let error = state.error {
                Label(error, systemImage: "exclamationmark.triangle.fill").font(Theme.body).foregroundStyle(Theme.bad)
            }
            HStack {
                if state.undecided > 0 {
                    Text(T("Decide %d more to seal", state.undecided)).font(Theme.caption).foregroundStyle(Theme.warn)
                } else if !model.hasVault {
                    Text(T("Sealing makes your vault first.")).font(Theme.caption).foregroundStyle(Theme.muted)
                }
                Spacer()
                Button(T("Back")) { model.bringing?.step = .choose }.buttonStyle(KRButtonStyle())
                Button(T("Cancel"), action: model.cancelBringIn).buttonStyle(KRButtonStyle()).keyboardShortcut(.cancelAction)
                Button(state.chosen.count == 1 ? T("Seal 1 key") : T("Seal %d keys", state.chosen.count), action: model.sealBrought)
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
                    .disabled(state.undecided > 0 || state.chosen.isEmpty)
            }
        }
        .padding(24)
    }

    /// Whose suggestions these are, set apart, with the person's say over the names.
    private func agentBanner(_ request: AccessRequests.Entry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(T("%@ suggested what to seal. Its choices are marked, and you can change any of them.", request.agent), systemImage: "sparkles")
                .font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
            if let reason = request.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(2)
            }
            Toggle(T("Use the names and notes it suggested"), isOn: Binding(
                get: { state.useAgentNames },
                set: { model.bringing?.useAgentNames = $0 }))
                .toggleStyle(.checkbox).font(Theme.caption)
            if !state.agentMissed.isEmpty {
                Text(T("%d of its choices no longer match what was found: the file changed or is gone.", state.agentMissed.count))
                    .font(Theme.caption).foregroundStyle(Theme.warn)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.accent.opacity(0.08), in: RoundedRectangle(cornerRadius: Theme.smallRadius))
    }

    @ViewBuilder private var doubtful: some View {
        let rows = state.candidates(.doubtful)
        if !rows.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Badge(text: T("To decide · %d", rows.count), icon: "questionmark.circle.fill", tone: .warn)
                    Spacer()
                    Button(T("Seal all")) { model.decideAllDoubtful(seal: true) }.buttonStyle(KRButtonStyle())
                    Button(T("Skip all")) { model.decideAllDoubtful(seal: false) }.buttonStyle(KRButtonStyle())
                }
                ForEach(rows) { row in
                    HStack(spacing: 8) {
                        BringRow(candidate: row, model: model, agent: state.request?.agent, choice: state.agentChoices[row.id])
                        Picker("", selection: Binding(
                            get: { state.decisions[row.id] },
                            set: { if let seal = $0 { model.decide(row.id, seal: seal) } })
                        ) {
                            Text(T("Seal")).tag(Bool?.some(true))
                            Text(T("Skip")).tag(Bool?.some(false))
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 130)
                    }
                }
            }
        }
    }

    @ViewBuilder private var other: some View {
        let rows = state.candidates(.other)
        if !rows.isEmpty {
            DisclosureGroup(isExpanded: $showOther) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(rows) { BringRow(candidate: $0, model: model, agent: nil, choice: nil) }
                }
                .padding(.top, 4)
            } label: {
                Text(T("Configuration, documents and public keys · %d, not sealed", rows.count))
                    .font(Theme.section).foregroundStyle(Theme.text)
            }
        }
    }

    @ViewBuilder
    private func group(_ title: String, icon: String, tone: Tone, rows: [BringCandidate], toggles: Bool) -> some View {
        if !rows.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Badge(text: "\(title) · \(rows.count)", icon: icon, tone: tone)
                ForEach(rows) { row in
                    Toggle(isOn: Binding(
                        get: { state.decisions[row.id] == true },
                        set: { model.decide(row.id, seal: $0) })
                    ) {
                        BringRow(candidate: row, model: model, agent: state.request?.agent, choice: state.agentChoices[row.id])
                    }
                }
            }
        }
    }
}

/// One key found: its names, what it is, its provider and where it was. Never its value.
private struct BringRow: View {
    let candidate: BringCandidate
    @ObservedObject var model: AppModel
    /// The agent that proposed this review, and what it suggested for this key.
    let agent: String?
    let choice: AgentBringing.Proposal.Item?

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(candidate.partNames.isEmpty ? T("whole file") : candidate.partNames)
                    .font(Theme.rowTitle).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                Text(origin).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1).truncationMode(.middle)
                if let agent, let choice { suggestion(agent, choice) }
            }
            Spacer(minLength: 6)
            if candidate.duplicate { Chip(text: T("%d places", candidate.origins.count)) }
            if candidate.from_project { Chip(text: T("a project uses it")) }
            Chip(text: kind)
            if let provider = candidate.provider {
                Text(model.providerName(provider)).font(Theme.caption).foregroundStyle(Theme.text)
            } else if !candidate.guessed.isEmpty {
                // A guess from a name: shown, never checked, never saved with the key.
                Text(T("maybe %@", candidate.guessed.map(model.providerName).joined(separator: T(" or "))))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
            }
            if let reason = candidate.check?.reason ?? candidate.unchecked, candidate.group != .works {
                Text(T(reason)).font(Theme.caption).foregroundStyle(Theme.faint).lineLimit(1)
            }
        }
    }

    /// What the agent suggested, in its words and set apart from keyreeve's own.
    private func suggestion(_ agent: String, _ choice: AgentBringing.Proposal.Item) -> some View {
        var parts = [choice.seal ? T("%@ suggests sealing it", agent) : T("%@ suggests skipping it", agent)]
        if let id = choice.id { parts.append(T("as %@", id)) }
        if let provider = choice.provider, provider != candidate.provider { parts.append(T("says %@", model.providerName(provider))) }
        if let words = choice.description ?? choice.reason { parts.append("\u{201C}\(words)\u{201D}") }
        return Label(parts.joined(separator: " · "), systemImage: "sparkles")
            .font(Theme.caption).foregroundStyle(Theme.accent).lineLimit(1).truncationMode(.tail)
    }

    private var origin: String {
        guard let first = candidate.origins.first else { return "" }
        let line = first.parts.first.map { $0.whole ? "" : " · " + T("line %d", $0.line) } ?? ""
        return shortPath(first.path) + line
    }

    private var kind: String {
        switch candidate.kind {
        case "key": T("key")
        case "login": T("login")
        case "configuration": T("configuration")
        case "document": T("document")
        case "public": T("public")
        default: candidate.kind
        }
    }
}

private struct BringDone: View {
    @ObservedObject var model: AppModel
    let state: BringState

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(state.sealed.count == 1 ? T("1 key sealed") : T("%d keys sealed", state.sealed.count))
                .font(Theme.title).foregroundStyle(Theme.text)
            Text(T("Each has an identifier, and no agent sees it until you offer it. Your files stay as they were."))
                .font(Theme.body).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            if !state.failed.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(state.failed, id: \.self) { problem in
                        Label(problem, systemImage: "exclamationmark.triangle.fill").font(Theme.body).foregroundStyle(Theme.warn)
                    }
                }
            }
            HStack {
                Spacer()
                if !state.fromProjects.isEmpty {
                    Button(T("Offer the %d your scripts already use", state.fromProjects.count), action: model.offerBroughtFromProjects)
                        .buttonStyle(KRButtonStyle())
                }
                Button(T("Done"), action: model.cancelBringIn)
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
    }
}

/// A path with the home folder written as `~`.
func shortPath(_ path: String) -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
}
