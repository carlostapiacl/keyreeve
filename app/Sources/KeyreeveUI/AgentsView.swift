import AppKit
import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Everything about agents in one place: whether Claude Code is connected, which keys and programs
/// they may use, what is open now and what they did.
struct AgentsView: View {
    @ObservedObject var model: AppModel
    @State private var connection = AgentConnection.none
    @State private var runs: [AgentTranscript.Entry] = []
    @AppStorage(AppModel.agentsCanSortKey) private var agentsCanSort = false
    /// Read again while this is on screen, off the main thread, so the window stays live and quick.
    private let ticker = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    private static let agentEvents: Set<String> = [
        "granted", "used", "denied", "refused", "handed", "closed", "request", "signed", "requested", "opened",
        "policy", "allowed", "declined", "paused", "resumed", "closed all",
    ]
    private var recent: [AuditLog.Entry] {
        Array(model.usage.entries.filter { Self.agentEvents.contains($0.event) }.prefix(12))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(T("An agent asks keyreeve to run a command with a key and says why. With a provider, the command gets a stand-in and the real key only travels to that provider. A program you allow by name gets the real key."))
                    .font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                if !model.pendingRequests.isEmpty { requestsCard }
                let news = ArrivalNews.make(items: model.items, index: model.keyIndex)
                if !news.isEmpty { Card { ArrivalNotice(news: news, review: model.showNewKeysNow).padding(14) } }
                sortingCard
                connectionCard
                allowedCard
                if !model.usage.grants.isEmpty { openCard }
                terminalCard
                activityCard
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .onAppear {
            connection = AgentConnection.read()
            model.reloadUsage()
            loadRuns()
        }
        .onReceive(ticker) { _ in
            loadRuns()
            model.reloadRequests()
        }
    }

    /// Waiting on you, so it comes first and stands out.
    private var requestsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "hand.raised.fill").foregroundStyle(Theme.accent)
                    SectionTitle(T("Requests"))
                }
                ForEach(Array(model.pendingRequests.enumerated()), id: \.element.id) { index, request in
                    if index > 0 { Divider() }
                    if request.kind == "sort" {
                        SortProposalRow(request: request, model: model)
                    } else if request.isRotation {
                        RotationRequestRow(request: request, model: model)
                    } else {
                        RequestRow(request: request, model: model)
                    }
                }
            }
            .padding(14)
        }
        .overlay(RoundedRectangle(cornerRadius: Theme.radius).strokeBorder(Theme.accent.opacity(0.6)))
    }

    /// Letting an agent sort the whole folder: it reads names and fields, proposes, and the person applies.
    private var sortingCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 6) {
                Toggle(T("Agents can sort my keys"), isOn: $agentsCanSort)
                    .toggleStyle(.switch).font(Theme.rowTitle)
                    .onChange(of: agentsCanSort) { _, _ in model.publishInventory() }
                Text(T("An agent sees each file's name, field names, provider and state, never a value, and proposes how to sort them. You review every change here and apply the ones you want."))
                    .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
        }
    }

    private var connectionCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("1. Connect Claude Code"))
                    Spacer()
                    Button(T("Look again")) { connection = AgentConnection.read() }.buttonStyle(KRButtonStyle())
                    Button(T("Copy the command")) { model.copyAgentCommand() }.buttonStyle(KRButtonStyle())
                }
                switch connection {
                case .everywhere:
                    status(T("Connected in every folder."), good: true)
                case .folders(let folders):
                    status(T("Connected only in %@. Copy the command to have it in every folder.", folders.map { URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: ", ")), good: false)
                case .none:
                    status(T("Not connected. Copy the command, run it in a terminal, and open a new Claude Code session."), good: false)
                }
                Text(T("A session started before connecting does not see keyreeve. Open a new one."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
        }
    }

    private func status(_ text: String, good: Bool) -> some View {
        Label(text, systemImage: good ? "checkmark.circle" : "exclamationmark.circle")
            .font(Theme.caption).foregroundStyle(good ? Theme.good : Theme.warn)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var allowedCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(T("2. What agents may use"))
                    Spacer()
                    Button(T("Make them ask again")) { model.endAgentApprovals() }
                        .buttonStyle(KRButtonStyle())
                        .help(T("Ends every permission agents hold now. Quitting Keyreeve does the same."))
                }
                Text(T("Only me: no agent. Ask: you choose once or for some hours, then your finger. Free: your finger once, then no questions until you quit Keyreeve."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                if model.agentKeys.isEmpty {
                    Text(T("Only sealed keys can be given to agents. Seal one in Vault first."))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                }
                ForEach(model.agentKeys) { key in
                    AgentKeyRow(key: key, model: model)
                    Divider()
                }
                if model.sealedWithoutIdentifier > 0 {
                    HStack {
                        Text(model.sealedWithoutIdentifier == 1
                            ? T("1 sealed key has no identifier yet. Agents do not see it until you offer it.")
                            : T("%d sealed keys have no identifier yet. Agents do not see them until you offer them.", model.sealedWithoutIdentifier))
                            .font(Theme.caption).foregroundStyle(Theme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer()
                        Button(T("Give them identifiers")) { model.assignIdentifiers() }.buttonStyle(KRButtonStyle())
                    }
                }
                if model.sealedNotOffered > 0 {
                    Text(model.sealedNotOffered == 1
                        ? T("1 sealed key is not offered to agents. Offer it from its page, under Usage.")
                        : T("%d sealed keys are not offered to agents. Offer one from its page, under Usage.", model.sealedNotOffered))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(14)
        }
    }

    private func loadRuns() {
        let transcript = AgentTranscript(url: model.files.directory.appendingPathComponent(AgentTranscript.fileName))
        Task.detached(priority: .utility) {
            let latest = transcript.entries(limit: 30)
            await MainActor.run { if latest != runs { runs = latest } }
        }
    }

    private var terminalCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionTitle(T("Agent terminal"))
                Text(T("Each command an agent ran with a key, and what came back. The key and its stand-in never appear here."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                if runs.isEmpty {
                    Text(T("No agent has run a command with a key yet.")).font(Theme.caption).foregroundStyle(Theme.muted)
                }
                ForEach(Array(runs.enumerated()), id: \.offset) { _, run in TerminalRow(run: run) }
            }
            .padding(14)
        }
    }

    private var openCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionTitle(T("Open now"))
                ForEach(model.usage.grants, id: \.id) { grant in
                    HStack(spacing: 6) {
                        Text(grant.key).font(Theme.rowTitle).foregroundStyle(Theme.text)
                        Text(grant.program).font(Theme.code).foregroundStyle(Theme.muted).lineLimit(1)
                        Text(T("%dm left", max(0, Int(grant.expires.timeIntervalSinceNow) / 60)))
                            .font(Theme.caption).foregroundStyle(Theme.muted)
                        Spacer(minLength: 4)
                        Button(T("End")) { model.endPermissions(of: grant.key, grant: grant.id) }.buttonStyle(KRButtonStyle())
                    }
                }
            }
            .padding(14)
        }
    }

    private var activityCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionTitle(T("3. What they did"))
                if let line = model.usage.brokenLine {
                    Text((line == 0 ? T("The usage log could not be read.") : T("The usage log was changed at line %d.", line))).font(Theme.caption).foregroundStyle(Theme.bad)
                }
                if recent.isEmpty {
                    Text(T("No agent has asked for a key yet.")).font(Theme.caption).foregroundStyle(Theme.muted)
                }
                ForEach(recent, id: \.hash) { UsageRow(entry: $0, showsKey: true) }
            }
            .padding(14)
        }
    }
}

/// One key: who may use it, and how they are asked.
struct AgentKeyRow: View {
    let key: KeyIndex.Key
    @ObservedObject var model: AppModel

    /// When an agent's request opened the key for some hours. Past that, the key is closed again.
    private var closes: Date? { model.agentPolicy.until[key.id] }
    private var level: AgentPolicy.Level? {
        if let closes, Date() >= closes { return nil }
        return model.agentPolicy.levels[key.id]
    }
    private var agents: [String] { model.agentPolicy.agents[key.id] ?? [] }
    private var programs: [String] { model.agentPolicy.commands[key.id] ?? [] }
    private var usesProxy: Bool { key.provider != nil }

    private var how: String {
        if key.provider == KeyService.sshProvider { return T("SSH: signs in, the key stays in keyreeve") }
        if usesProxy { return T("Proxy: the command gets a stand-in") }
        return T("No provider, so only through a program you choose")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(key.id).font(Theme.rowTitle).foregroundStyle(Theme.text)
                    Text(how).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                    if let closes, level != nil {
                        Text(T("Open until %@", closes.formatted(date: .omitted, time: .shortened)))
                            .font(Theme.caption).foregroundStyle(Theme.warn).lineLimit(1)
                    }
                }
                Spacer(minLength: 8)
                if usesProxy {
                    Picker(T("Level"), selection: Binding(get: { level }, set: { model.setAgentLevel($0, for: key.id) })) {
                        Text(T("Only me")).tag(AgentPolicy.Level?.none)
                        Text(T("Ask")).tag(AgentPolicy.Level?.some(.ask))
                        Text(T("Free")).tag(AgentPolicy.Level?.some(.free))
                        Text(T("Always, no fingerprint")).tag(AgentPolicy.Level?.some(.always))
                    }
                    .labelsHidden().fixedSize()
                } else {
                    Text(programs.isEmpty ? T("Only me") : T("Ask")).font(Theme.caption).foregroundStyle(Theme.muted)
                }
                // Every agent the log has seen, each one on or off, so a key can be open to Claude and a bot at once.
                Menu(agents.isEmpty ? T("Any agent") : agents.joined(separator: ", ")) {
                    Button(T("Any agent")) { model.setAgents([], for: key.id) }
                    Divider()
                    ForEach(model.knownAgents, id: \.self) { name in
                        Button {
                            let chosen = agents.contains(name) ? agents.filter { $0 != name } : (agents + [name]).sorted()
                            model.setAgents(chosen, for: key.id)
                        } label: {
                            if agents.contains(name) { Label(name, systemImage: "checkmark") } else { Text(name) }
                        }
                    }
                }
                .fixedSize()
                .disabled(level == nil && programs.isEmpty)
            }
            if level == .always, !model.hasUnattendedCopy(key.id) {
                // Marked, with no copy to open: an older Keyreeve dropped it, or the key was sealed again from
                // elsewhere. It asks for the finger meanwhile, and one more makes the copy again.
                HStack(spacing: 8) {
                    Text(T("This key asks for a fingerprint again: its copy for use with no fingerprint is missing."))
                        .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
                    Button(T("Mark again")) { model.markAlways(key.id) }.buttonStyle(KRButtonStyle())
                }
            }
            if level == .always {
                // Said where it is chosen, every time it shows.
                Text(T("Any program running as you can use this key through the proxy without asking, while this Mac is unlocked. Keep it for keys that only read."))
                    .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(programs, id: \.self) { program in
                HStack(spacing: 6) {
                    Image(systemName: "terminal").foregroundStyle(Theme.muted)
                    Text(URL(fileURLWithPath: program).lastPathComponent)
                        .font(Theme.code).foregroundStyle(Theme.text).lineLimit(1).help(program)
                    if model.agentPolicy.hash(of: program, for: key.id) == nil {
                        Text(T("allow it again to pin it")).font(Theme.caption).foregroundStyle(Theme.warn)
                    }
                    Spacer(minLength: 4)
                    Button(T("Remove")) { model.disallow(program: program, keyID: key.id) }.buttonStyle(KRButtonStyle())
                }
            }
            if !usesProxy || !programs.isEmpty {
                Button(T("Allow a program…")) { model.chooseProgram { model.allow(program: $0, keyID: key.id) } }
                    .buttonStyle(KRButtonStyle())
            }
        }
        .padding(.vertical, 2)
    }
}

/// One command an agent ran, as a terminal would show it.
struct TerminalRow: View {
    let run: AgentTranscript.Entry
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(run.agent).font(Theme.caption).foregroundStyle(Theme.accent)
                Text(run.key).font(Theme.caption).foregroundStyle(Theme.muted)
                Text(run.reason).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 4)
                Text(T("exit %d", Int(run.exit))).font(Theme.code).foregroundStyle(run.exit == 0 ? Theme.good : Theme.bad)
                Text("\(run.milliseconds) ms").font(Theme.caption).foregroundStyle(Theme.faint)
                Text(run.at, format: .dateTime.day().month().hour().minute().second())
                    .font(Theme.caption).foregroundStyle(Theme.faint)
            }
            Button {
                expanded.toggle()
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("$ " + run.command).font(Theme.code).foregroundStyle(Theme.text)
                        .lineLimit(expanded ? nil : 1).truncationMode(.middle)
                    if !run.output.isEmpty {
                        Text(run.output).font(Theme.code).foregroundStyle(Theme.muted)
                            .lineLimit(expanded ? 40 : 2)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(RoundedRectangle(cornerRadius: Theme.smallRadius).fill(Theme.raised))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .textSelection(.enabled)
            .help(expanded ? T("Show less") : T("Show all"))
        }
    }
}

/// An agent asking for a key that is not saved yet: choose the file and for how long, and it is saved,
/// named and allowed at once.
struct RequestRow: View {
    let request: AccessRequests.Entry
    @ObservedObject var model: AppModel
    @State private var chosen: String?
    @State private var hours: Int?
    @State private var started = false

    private static let durations: [Int?] = AccessDecision.hourChoices.map { $0 } + [nil]

    var body: some View {
        let candidates = model.candidates(for: request)
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(T("%@ asks for a %@ key", request.agent, request.provider))
                    .font(Theme.rowTitle).foregroundStyle(Theme.text)
                Spacer(minLength: 8)
                Text(request.at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
            }
            if let reason = request.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let account = request.account {
                Text(T("For: %@", account)).font(Theme.caption).foregroundStyle(Theme.text)
            }
            if candidates.isEmpty {
                Text(T("No file in your keys folder is a %@ key. Paste a new one, or decline.", request.provider))
                    .font(Theme.caption).foregroundStyle(Theme.warn)
            }
            HStack(spacing: 8) {
                if !candidates.isEmpty {
                    Picker(T("Which file"), selection: $chosen) {
                        ForEach(candidates, id: \.path) { item in
                            Text(label(item)).tag(String?.some(item.path))
                        }
                    }
                    .labelsHidden()
                    .help(T("Which file"))
                    Picker(T("For how long"), selection: $hours) {
                        ForEach(Self.durations, id: \.self) { value in
                            Text(value.map { T("For %d h", $0) } ?? T("Always")).tag(value)
                        }
                    }
                    .labelsHidden().fixedSize()
                    .help(T("For how long"))
                }
                Spacer(minLength: 8)
                Button(T("Paste a new one")) { model.startAddingKey(for: request) }
                    .buttonStyle(KRButtonStyle(primary: candidates.isEmpty))
                    .help(T("Copy a new key from the provider and paste it"))
                Button(T("Decline")) { model.decline(request) }.buttonStyle(KRButtonStyle())
                if !candidates.isEmpty {
                    Button(T("Save and allow")) {
                        guard let item = candidates.first(where: { $0.path == (chosen ?? candidates.first?.path) }) else { return }
                        model.allow(request, with: item, hours: hours)
                    }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
                }
            }
        }
        .onAppear {
            guard !started else { return }
            started = true
            chosen = candidates.first?.path
            hours = AccessDecision.startingHours(for: request.hours)
        }
    }

    /// The file's name or path, and what keyreeve knows of it, so the right one is easy to pick.
    private func label(_ item: CatalogItem) -> String {
        var parts = [item.name.isEmpty ? item.path : "\(item.name) · \(item.path)"]
        // Who the key belongs to, as its provider said: what tells apart several keys of one provider.
        if let reaches = item.reaches { parts.append(reaches) }
        if item.fit(account: request.account) > 0 { parts.append(T("Matches what was asked")) }
        if item.vault != .none { parts.append(T("sealed already")) }
        if item.lastResult == "works" { parts.append(T("last check passed")) }
        return parts.joined(separator: " · ")
    }
}

/// An agent asking to rotate a key, answered in one place: seal it if it is not, say where the new key goes
/// (approving a file of yours that updates a place, right here), paste the new key for a provider with no
/// way to make one from here, and rotate. The vault asks for the fingerprint when it starts.
struct RotationRequestRow: View {
    let request: AccessRequests.Entry
    @ObservedObject var model: AppModel
    @State private var newKey = ""

    /// Buttons of the person's own that receive a new key, from every provider file, approved or not.
    private var placeActions: [(provider: ProviderInfo, id: String, title: String)] {
        model.providers.all.filter { $0.problem == nil }.flatMap { provider in
            (provider.actions ?? []).filter { $0.run != nil }.map { (provider: provider, id: "\(provider.id)/\($0.id)", title: $0.title) }
        }
    }

    var body: some View {
        let item = model.item(forKey: request.key)
        let provider = item.flatMap { model.providers.rotator(of: $0) }
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(T("%@ asks to rotate %@", request.agent, request.key ?? request.provider))
                    .font(Theme.rowTitle).foregroundStyle(Theme.text)
                Spacer(minLength: 8)
                Text(request.at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
            }
            if let reason = request.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let item, let provider {
                steps(item, provider)
            } else {
                Text(item == nil ? T("That key is not on your list.") : T("Its provider has no way to rotate a key, here or by hand."))
                    .font(Theme.caption).foregroundStyle(Theme.warn)
                HStack { Spacer(); Button(T("Decline")) { model.decline(request) }.buttonStyle(KRButtonStyle()) }
            }
        }
    }

    @ViewBuilder private func steps(_ item: CatalogItem, _ provider: ProviderInfo) -> some View {
        let places = model.places[item.path] ?? KeyPlaces()
        let open = model.rotations.contains { $0.key == item.path && $0.isOpen }
        // 1. Sealed, so the new key has a safe place to land.
        if item.vault == .sealed {
            Label(T("Sealed in the vault"), systemImage: "checkmark.circle.fill").font(Theme.caption).foregroundStyle(Theme.good)
        } else {
            HStack(spacing: 8) {
                Text(T("Seal this key first, so the new one has a safe place to land.")).font(Theme.caption).foregroundStyle(Theme.warn)
                Button(T("Seal")) { model.seal([item]) }.buttonStyle(KRButtonStyle()).disabled(model.busy)
            }
        }
        // 2. Where the new key goes.
        Text(T("Where else is this key used? Each place gets the new key before the old one is revoked."))
            .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
        ForEach(placeActions, id: \.id) { place in
            HStack(spacing: 8) {
                Toggle(place.title, isOn: Binding(
                    get: { places.actions.contains(place.id) },
                    set: { on in
                        var value = places
                        if on { value.actions.append(place.id); value.nothingElse = false } else { value.actions.removeAll { $0 == place.id } }
                        _ = model.savePlaces(value, for: item)
                    }))
                .toggleStyle(.checkbox).font(Theme.caption)
                .disabled(!place.provider.approved)
                if !place.provider.approved {
                    Button(T("Approve %@", place.provider.name)) { approveProvider(place.provider, model: model) }
                        .buttonStyle(KRButtonStyle())
                }
            }
        }
        ForEach(places.files, id: \.self) { file in
            Label(URL(fileURLWithPath: file).lastPathComponent, systemImage: "doc").font(Theme.caption).foregroundStyle(Theme.text)
        }
        if places.actions.isEmpty && places.files.isEmpty {
            Toggle(T("Nothing else uses this key"), isOn: Binding(
                get: { places.nothingElse },
                set: { on in var value = places; value.nothingElse = on; _ = model.savePlaces(value, for: item) }))
            .toggleStyle(.checkbox).font(Theme.caption)
        }
        // 3. The new key, when the provider cannot make one from here.
        if !provider.can_rotate {
            Text(T("Make the new key at %@'s page and paste it here. It is tested before anything changes.", provider.name))
                .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                if let page = provider.dashboard.flatMap(URL.init(string:)) {
                    Button(T("Open its page")) { NSWorkspace.shared.open(page) }.buttonStyle(KRButtonStyle())
                }
                SecureField(T("New key"), text: $newKey).textFieldStyle(.roundedBorder)
                Button(T("Paste from the clipboard")) { newKey = PastedKey.take() ?? newKey }
                    .buttonStyle(KRButtonStyle())
                    .help(T("Takes the key you copied and clears the clipboard. It is not shown."))
            }
        }
        if open {
            Text(T("A rotation of this key is open. Finish it in Vault.")).font(Theme.caption).foregroundStyle(Theme.warn)
        }
        // 4. Rotate.
        HStack(spacing: 8) {
            Spacer()
            Button(T("Decline")) { model.decline(request) }.buttonStyle(KRButtonStyle())
            Button(T("Rotate this key")) {
                model.rotate(for: request, item: item, handedOver: provider.can_rotate ? nil : newKey)
                newKey = ""
            }
            .buttonStyle(KRButtonStyle(primary: true))
            .disabled(model.busy || open || item.vault != .sealed || !places.isDecided || (!provider.can_rotate && newKey.isEmpty))
        }
    }
}

/// An agent's proposal to sort many keys, in one list: each file with what would change, all chosen to
/// start, and one button to apply the chosen ones. Checking asks for the fingerprint as always.
struct SortProposalRow: View {
    let request: AccessRequests.Entry
    @ObservedObject var model: AppModel
    @State private var proposal: SortProposal?
    @State private var chosen: Set<String> = []

    var body: some View {
        let proposal = self.proposal ?? SortProposal()
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(T("%@ proposes changes to %d keys", request.agent, proposal.paths.count))
                    .font(Theme.rowTitle).foregroundStyle(Theme.text)
                Spacer(minLength: 8)
                Text(request.at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
            }
            if let reason = request.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if proposal.paths.isEmpty {
                Text(T("Nothing in it matches your list today.")).font(Theme.caption).foregroundStyle(Theme.warn)
            } else {
                HStack(spacing: 8) {
                    Button(T("Choose all")) { chosen = Set(proposal.paths) }.buttonStyle(.link).font(Theme.caption)
                    Button(T("Choose none")) { chosen = [] }.buttonStyle(.link).font(Theme.caption)
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(proposal.paths, id: \.self) { path in
                            Toggle(isOn: Binding(
                                get: { chosen.contains(path) },
                                set: { on in if on { chosen.insert(path) } else { chosen.remove(path) } })
                            ) {
                                HStack(spacing: 8) {
                                    Text(path).font(Theme.body).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                                    if let what = proposal.suggestion(for: path)?.what {
                                        Text(what).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                                    }
                                    Spacer(minLength: 6)
                                    Text(changes(path, in: proposal)).font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1)
                                }
                            }
                            .toggleStyle(.checkbox)
                        }
                    }
                }
                .frame(maxHeight: 320)
            }
            HStack(spacing: 8) {
                if !proposal.check.intersection(chosen).isEmpty {
                    Text(T("Checking sends each key to its own provider, and may ask for your fingerprint."))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                }
                Spacer()
                Button(T("Decline")) { model.decline(request) }.buttonStyle(KRButtonStyle())
                Button(T("Apply %d", chosen.count)) { model.applyProposal(for: request, chosen: chosen) }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(model.busy || chosen.isEmpty)
            }
        }
        .onAppear {
            guard self.proposal == nil else { return }
            let read = model.proposal(for: request)
            self.proposal = read
            chosen = Set(read.paths)
        }
        // What is shown follows the list as it loads, so it says what applying will do.
        .onChange(of: model.itemsVersion) { _, _ in
            let read = model.proposal(for: request)
            if self.proposal?.paths.isEmpty != false { chosen = Set(read.paths) }
            self.proposal = read
        }
    }

    /// What would change for one file, in a few words.
    private func changes(_ path: String, in proposal: SortProposal) -> String {
        var parts: [String] = []
        switch proposal.suggestion(for: path)?.kind {
        case .provider(let id, let field)?:
            let name = model.providers.name(of: id)
            parts.append(field.map { "\(name) · \($0)" } ?? name)
        case .untestable?: parts.append(T("Nothing to check"))
        case .internalSecret?: parts.append(T("Internal secret"))
        case .notSecret?: parts.append(T("Not secret"))
        case .described?, nil: break
        }
        if proposal.check.contains(path) { parts.append(T("check")) }
        if proposal.seal.contains(path) { parts.append(T("seal")) }
        if proposal.archive.contains(path) { parts.append(T("archive")) }
        if proposal.split.contains(path) { parts.append(T("split")) }
        if let host = proposal.hosts[path] { parts.append(URL(string: host)?.host ?? host) }
        if let day = proposal.expires[path] { parts.append(T("expires %@", day)) }
        return parts.joined(separator: " · ")
    }
}


extension AgentPolicy.Level {
    /// How the window names the level.
    var label: String {
        switch self {
        case .ask: return T("Ask")
        case .free: return T("Free")
        case .always: return T("Always, no fingerprint")
        }
    }
}
