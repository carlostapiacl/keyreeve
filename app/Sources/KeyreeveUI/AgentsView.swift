import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Everything about agents in one place: whether Claude Code is connected, which keys and programs
/// they may use, what is open now and what they did.
struct AgentsView: View {
    @ObservedObject var model: AppModel
    @State private var connection = AgentConnection.none
    @State private var runs: [AgentTranscript.Entry] = []
    /// Read again while this is on screen, off the main thread, so the window stays live and quick.
    private let ticker = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    private static let agentEvents: Set<String> = [
        "granted", "used", "denied", "refused", "handed", "closed", "request", "signed", "requested", "opened",
    ]
    private var recent: [AuditLog.Entry] {
        Array(model.usage.entries.filter { Self.agentEvents.contains($0.event) }.prefix(12))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(T("An agent asks keyreeve to run a command with a key and says why. The command gets a stand-in, and the real key only travels to the key's provider. The agent never sees the value."))
                    .font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                if !model.pendingRequests.isEmpty { requestsCard }
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
                    RequestRow(request: request, model: model)
                }
            }
            .padding(14)
        }
        .overlay(RoundedRectangle(cornerRadius: Theme.radius).strokeBorder(Theme.accent.opacity(0.6)))
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
                        .help(T("Ends what you allowed for 1 to 24 hours. Locking the app does the same."))
                }
                Text(T("Only me: no agent. Ask: you choose once or for some hours, then your finger. Free: your finger once, then no questions until you lock the app."))
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
                            ? T("1 sealed key has no identifier yet, so it cannot be chosen.")
                            : T("%d sealed keys have no identifier yet, so they cannot be chosen.", model.sealedWithoutIdentifier))
                            .font(Theme.caption).foregroundStyle(Theme.muted)
                        Spacer()
                        Button(T("Give them identifiers")) { model.assignIdentifiers() }.buttonStyle(KRButtonStyle())
                    }
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
                        Button(T("End")) { model.endPermissions(of: grant.key) }.buttonStyle(KRButtonStyle())
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
                    Text(T("The usage log was changed at line %d.", line)).font(Theme.caption).foregroundStyle(Theme.bad)
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
                    }
                    .labelsHidden().fixedSize()
                } else {
                    Text(programs.isEmpty ? T("Only me") : T("Ask")).font(Theme.caption).foregroundStyle(Theme.muted)
                }
                Picker(T("Agents"), selection: Binding(get: { agents }, set: { model.setAgents($0, for: key.id) })) {
                    Text(T("Any agent")).tag([String]())
                    Text("Claude").tag(["claude"])
                    Text("Codex").tag(["codex"])
                    if ![[], ["claude"], ["codex"]].contains(agents) { Text(agents.joined(separator: ", ")).tag(agents) }
                }
                .labelsHidden().fixedSize()
                .disabled(level == nil && programs.isEmpty)
            }
            ForEach(programs, id: \.self) { program in
                HStack(spacing: 6) {
                    Image(systemName: "terminal").foregroundStyle(Theme.muted)
                    Text(URL(fileURLWithPath: program).lastPathComponent)
                        .font(Theme.code).foregroundStyle(Theme.text).lineLimit(1).help(program)
                    if model.agentPolicy.hashes[program] == nil {
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
            if candidates.isEmpty {
                Text(T("No file in your keys folder is a %@ key. Add one, or decline.", request.provider))
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
            hours = Self.durations.contains(request.hours) ? request.hours : 1
        }
    }

    /// The file's name or path, and what keyreeve knows of it, so the right one is easy to pick.
    private func label(_ item: CatalogItem) -> String {
        var parts = [item.name.isEmpty ? item.path : "\(item.name) · \(item.path)"]
        if item.vault != .none { parts.append(T("sealed already")) }
        if item.lastResult == "works" { parts.append(T("last check passed")) }
        return parts.joined(separator: " · ")
    }
}
