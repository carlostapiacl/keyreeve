import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Everything about agents in one place: whether Claude Code is connected, which keys and programs
/// they may use, what is open now and what they did.
struct AgentsView: View {
    @ObservedObject var model: AppModel
    @State private var connection = AgentConnection.none
    @State private var adding = false

    private var allowed: [(key: String, programs: [String])] {
        model.agentPolicy.commands.keys.sorted().compactMap { key in
            let programs = model.agentPolicy.commands[key] ?? []
            return programs.isEmpty ? nil : (key, programs)
        }
    }

    private static let agentEvents: Set<String> = ["granted", "used", "denied", "refused", "handed", "closed", "request", "signed"]
    private var recent: [AuditLog.Entry] {
        Array(model.usage.entries.filter { Self.agentEvents.contains($0.event) }.prefix(12))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(T("An agent asks keyreeve to run a program with a key and says why. You allow the pair here. When it asks, you choose once or for 1 to 24 hours, then confirm with your finger. The agent never sees the value."))
                    .font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                connectionCard
                allowedCard
                if !model.usage.grants.isEmpty { openCard }
                activityCard
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .onAppear {
            connection = AgentConnection.read()
            model.reloadUsage()
        }
        .sheet(isPresented: $adding) { AllowAgentSheet(model: model) }
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
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("2. What agents may use"))
                    Spacer()
                    Button(T("Make them ask again")) { model.endAgentApprovals() }
                        .buttonStyle(KRButtonStyle())
                        .help(T("Ends what you allowed for 1 to 24 hours. Locking the app does the same."))
                    Button(T("Allow a key…")) { adding = true }
                        .buttonStyle(KRButtonStyle(primary: true))
                        .disabled(model.agentKeys.isEmpty)
                }
                if model.agentKeys.isEmpty {
                    Text(T("Only sealed keys can be given to agents. Seal one in Vault first."))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                } else if allowed.isEmpty {
                    Text(T("Nothing yet. An agent that asks gets told no key is allowed."))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                }
                ForEach(allowed, id: \.key) { entry in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(entry.key).font(Theme.rowTitle).foregroundStyle(Theme.text)
                        ForEach(entry.programs, id: \.self) { program in
                            HStack(spacing: 6) {
                                Image(systemName: "terminal").foregroundStyle(Theme.muted)
                                Text(URL(fileURLWithPath: program).lastPathComponent)
                                    .font(Theme.code).foregroundStyle(Theme.text).lineLimit(1)
                                    .help(program)
                                Spacer(minLength: 4)
                                Button(T("Remove")) { model.disallow(program: program, keyID: entry.key) }
                                    .buttonStyle(KRButtonStyle())
                            }
                        }
                    }
                    .padding(.vertical, 4)
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

/// Picks a sealed key and a program, then allows the pair.
struct AllowAgentSheet: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var key = ""
    @State private var program = ""

    private var chosenKey: KeyIndex.Key? { model.agentKeys.first { $0.id == key } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(T("Allow a key for agents")).font(Theme.section).foregroundStyle(Theme.text)
            Picker(T("Key"), selection: $key) {
                ForEach(model.agentKeys) { item in
                    Text(item.provider.map { "\(item.id) · \($0)" } ?? item.id).tag(item.id)
                }
            }
            HStack {
                Text(program.isEmpty ? T("No program chosen") : URL(fileURLWithPath: program).lastPathComponent)
                    .font(Theme.code).foregroundStyle(program.isEmpty ? Theme.muted : Theme.text)
                    .lineLimit(1).truncationMode(.middle).help(program)
                Spacer()
                Button(T("Choose a program…")) { model.chooseProgram { program = $0 } }.buttonStyle(KRButtonStyle())
            }
            Text(T("Pick a program that does one thing, such as a script that checks or deploys. Shells, curl and similar tools cannot be allowed, since the agent would choose what they do with the key."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            if !program.isEmpty && AgentPolicy.isNeverAllowed(program) {
                Text(T("%@ can print or send whatever it gets, so it cannot be allowed.", URL(fileURLWithPath: program).lastPathComponent))
                    .font(Theme.caption).foregroundStyle(Theme.bad)
            }
            if let variable = chosenKey?.variable {
                Text(T("The agent passes the key in a variable it names. This key's usual one is %@.", variable))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(T("Cancel")) { dismiss() }.buttonStyle(KRButtonStyle())
                Button(T("Allow")) {
                    model.allow(program: program, keyID: key)
                    dismiss()
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .disabled(key.isEmpty || program.isEmpty || AgentPolicy.isNeverAllowed(program))
            }
        }
        .padding(20)
        .frame(width: 440)
        .onAppear { if key.isEmpty { key = model.agentKeys.first?.id ?? "" } }
    }
}
