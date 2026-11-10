import AppKit
import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Keyreeve in the menu bar: what agents ask for, what they hold now, the latest uses, and the
/// emergency stop. It reads the service and the files directly, so it works while the window is locked,
/// and it shows names only, never a value.
public struct MenuBarView: View {
    @ObservedObject var model: AppModel
    let openWindow: () -> Void
    @State private var grants: [KeyService.GrantInfo] = []
    @State private var runs: [AgentTranscript.Entry] = []
    /// Keys that came in without the person, and values that wait: counts and names only.
    @State private var news = ArrivalNews()
    /// The menu's contents are read only while it is open.
    @State private var open = false
    private let ticker = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    public init(model: AppModel, openWindow: @escaping () -> Void) {
        self.model = model
        self.openWindow = openWindow
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if model.agentsPaused { pausedBanner }
            if !model.pendingRequests.isEmpty { requests }
            if !news.isEmpty {
                ArrivalNotice(news: news) {
                    model.showNewKeysNow()
                    openWindow()
                }
            }
            openNow
            if !runs.isEmpty { latest }
            Divider()
            HStack(spacing: 8) {
                Button(T("Open Keyreeve"), action: openWindow).buttonStyle(KRButtonStyle())
                Button(T("Add a key")) {
                    openWindow()
                    model.startAddingKey()
                }
                .buttonStyle(KRButtonStyle())
                Spacer()
                Button(T("Quit Keyreeve")) { NSApp.terminate(nil) }.buttonStyle(KRButtonStyle())
                    .help(T("Agent permissions end when you quit."))
            }
            if let message = model.message {
                Text(message).font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            }
            Button {
                model.lockEverything()
                read()
            } label: {
                Label(T("Lock everything"), systemImage: "lock.fill").frame(maxWidth: .infinity)
            }
            .buttonStyle(EmergencyButtonStyle())
            .help(T("Ends every agent permission, locks Keyreeve and pauses agents until you resume them."))
        }
        .padding(14)
        .frame(width: 340)
        .background(Theme.background)
        .onAppear {
            open = true
            read()
        }
        .onDisappear { open = false }
        .onReceive(ticker) { _ in if open { read() } }
    }

    private var pausedBanner: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(T("Agents are paused"), systemImage: "pause.circle.fill").font(Theme.rowTitle).foregroundStyle(Theme.bad)
            Text(T("Every agent is refused until you resume them.")).font(Theme.caption).foregroundStyle(Theme.muted)
            Button(T("Resume agents"), action: model.resumeAgents).buttonStyle(KRButtonStyle())
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.bad.opacity(0.12), in: RoundedRectangle(cornerRadius: Theme.smallRadius))
    }

    private var requests: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(T("Requests"), systemImage: "hand.raised.fill").font(Theme.section).foregroundStyle(Theme.accent)
            ForEach(model.pendingRequests, id: \.id) { request in
                HStack {
                    Text(request.kind == "sort"
                         ? T("%@ proposes sorting your keys", request.agent)
                         : request.kind == AgentBringing.kind
                         ? T("%@ proposes bringing in keys", request.agent)
                         : request.isRotation
                         ? T("%@ asks to rotate %@", request.agent, request.key ?? request.provider)
                         : T("%@ asks for a %@ key", request.agent, request.provider))
                        .font(Theme.body).foregroundStyle(Theme.text).lineLimit(1)
                    Spacer(minLength: 6)
                    Button(T("Answer")) {
                        model.showRequests += 1
                        openWindow()
                    }
                    .buttonStyle(KRButtonStyle(primary: true))
                }
            }
        }
    }

    private var openNow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(T("Open now")).font(Theme.section).foregroundStyle(Theme.text)
                Spacer()
                if !grants.isEmpty {
                    Button(T("Close all")) {
                        model.endAgentApprovals()
                        grants = []
                    }
                    .buttonStyle(KRButtonStyle())
                }
            }
            if grants.isEmpty {
                Text(T("No agent holds a key now.")).font(Theme.caption).foregroundStyle(Theme.muted)
            }
            ForEach(grants, id: \.id) { grant in
                HStack {
                    Image(systemName: "key.fill").foregroundStyle(Theme.accent)
                    Text(grant.key).font(Theme.rowTitle).foregroundStyle(Theme.text)
                    Text(grant.program == KeyService.anyProgram ? T("any command") : grant.program)
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                    Spacer()
                    Text(T("until %@", grant.expires.formatted(date: .omitted, time: .shortened)))
                        .font(Theme.caption).foregroundStyle(Theme.faint)
                }
            }
        }
    }

    private var latest: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(T("Latest uses")).font(Theme.section).foregroundStyle(Theme.text)
            ForEach(Array(runs.prefix(4).enumerated()), id: \.offset) { _, run in
                HStack(spacing: 6) {
                    Circle().fill(run.exit == 0 ? Theme.good : Theme.bad).frame(width: 6, height: 6)
                    Text("\(run.agent) · \(run.key) · \(run.command.split(separator: " ").first.map(String.init) ?? "")")
                        .font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1)
                    Spacer()
                    Text(run.at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
                }
            }
        }
    }

    /// Names and times only. The service answers without a fingerprint, and the transcript is a file.
    private func read() {
        model.reloadRequests()
        let files = model.files
        let store = model.vaultStore
        Task.detached {
            let grants = (try? KeySocket.send(KeyService.Request(op: "grants"), path: files.keySocket.path, timeout: 1))?.grants ?? []
            let runs = AgentTranscript(url: files.directory.appendingPathComponent(AgentTranscript.fileName)).entries(limit: 4)
            let news = ArrivalNews.read(files: files, store: store)
            await MainActor.run {
                self.grants = grants.sorted { $0.expires < $1.expires }
                self.runs = runs
                if self.news != news { self.news = news }
            }
        }
    }
}

/// The menu bar's icon: a key, with the number of requests waiting, or a pause sign when stopped.
public struct MenuBarLabel: View {
    @ObservedObject var model: AppModel
    /// The icon stays current with the menu closed: requests and the pause, which are small files.
    private let ticker = Timer.publish(every: 3, on: .main, in: .common).autoconnect()
    public init(model: AppModel) { self.model = model }

    public var body: some View {
        icon.onReceive(ticker) { _ in
            model.reloadRequests()
            model.reloadIfIndexChanged()
        }
    }

    @ViewBuilder private var icon: some View {
        if model.agentsPaused {
            Image(systemName: "pause.circle")
        } else if model.pendingRequests.isEmpty {
            Image(systemName: "key.horizontal")
        } else {
            HStack(spacing: 2) {
                Image(systemName: "key.horizontal.fill")
                Text("\(model.pendingRequests.count)")
            }
        }
    }
}

struct EmergencyButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.rowTitle)
            .foregroundStyle(.white)
            .padding(.vertical, 7)
            .background(Theme.bad.opacity(configuration.isPressed ? 0.75 : 1), in: RoundedRectangle(cornerRadius: Theme.smallRadius))
    }
}
