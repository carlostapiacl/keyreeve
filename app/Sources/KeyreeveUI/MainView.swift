import AppKit
import KeyreeveCatalog
import SwiftUI

/// Plain words for each access level. The stored values stay the same in every language.
func levelName(_ level: String) -> String {
    switch level {
    case "free": return T("Checked without asking")
    case "ask": return T("Ask me")
    case "never": return T("Only me")
    default: return T("Not secret")
    }
}

func resultName(_ result: String) -> String {
    switch result {
    case "works": return T("Works")
    case "rejected": return T("Rejected")
    case "no_answer": return T("No answer")
    default: return T("Never checked")
    }
}

/// The app once unlocked: a sidebar, then the overview or a list.
public struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var selection: Sidebar?
    @State private var search = ""
    @State private var pressedChip: Sidebar?
    @State private var chosenRows: Set<CatalogItem.ID>

    public init(model: AppModel, initial: Sidebar = .home, chosen: CatalogItem.ID? = nil) {
        self.model = model
        _selection = State(initialValue: initial)
        _chosenRows = State(initialValue: chosen.map { [$0] } ?? [])
    }

    private var items: [CatalogItem] { model.items }
    private var shown: [CatalogItem] { filter(items, by: selection ?? .all, search: search) }
    private var active: [CatalogItem] { items.filter { !$0.isArchived } }
    private var toReview: Int { items.filter { $0.attention != nil }.count }

    private var chosenItem: CatalogItem? {
        guard chosenRows.count == 1, let path = chosenRows.first else { return nil }
        return items.first { $0.path == path }
    }

    private var scope: [CatalogItem] {
        chosenRows.isEmpty ? shown : shown.filter { chosenRows.contains($0.id) }
    }
    private var checkable: [CatalogItem] { scope.filter(model.providers.canCheck) }
    private var identifiable: [CatalogItem] { scope.filter(model.providers.canIdentify) }

    public var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label(T("Overview"), systemImage: "square.grid.2x2").tag(Sidebar.home)
                sidebarRow(T("To review"), "exclamationmark.circle", .attention, toReview)
                sidebarRow(T("All keys"), "key", .all, active.count)
                sidebarRow(T("Vault"), "lock.shield", .vault, filter(items, by: .vault, search: "").count)
                sidebarRow(T("Agents"), "cpu", .agents, model.agentPolicy.keys.count)
                sidebarRow(T("Archive"), "archivebox", .archive, items.count - active.count)
                Section(T("Projects")) {
                    ForEach(projectTags(in: active), id: \.tag) { entry in
                        sidebarRow(entry.tag, "folder", .tag(entry.tag), entry.count)
                    }
                }
            }
            .tint(Theme.accent)
            .navigationSplitViewColumnWidth(min: 190, ideal: 220)
        } detail: {
            VStack(spacing: 0) {
                content
                statusBar
            }
            .background(Theme.background)
            .navigationTitle(title)
            .toolbar { toolbar }
            // An agent's request opens the app: show it where it is answered.
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.reloadRequests()
            }
            .onChange(of: model.pendingRequests.map(\.id)) { old, new in
                if !Set(new).subtracting(old).isEmpty { selection = .agents }
            }
        }
    }

    @ViewBuilder private var content: some View {
        if selection == .home {
            HomeView(stats: CatalogStats(items: items), activity: model.activity, model: model) { target, path in
                selection = target
                search = ""
                chosenRows = path.map { [$0] } ?? []
            }
        } else if selection == .vault {
            VaultView(model: model)
        } else if selection == .agents {
            AgentsView(model: model)
        } else {
            VStack(spacing: 0) {
                filterBar
                HStack(spacing: 0) {
                if shown.isEmpty {
                    emptyList.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    keyList
                }
                if let chosenItem {
                    Rectangle().fill(Theme.border).frame(width: 1)
                    KeyDetail(item: chosenItem, model: model).frame(width: 300)
                }
                }
            }
            .searchable(text: $search, prompt: T("Search by name or tag"))
        }
    }

    /// One click to the views people use most.
    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                filterChip(T("All"), .all)
                filterChip(T("Can be checked"), .checkable)
                filterChip(T("Critical keys"), .critical)
                filterChip(T("Rejected"), .result("rejected"))
                filterChip(T("Works"), .result("works"))
                filterChip(T("No answer"), .result("no_answer"))
                filterChip(T("Never checked"), .result(""))
                filterChip(T("Older than suggested"), .stale)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
        .background(Theme.surface)
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.border).frame(height: 1) }
    }

    private func filterChip(_ title: String, _ target: Sidebar) -> some View {
        FilterChip(
            title: title, count: filter(items, by: target, search: "").count,
            isOn: (pressedChip ?? selection) == target
        ) {
            // Filtering a long list takes a moment, so the chip answers first and the list follows.
            pressedChip = target
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(30))
                selection = target
                chosenRows = []
                pressedChip = nil
            }
        }
    }

    private var title: String {
        switch selection ?? .home {
        case .home: return T("Overview")
        case .attention: return T("To review")
        case .all: return T("All keys")
        case .archive: return T("Archive")
        case .vault: return T("Vault")
        case .agents: return T("Agents")
        case .checkable: return T("Can be checked")
        case .critical: return T("Critical keys")
        case .stale: return T("Older than suggested")
        case .internalOnly: return T("Internal secrets")
        case .result(let result): return resultName(result)
        case .level(let level): return levelName(level)
        case .tag(let tag): return tag
        }
    }

    @ViewBuilder private var emptyList: some View {
        if selection == .attention {
            ContentUnavailableView(
                T("Everything looks fine."), systemImage: "checkmark.seal",
                description: Text(T("Keys asking for attention will show here.")))
        } else {
            ContentUnavailableView(T("No keys here"), systemImage: "key")
        }
    }

    private var keyList: some View {
        List(shown, selection: $chosenRows) { item in
            KeyRow(item: item, compact: chosenItem != nil)
                .listRowSeparatorTint(Theme.border)
                .listRowBackground(Color.clear)
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        if selection != .home {
            ToolbarItem(placement: .automatic) {
                Menu {
                    Button(T("All keys")) { selection = .all }
                    Button(T("Critical keys")) { selection = .critical }
                    Button(T("Older than suggested")) { selection = .stale }
                    Button(T("Internal secrets")) { selection = .internalOnly }
                    Button(T("Can be checked")) { selection = .checkable }
                    Divider()
                    ForEach(["free", "ask", "never", "none"], id: \.self) { level in
                        Button(levelName(level)) { selection = .level(level) }
                    }
                } label: {
                    Label(T("Show"), systemImage: "line.3.horizontal.decrease.circle")
                }
            }
            ToolbarItem(placement: .automatic) {
                Button {
                    model.identify(identifiable)
                } label: {
                    Label(
                        identifiable.count == 1 ? T("Identify 1 key") : T("Identify %d keys", identifiable.count),
                        systemImage: "person.text.rectangle"
                    )
                    .labelStyle(.titleAndIcon)
                }
                .disabled(model.busy || identifiable.isEmpty)
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.check(checkable)
                } label: {
                    Label(
                        checkable.count == 1 ? T("Check 1 key") : T("Check %d keys", checkable.count),
                        systemImage: "checkmark.shield"
                    )
                    .labelStyle(.titleAndIcon)
                }
                .disabled(model.busy || checkable.isEmpty)
                .help(checkHelp)
            }
        }
        ToolbarItem(placement: .automatic) {
            Button {
                model.refresh()
            } label: {
                Label(T("Refresh"), systemImage: "arrow.clockwise")
            }
            .disabled(model.busy)
            .help(T("Scan the folder again"))
        }
    }

    private var checkHelp: String {
        if !checkable.isEmpty { return T("One read-only request to each provider. Some need your fingerprint.") }
        return shown.first { chosenRows.contains($0.id) }?.whyNoCheck ?? T("Choose where to check it")
    }

    private func sidebarRow(_ title: String, _ icon: String, _ value: Sidebar, _ count: Int) -> some View {
        Label {
            HStack {
                Text(title).lineLimit(1)
                Spacer()
                Text("\(count)").font(Theme.caption).foregroundStyle(Theme.muted).monospacedDigit()
            }
        } icon: {
            Image(systemName: icon)
        }
        .tag(value)
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            if model.busy { ProgressView().controlSize(.mini) }
            if let progress = model.progress {
                Text(T("%d of %d keys", progress.done, progress.total)).monospacedDigit()
            } else if let message = model.message { Text(message).foregroundStyle(Theme.text) }
            Spacer()
            if selection != .home { Text(T("%d of %d", shown.count, active.count)).monospacedDigit() }
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.muted)
        .padding(.horizontal, 14)
        .frame(height: 26)
        .background(Theme.surface)
        .overlay(alignment: .top) { Rectangle().fill(Theme.border).frame(height: 1) }
    }
}

/// One filter above the list. It shows it can be pressed before anything is pressed.
struct FilterChip: View {
    let title: String
    let count: Int
    let isOn: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Text(title).lineLimit(1)
                Text("\(count)").monospacedDigit().foregroundStyle(isOn ? Theme.onAccent.opacity(0.8) : Theme.faint)
            }
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(isOn ? Theme.onAccent : Theme.text)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(isOn ? Theme.accent : hovering ? Theme.border : Theme.raised, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .onHover { inside in
            hovering = inside
            if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
        }
        .onDisappear { if hovering { NSCursor.pop() } }
        .accessibilityAddTraits(isOn ? [.isSelected] : [])
    }
}
