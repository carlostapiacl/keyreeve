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
    case "gone": return T("Not in the vault")
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
    @State private var confirmCheck = false
    @State private var sorting = false
    /// The keys chosen when Sort was pressed, asked about even when sorted already. None means every unsorted key.
    @State private var sortingKeys: [CatalogItem]?
    /// What this view worked out from the keys, kept until the keys, the filter or the search change.
    @State private var memo = ViewMemo()

    public init(model: AppModel, initial: Sidebar = .home, chosen: CatalogItem.ID? = nil) {
        self.model = model
        _selection = State(initialValue: initial)
        _chosenRows = State(initialValue: chosen.map { [$0] } ?? [])
    }

    private var items: [CatalogItem] { model.items }
    /// A filter of My keys, apart from the sidebar's choice: a list row cannot be selected for a filter
    /// with no row, and the sidebar would drop it and show every key.
    @State private var filterOverride: Sidebar?
    /// What the list shows: a filter when one is on, else the sidebar's section.
    private var current: Sidebar { filterOverride ?? selection ?? .all }

    /// Goes to a section or a filter. Sections are sidebar rows; a filter shows My keys with it on.
    private func go(_ target: Sidebar) {
        switch target {
        case .home, .all, .attention, .vault, .agents, .providers, .rotation, .log:
            filterOverride = nil
            selection = target
        default:
            selection = .all
            filterOverride = target
        }
    }

    /// The sidebar's own choice. Clicking a row there takes any filter off.
    private var sidebarSelection: Binding<Sidebar?> {
        Binding(get: { filterOverride == nil ? selection : .all }, set: { value in
            filterOverride = nil
            selection = value
        })
    }

    private var shown: [CatalogItem] {
        memo.value("shown", key: [AnyHashable(model.itemsVersion), current, search]) { filter(items, by: current, search: search) }
    }

    private var chosenItem: CatalogItem? {
        guard chosenRows.count == 1, let path = chosenRows.first else { return nil }
        // Only from what the list shows, so the detail never speaks of a key another filter hid.
        return memo.value("chosen", key: [AnyHashable(model.itemsVersion), current, search, path]) { shown.first { $0.path == path } }
    }

    private var scope: [CatalogItem] {
        memo.value("scope", key: [AnyHashable(model.itemsVersion), current, search, chosenRows]) {
            chosenRows.isEmpty ? shown : shown.filter { chosenRows.contains($0.id) }
        }
    }
    private var checkable: [CatalogItem] {
        memo.value("checkable", key: [AnyHashable(model.itemsVersion), current, search, chosenRows]) { scope.filter(model.providers.canCheck) }
    }
    private var identifiable: [CatalogItem] {
        memo.value("identifiable", key: [AnyHashable(model.itemsVersion), current, search, chosenRows]) { scope.filter(model.providers.canIdentify) }
    }

    public var body: some View {
        NavigationSplitView {
            // By task, not by part of the app: what you have, what needs you, how it is kept. The tools follow.
            List(selection: sidebarSelection) {
                Label(T("Home"), systemImage: "house").tag(Sidebar.home)
                sidebarRow(T("My keys"), "key", .all, model.summary.active)
                sidebarRow(T("To review"), "exclamationmark.circle", .attention, model.summary.toReview)
                Label(T("Security and backup"), systemImage: "lock.shield").tag(Sidebar.vault)
                Section(T("Tools")) {
                    // A request waiting shows here and in the menu bar, and never moves you away from what you were doing.
                    if model.pendingRequests.isEmpty {
                        sidebarRow(T("Agents"), "cpu", .agents, model.agentPolicy.keys.count)
                    } else {
                        Label {
                            HStack {
                                Text(T("Agents")).lineLimit(1)
                                Spacer()
                                Text(T("%d waiting", model.pendingRequests.count))
                                    .font(Theme.caption).foregroundStyle(Theme.onAccent)
                                    .padding(.horizontal, 6).padding(.vertical, 1)
                                    .background(Theme.accent, in: Capsule())
                            }
                        } icon: {
                            Image(systemName: "hand.raised.fill")
                        }
                        .tag(Sidebar.agents)
                    }
                    Label(T("Rotation"), systemImage: "arrow.triangle.2.circlepath").tag(Sidebar.rotation)
                    Label(T("Log"), systemImage: "list.bullet.rectangle").tag(Sidebar.log)
                    Label(T("Providers"), systemImage: "puzzlepiece.extension").tag(Sidebar.providers)
                }
            }
            .tint(Theme.accent)
            .navigationSplitViewColumnWidth(min: 190, ideal: 220)
        } detail: {
            VStack(spacing: 0) {
                content
                statusBar
            }
            // Work in progress shows at the top where it is seen, and the app stays usable meanwhile.
            .safeAreaInset(edge: .top, spacing: 0) { if model.busy { WorkingBanner(message: model.message, progress: model.progress) } }
            .background(Theme.background)
            .navigationTitle(title)
            .toolbar { toolbar }
            // An agent's request opens the app: show it where it is answered.
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.reloadRequests()
            }
            .onChange(of: model.showRequests) { _, _ in go(.agents) }
            .sheet(isPresented: $sorting) { SortSheet(model: model, keys: sortingKeys) }
            .confirmationDialog(
                T("Check %d keys?", checkable.count), isPresented: $confirmCheck, titleVisibility: .visible
            ) {
                Button(T("Check %d keys", checkable.count)) { model.check(checkable) }
                Button(T("Cancel"), role: .cancel) {}
            } message: {
                Text(T("Each key goes to its own provider, and only to read. Keys set to Only me stay out."))
            }
            .onAppear {
                if !model.pendingRequests.isEmpty { go(.agents) }
                // A start on a filter, such as from a link, goes through the same path.
                if let start = selection { go(start) }
            }
        }
    }

    @ViewBuilder private var content: some View {
        if selection == .home {
            HomeView(
                stats: model.summary.stats, activity: model.activity, model: model,
                checkAll: {
                    go(.checkable)
                    confirmCheck = true
                }
            ) { target, path in
                go(target)
                search = ""
                chosenRows = path.map { [$0] } ?? []
            }
        } else if selection == .vault {
            VaultView(model: model, part: .security) { go($0) }
        } else if selection == .rotation {
            VaultView(model: model, part: .rotation) { go($0) }
        } else if selection == .log {
            UsageLogSheet(model: model, inline: true)
        } else if selection == .agents {
            AgentsView(model: model)
        } else if selection == .providers {
            ProvidersView(model: model)
        } else {
            HStack(spacing: 0) {
                if shown.isEmpty {
                    emptyList.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    keyList
                }
                if let chosenItem {
                    Rectangle().fill(Theme.border).frame(width: 1)
                    // Wide enough to read without truncating, with the technical parts behind a disclosure.
                    KeyDetail(item: chosenItem, model: model).frame(width: 440)
                }
            }
            // An inset, not the first row of a stack: a scroll view at the column's top edge reaches under the
            // toolbar, and its chips are drawn below it while the clicks land behind the toolbar.
            .safeAreaInset(edge: .top, spacing: 0) { filterBar }
            .searchable(text: $search, prompt: T("Search by name or tag"))
        }
    }

    /// One click to the views people use most. The chips wrap to a second line instead of scrolling: a
    /// scroll view at the top of the column reaches under the toolbar, where its clicks are lost.
    private var filterBar: some View {
        FlowRow(spacing: 6) {
            filterChip(T("All"), .all)
            filterChip(T("Can be checked"), .checkable)
            filterChip(T("Critical keys"), .critical)
            filterChip(T("Rejected"), .result("rejected"))
            filterChip(T("Works"), .result("works"))
            filterChip(T("No answer"), .result("no_answer"))
            filterChip(T("Never checked"), .result(""))
            filterChip(T("Older than suggested"), .stale)
            filterChip(T("Expire soon"), .expiring)
            filterChip(T("Archive"), .archive)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface)
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.border).frame(height: 1) }
    }

    private func filterChip(_ title: String, _ target: Sidebar) -> some View {
        FilterChip(
            title: title, count: model.summary.count(target),
            isOn: (pressedChip ?? current) == target
        ) {
            // Filtering a long list takes a moment, so the chip answers first and the list follows.
            pressedChip = target
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(30))
                go(target)
                chosenRows = []
                pressedChip = nil
            }
        }
    }

    private var title: String {
        switch filterOverride ?? selection ?? .home {
        case .home: return T("Home")
        case .attention: return T("To review")
        case .all: return T("My keys")
        case .archive: return T("Archive")
        case .vault: return T("Security and backup")
        case .agents: return T("Agents")
        case .rotation: return T("Rotation")
        case .log: return T("Log")
        case .providers: return T("Providers")
        case .checkable: return T("Can be checked")
        case .critical: return T("Critical keys")
        case .stale: return T("Older than suggested")
        case .internalOnly: return T("Internal secrets")
        case .expiring: return T("Expire soon")
        case .result(let result): return resultName(result)
        case .level(let level): return levelName(level)
        case .tag(let tag): return tag
        }
    }

    /// Says why the list is empty, and the one step that helps.
    @ViewBuilder private var emptyList: some View {
        if !search.trimmingCharacters(in: .whitespaces).isEmpty {
            EmptyHint(
                title: T("Nothing matches “%@”", search), text: T("Search looks in names, files, notes and what providers said."),
                action: T("Clear the search"), run: { search = "" })
        } else if current == .attention {
            EmptyHint(
                title: T("No alerts found."), text: T("Keys asking for attention will show here."),
                action: T("See my keys"), run: { go(.all) })
        } else if items.isEmpty {
            EmptyHint(
                title: T("No keys yet"), text: T("Paste a key, or choose the folder that holds your key files."),
                action: T("Add a key"), run: { model.startAddingKey() })
        } else if current == .checkable {
            EmptyHint(
                title: T("No key can be checked yet"), text: T("Open a key and choose its provider, under More details and options."),
                action: T("See my keys"), run: { go(.all) })
        } else if current == .archive {
            EmptyHint(title: T("Nothing archived"), text: T("Archiving hides a key from your lists. It does not stop it."))
        } else {
            EmptyHint(
                title: T("No keys in this view"), text: T("Another filter may show them."),
                action: T("See my keys"), run: { go(.all) })
        }
    }

    private var keyList: some View {
        // Worked out once for the whole list, not once for each row.
        let compact = chosenItem != nil
        return List(shown, selection: $chosenRows) { item in
            KeyRow(item: item, compact: compact)
                .listRowSeparatorTint(Theme.border)
                .listRowBackground(Color.clear)
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
    }

    /// Sections that show the list of keys, where filters and checks belong. The tool sections have their own.
    private var showsList: Bool {
        switch selection ?? .all {
        case .home, .vault, .agents, .providers, .rotation, .log: return false
        default: return true
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .automatic) {
            Button {
                model.startAddingKey()
            } label: {
                Label(T("Add a key"), systemImage: "plus")
            }
            .help(T("Paste a key and seal it, with no file"))
        }
        if showsList {
            ToolbarItem(placement: .automatic) {
                Menu {
                    Button(T("All keys")) { go(.all) }
                    Button(T("Critical keys")) { go(.critical) }
                    Button(T("Older than suggested")) { go(.stale) }
                    Button(T("Internal secrets")) { go(.internalOnly) }
                    Button(T("Can be checked")) { go(.checkable) }
                    Divider()
                    ForEach(["free", "ask", "never", "none"], id: \.self) { level in
                        Button(levelName(level)) { go(.level(level)) }
                    }
                    Divider()
                    Button(T("Archive")) { go(.archive) }
                    // Projects were sidebar rows; they are filters of My keys now.
                    Menu(T("Projects")) {
                        ForEach(model.summary.projects, id: \.tag) { entry in
                            Button("\(entry.tag) (\(entry.count))") { go(.tag(entry.tag)) }
                        }
                    }
                } label: {
                    Label(T("Show"), systemImage: "line.3.horizontal.decrease.circle")
                }
            }
            ToolbarItem(placement: .automatic) {
                // Several chosen keys: one provider for all, or nothing to check.
                if chosenRows.count > 1 {
                    Menu {
                        ForEach(model.providers.all.filter { $0.problem == nil }.sorted { $0.name < $1.name }) { provider in
                            Button(provider.name) { model.assign(provider: provider.id, to: scope) }
                        }
                        Divider()
                        Button(T("Nothing to check")) { model.markUntestable(scope) }
                        Button(T("Ask what they are")) {
                            sortingKeys = scope
                            sorting = true
                        }
                    } label: {
                        Label(T("Provider for %d", chosenRows.count), systemImage: "tag")
                    }
                } else {
                    Button {
                        sortingKeys = chosenRows.isEmpty ? nil : scope
                        sorting = true
                    } label: {
                        Label(chosenRows.isEmpty ? T("Sort keys") : T("Ask what it is"), systemImage: "wand.and.stars")
                    }
                    .help(chosenRows.isEmpty
                        ? T("Propose a provider for keys keyreeve cannot check yet")
                        : T("Ask your assistant what this key is, from its name and fields, never its value"))
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
                    // Several keys go out to their providers: the same question the Home screen used to ask.
                    if checkable.count > 1 { confirmCheck = true } else { model.check(checkable) }
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
            // While something runs, the banner at the top says so; here stays what it last said.
            if !model.busy, let message = model.message { Text(message).foregroundStyle(Theme.text) }
            Spacer()
            if showsList { Text(T("%d of %d", shown.count, model.summary.active)).monospacedDigit() }
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.muted)
        .padding(.horizontal, 14)
        .frame(height: 26)
        .background(Theme.surface)
        .overlay(alignment: .top) { Rectangle().fill(Theme.border).frame(height: 1) }
    }
}

/// Keeps what a view worked out until what it was worked out from changes. A plain class, so filling it
/// while drawing does not ask for another draw.
final class ViewMemo {
    private var kept: [String: (key: AnyHashable, value: Any)] = [:]

    func value<V>(_ name: String, key: [AnyHashable], _ make: () -> V) -> V {
        let key = AnyHashable(key)
        if let entry = kept[name], entry.key == key, let value = entry.value as? V { return value }
        let value = make()
        kept[name] = (key, value)
        return value
    }
}

/// Says what the app is doing while it works, with how far it got when that is known.
struct WorkingBanner: View {
    let message: String?
    let progress: (done: Int, total: Int)?

    var body: some View {
        HStack(spacing: 10) {
            if let progress, progress.total > 0 {
                ProgressView(value: Double(progress.done), total: Double(progress.total))
                    .progressViewStyle(.linear).tint(Theme.onAccent).frame(width: 160)
            } else {
                ProgressView().controlSize(.small).tint(Theme.onAccent)
            }
            Text(message ?? T("Working…")).fontWeight(.semibold)
            if let progress, progress.total > 0 {
                Text(T("%d of %d keys", progress.done, progress.total)).monospacedDigit().opacity(0.8)
            }
            Spacer()
            Text(T("You can keep using the app")).opacity(0.8)
        }
        .font(.system(size: 12))
        .foregroundStyle(Theme.onAccent)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .background(Theme.accent)
        .accessibilityElement(children: .combine)
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
