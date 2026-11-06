import KeyreeveCatalog
import SwiftUI

public struct CatalogView: View {
    let items: [CatalogItem]
    let source: String
    let reload: () -> Void
    let check: ([CatalogItem]) -> Void
    let checking: Bool
    let message: String?
    let activity: [ActivityItem]
    @State private var selection: Sidebar? = .home
    @State private var search = ""
    @State private var chosenRows = Set<CatalogItem.ID>()

    public init(
        items: [CatalogItem], source: String, reload: @escaping () -> Void = {},
        check: @escaping ([CatalogItem]) -> Void = { _ in }, checking: Bool = false, message: String? = nil,
        activity: [ActivityItem] = [], initial: Sidebar = .home, chosen: CatalogItem.ID? = nil
    ) {
        self.activity = activity
        _selection = State(initialValue: initial)
        _chosenRows = State(initialValue: chosen.map { [$0] } ?? [])
        self.items = items
        self.source = source
        self.reload = reload
        self.check = check
        self.checking = checking
        self.message = message
    }

    /// What the button would check: the selected rows, or else everything shown.
    private var checkable: [CatalogItem] {
        let base = chosenRows.isEmpty ? shown : shown.filter { chosenRows.contains($0.id) }
        return base.filter(\.canCheck)
    }

    private var shown: [CatalogItem] {
        filter(items, by: selection ?? .all, search: search)
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Overview", systemImage: "gauge.with.dots.needle.33percent").tag(Sidebar.home)
                row("All keys", .all, items.count)
                row("Needs a look", .attention, items.filter { $0.attention != nil }.count)
                row("Can be checked", .checkable, items.filter(\.canCheck).count)
                Section("Access") {
                    row("Free", .level("free"), count("free"))
                    row("Ask each time", .level("ask"), count("ask"))
                    row("Never", .level("never"), count("never"))
                    row("Not secret", .level("none"), count("none"))
                }
                Section("Projects") {
                    ForEach(projectTags(in: items), id: \.tag) { entry in
                        row(entry.tag, .tag(entry.tag), entry.count)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 220)
        } detail: {
            if selection == .home {
                VStack(spacing: 0) {
                    HomeView(stats: CatalogStats(items: items), activity: activity) { target, path in
                        selection = target
                        search = ""
                        chosenRows = path.map { [$0] } ?? []
                    }
                    Divider()
                    footer
                }
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 0) {
                        table
                        if let chosenItem {
                            Divider()
                            KeyDetail(item: chosenItem).frame(width: 270)
                        }
                    }
                    Divider()
                    footer
                }
                .searchable(text: $search, prompt: "Name or tag")
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            check(checkable)
                        } label: {
                            if checking {
                                ProgressView().controlSize(.small)
                            } else {
                                Label(checkTitle, systemImage: "checkmark.shield").labelStyle(.titleAndIcon)
                            }
                        }
                        .disabled(checking || checkable.isEmpty)
                        .help(checkHelp)
                    }
                }
            }
        }
    }

    private var chosenItem: CatalogItem? {
        guard chosenRows.count == 1, let path = chosenRows.first else { return nil }
        return items.first { $0.path == path }
    }

    private var checkTitle: String {
        checkable.count == 1 ? "Check 1 key" : "Check \(checkable.count) keys"
    }

    private var checkHelp: String {
        if !checkable.isEmpty {
            return "One read-only request to each provider. Keys set to ask need your fingerprint."
        }
        let picked = shown.first { chosenRows.contains($0.id) }
        return picked?.whyNoCheck ?? "None of these keys has a recipe assigned"
    }

    private func count(_ level: String) -> Int { items.filter { $0.level == level }.count }

    private func row(_ title: String, _ value: Sidebar, _ count: Int) -> some View {
        HStack {
            Text(title).lineLimit(1)
            Spacer()
            Text("\(count)").foregroundStyle(.secondary).monospacedDigit()
        }
        .tag(value)
    }

    private var table: some View {
        Table(shown, selection: $chosenRows) {
            TableColumn("Key") { item in
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.path).lineLimit(1).truncationMode(.middle)
                    if let attention = item.attention {
                        Text(attention).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            .width(min: 180, ideal: 240)
            TableColumn("Access") { item in LevelText(level: item.level) }
                .width(70)
            TableColumn("Last check") { item in ResultText(item: item) }
                .width(min: 110, ideal: 140)
            TableColumn("Tags") { item in
                Text(item.tags.joined(separator: "  "))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(item.tags.joined(separator: "\n"))
            }
            .width(min: 90, ideal: 130)
            TableColumn("Changed") { item in
                Text(item.modified).foregroundStyle(.secondary).monospacedDigit()
            }
            .width(min: 70, ideal: 76)
        }
    }

    private var footer: some View {
        HStack {
            Text("\(shown.count) of \(items.count)").monospacedDigit()
            if let message { Text(message).foregroundStyle(.primary) }
            Spacer()
            Text(source).lineLimit(1).truncationMode(.head)
            Button("Refresh", action: reload).controlSize(.small).help("Scan the folder again")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
    }
}

/// One key's details, beside the table. It shows names and results, and never a value.
struct KeyDetail: View {
    let item: CatalogItem

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(item.path).font(.headline).textSelection(.enabled)
                if let attention = item.attention {
                    Label(attention, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                fact("Access") { LevelText(level: item.level) }
                fact("Last check") { ResultText(item: item) }
                if let why = item.whyNoCheck {
                    fact("Checking") { Text(why).foregroundStyle(.secondary) }
                } else {
                    fact("Checks with") { Text(item.recipes.joined(separator: ", ")) }
                }
                if !item.format.isEmpty { fact("Format") { Text(item.format) } }
                fact("File changed") { Text(item.modified).monospacedDigit() }
                fact("Permissions") { Text(item.mode).monospacedDigit() }
                if !item.tags.isEmpty {
                    fact("Tags") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(item.tags, id: \.self) { Text($0) }
                        }
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func fact<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            content()
        }
    }
}

struct LevelText: View {
    let level: String
    var body: some View {
        switch level {
        case "never": Text("never").foregroundStyle(.red)
        case "free": Text("free").foregroundStyle(.green)
        case "none": Text("not secret").foregroundStyle(.secondary)
        default: Text(level)
        }
    }
}

struct ResultText: View {
    let item: CatalogItem
    var body: some View {
        switch item.lastResult {
        case "works": line("Works", "checkmark.circle.fill", .green)
        case "rejected": line("Rejected", "xmark.circle.fill", .red)
        case "forbidden", "no_result": line("No answer", "questionmark.circle", .secondary)
        default: Text(item.isSecret ? "Never checked" : "").foregroundStyle(.tertiary)
        }
    }

    private func line(_ title: String, _ icon: String, _ color: Color) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon).foregroundStyle(color).imageScale(.small)
            Text(title)
            Text(item.lastChecked).font(.caption).foregroundStyle(.secondary).monospacedDigit()
        }
    }
}

public struct LockedView: View {
    let message: String?
    let unlock: () -> Void

    public init(message: String?, unlock: @escaping () -> Void) {
        self.message = message
        self.unlock = unlock
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "touchid")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.secondary)
            Text("Keyreeve is locked").font(.title3)
            if let message {
                Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            Button("Unlock", action: unlock)
                .keyboardShortcut(.defaultAction)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

public struct EmptyCatalogView: View {
    let problem: String
    let path: String

    public init(problem: String, path: String) {
        self.problem = problem
        self.path = path
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(problem).font(.title3)
            Text("Keyreeve reads a catalog from \(path). Make one in Terminal:")
                .foregroundStyle(.secondary)
            Text(
                """
                keyreeve inventory ~/my-keys --out ~/.keyreeve/inventory.json
                keyreeve catalog ~/.keyreeve/inventory.json --out ~/.keyreeve/catalog.csv
                """
            )
            .font(.system(.callout, design: .monospaced))
            .textSelection(.enabled)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}
