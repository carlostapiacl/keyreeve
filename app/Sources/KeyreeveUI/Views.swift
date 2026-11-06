import AppKit
import KeyreeveCatalog
import SwiftUI

/// Plain words for each access level. The stored values stay the same in every language.
func levelName(_ level: String) -> String {
    switch level {
    case "free": return T("Agents can use it")
    case "ask": return T("Ask me")
    case "never": return T("Only me")
    default: return T("Not secret")
    }
}

/// The app once unlocked: a sidebar, then the overview or a list.
public struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var selection: Sidebar?
    @State private var search = ""
    @State private var chosenRows: Set<CatalogItem.ID>

    public init(model: AppModel, initial: Sidebar = .home, chosen: CatalogItem.ID? = nil) {
        self.model = model
        _selection = State(initialValue: initial)
        _chosenRows = State(initialValue: chosen.map { [$0] } ?? [])
    }

    private var items: [CatalogItem] { model.items }
    private var shown: [CatalogItem] { filter(items, by: selection ?? .all, search: search) }
    private var toReview: Int { items.filter { $0.attention != nil }.count }

    private var chosenItem: CatalogItem? {
        guard chosenRows.count == 1, let path = chosenRows.first else { return nil }
        return items.first { $0.path == path }
    }

    private var checkable: [CatalogItem] {
        let base = chosenRows.isEmpty ? shown : shown.filter { chosenRows.contains($0.id) }
        return base.filter(\.canCheck)
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label(T("Overview"), systemImage: "gauge.with.dots.needle.33percent").tag(Sidebar.home)
                sidebarRow(T("To review"), "exclamationmark.circle", .attention, toReview)
                sidebarRow(T("All keys"), "key", .all, items.count)
                Section(T("Projects")) {
                    ForEach(projectTags(in: items), id: \.tag) { entry in
                        sidebarRow(entry.tag, "folder", .tag(entry.tag), entry.count)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 220)
        } detail: {
            VStack(spacing: 0) {
                content
                Divider()
                footer
            }
            .navigationTitle(title)
            .toolbar { toolbar }
        }
    }

    @ViewBuilder private var content: some View {
        if selection == .home {
            HomeView(stats: CatalogStats(items: items), activity: model.activity, model: model) { target, path in
                selection = target
                search = ""
                chosenRows = path.map { [$0] } ?? []
            }
        } else {
            HStack(spacing: 0) {
                if shown.isEmpty {
                    emptyList.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    table
                }
                if let chosenItem {
                    Divider()
                    KeyDetail(item: chosenItem, model: model).frame(width: 280)
                }
            }
            .searchable(text: $search, prompt: T("Search by name or tag"))
        }
    }

    private var title: String {
        switch selection ?? .home {
        case .home: return T("Overview")
        case .attention: return T("To review")
        case .all: return T("All keys")
        case .checkable: return T("Can be checked")
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

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        if selection != .home {
            ToolbarItem(placement: .automatic) {
                Menu {
                    Button(T("All keys")) { selection = .all }
                    Button(T("Can be checked")) { selection = .checkable }
                    Divider()
                    ForEach(["free", "ask", "never", "none"], id: \.self) { level in
                        Button(levelName(level)) { selection = .level(level) }
                    }
                } label: {
                    Label(T("Show"), systemImage: "line.3.horizontal.decrease.circle")
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.check(checkable)
                } label: {
                    Label(checkTitle, systemImage: "checkmark.shield").labelStyle(.titleAndIcon)
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

    private var checkTitle: String {
        checkable.count == 1 ? T("Check 1 key") : T("Check %d keys", checkable.count)
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
                Text("\(count)").foregroundStyle(.secondary).monospacedDigit()
            }
        } icon: {
            Image(systemName: icon)
        }
        .tag(value)
    }

    private var table: some View {
        Table(shown, selection: $chosenRows) {
            TableColumn(T("Key")) { item in
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.path).lineLimit(1).truncationMode(.middle)
                    if let attention = item.attention {
                        Text(attention).font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            .width(min: 180, ideal: 260)
            TableColumn(T("Who can use it")) { item in LevelText(level: item.level) }
                .width(min: 90, ideal: 120)
            TableColumn(T("Last check")) { item in ResultText(item: item) }
                .width(min: 110, ideal: 150)
            TableColumn(T("Tags")) { item in
                Text(item.tags.filter { !$0.hasPrefix("kind:") }.joined(separator: "  "))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(item.tags.joined(separator: "\n"))
            }
            .width(min: 90, ideal: 130)
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if model.busy { ProgressView().controlSize(.small) }
            if let message = model.message { Text(message).foregroundStyle(.primary) }
            Spacer()
            if selection != .home { Text(T("%d of %d", shown.count, items.count)).monospacedDigit() }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .frame(height: 26)
        .background(.bar)
    }
}

/// One key's details, which can be edited here. It never holds a value.
struct KeyDetail: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var newTag = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(item.path).font(.headline).textSelection(.enabled)
                if let attention = item.attention {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(attention, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        ActionButtons(item: item, model: model)
                    }
                }
                fact(T("Last check")) { ResultText(item: item) }
                fact(T("Who can use it")) {
                    Picker("", selection: levelBinding) {
                        Text(T("Agents can use it")).tag("free")
                        Text(T("Ask me each time")).tag("ask")
                        Text(T("Only me")).tag("never")
                        Text(T("Not secret")).tag("none")
                    }
                    .labelsHidden()
                }
                if item.isSecret { checkPlace }
                fact(T("Tags")) { tagEditor }
                fact(T("File changed")) { Text(item.modified).monospacedDigit() }
                if !item.format.isEmpty { fact(T("Format")) { Text(item.format) } }
                fact(T("Permissions")) { Text(item.mode).monospacedDigit() }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var levelBinding: Binding<String> {
        Binding(get: { item.level }, set: { model.save(KeyEdit(level: $0), for: item) })
    }

    /// One provider, or several set by hand elsewhere, which stay until someone changes them.
    private var recipeBinding: Binding<String> {
        Binding(
            get: { item.recipes.joined(separator: " ") },
            set: { value in
                model.save(KeyEdit(recipes: value.split(separator: " ").map(String.init)), for: item)
            })
    }

    @ViewBuilder private var checkPlace: some View {
        fact(T("Where to check")) {
            VStack(alignment: .leading, spacing: 6) {
                Picker("", selection: recipeBinding) {
                    Text(T("Nobody")).tag("")
                    ForEach(Providers.checkable, id: \.self) { Text(Providers.displayName($0)).tag($0) }
                    if item.recipes.count > 1 {
                        Text(item.recipes.map(Providers.displayName).joined(separator: ", ")).tag(item.recipes.joined(separator: " "))
                    }
                }
                .labelsHidden()
                Text(T("The key is sent to this company to check it. Choose only the company it belongs to."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
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
                }
                .labelsHidden()
            }
        }
    }

    private var tagEditor: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(item.tags.filter { !$0.hasPrefix("kind:") }, id: \.self) { tag in
                HStack(spacing: 4) {
                    Text(tag).lineLimit(1)
                    Spacer()
                    Button {
                        model.save(KeyEdit(tags: item.tags.filter { $0 != tag }), for: item)
                    } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
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

    private func fact<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            content()
        }
    }
}

struct ActionButtons: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    var body: some View {
        FlowRow(spacing: 6) {
            ForEach(actions(for: item), id: \.self) { action in
                let main = action == actions(for: item).first
                Button(action.title) { model.perform(action, on: item) }
                    .controlSize(.small)
                    .disabled(model.busy)
                    .buttonStyle(main ? AnyPrimitiveButtonStyle(.borderedProminent) : AnyPrimitiveButtonStyle(.bordered))
            }
        }
    }
}

/// Lets one button stand out in a row, which SwiftUI's style types do not allow directly.
struct AnyPrimitiveButtonStyle: PrimitiveButtonStyle {
    private let make: (Configuration) -> AnyView
    init<S: PrimitiveButtonStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

/// Lays out buttons in rows, because translated labels differ in length.
struct FlowRow: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var (x, y, row, widest): (CGFloat, CGFloat, CGFloat, CGFloat) = (0, 0, 0, 0)
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width {
                y += row + spacing
                x = 0
                row = 0
            }
            x += size.width + spacing
            row = max(row, size.height)
            widest = max(widest, x - spacing)
        }
        return CGSize(width: widest, height: y + row)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var (x, y, row) = (bounds.minX, bounds.minY, CGFloat(0))
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX {
                y += row + spacing
                x = bounds.minX
                row = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            row = max(row, size.height)
        }
    }
}

struct LevelText: View {
    let level: String
    var body: some View {
        switch level {
        case "never": Label(levelName(level), systemImage: "lock.fill").labelStyle(.titleOnly).foregroundStyle(.primary)
        case "none": Text(levelName(level)).foregroundStyle(.secondary)
        default: Text(levelName(level))
        }
    }
}

struct ResultText: View {
    let item: CatalogItem
    var body: some View {
        switch item.lastResult {
        case "works": line(T("Works"), "checkmark.circle.fill", .green)
        case "rejected": line(T("Rejected"), "xmark.circle.fill", .red)
        case "forbidden", "no_result": line(T("No answer"), "questionmark.circle", .secondary)
        default: Text(item.isSecret ? T("Never checked") : "").foregroundStyle(.tertiary)
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
            Text(T("Keyreeve is locked")).font(.title3)
            if let message {
                Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            Button(T("Unlock"), action: unlock).keyboardShortcut(.defaultAction)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// The first screen anyone sees: one decision, and no Terminal.
public struct WelcomeView: View {
    let choose: () -> Void
    let busy: Bool

    public init(busy: Bool = false, choose: @escaping () -> Void) {
        self.busy = busy
        self.choose = choose
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "key.viewfinder")
                .font(.system(size: 48, weight: .light))
                .foregroundStyle(Color.accentColor)
            Text(T("Your keys, without showing them")).font(.title2)
            Text(T("A short list of what to do, and a way to confirm it got done."))
                .foregroundStyle(.secondary)
            if busy {
                ProgressView().controlSize(.small).padding(.top, 6)
            } else {
                Button(T("Choose your keys folder"), action: choose)
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
                    .padding(.top, 6)
            }
            Text(T("Scanning sends nothing out of this Mac. Keyreeve reads your files to describe them, and saves no value."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

/// Settings, in the standard window (Command-comma).
public struct SettingsView: View {
    @ObservedObject var model: AppModel
    @AppStorage(Language.settingsKey) private var language = Language.system.rawValue
    @AppStorage(SettingsKey.appearance) private var appearance = "system"
    @AppStorage(SettingsKey.lockMinutes) private var lockMinutes = 5
    @AppStorage(SettingsKey.scanOnOpen) private var scanOnOpen = true

    public init(model: AppModel) { self.model = model }

    public var body: some View {
        Form {
            Section(T("General")) {
                Picker(T("Language"), selection: $language) {
                    Text(T("System")).tag(Language.system.rawValue)
                    Text("English").tag(Language.english.rawValue)
                    Text("Español").tag(Language.spanish.rawValue)
                }
                Picker(T("Appearance"), selection: $appearance) {
                    Text(T("System")).tag("system")
                    Text(T("Light")).tag("light")
                    Text(T("Dark")).tag("dark")
                }
                Picker(T("Lock after"), selection: $lockMinutes) {
                    ForEach([1, 5, 15, 60], id: \.self) { Text("\($0) \(T("minutes"))").tag($0) }
                }
                Toggle(T("Scan when opening"), isOn: $scanOnOpen)
            }
            Section(T("Files")) {
                LabeledContent(T("Folder")) {
                    HStack {
                        Text(model.keysFolder?.path ?? T("None"))
                            .lineLimit(1)
                            .truncationMode(.head)
                            .foregroundStyle(.secondary)
                        Button(T("Change"), action: model.chooseFolder)
                    }
                }
                Button(T("Show the app's files")) {
                    NSWorkspace.shared.open(model.files.directory)
                }
            }
            Section(T("About")) {
                Text(T("Version %@", Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"))
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .id(language)
    }
}
