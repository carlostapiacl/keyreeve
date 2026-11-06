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
        let on = selection == target
        let count = filter(items, by: target, search: "").count
        return Button {
            selection = target
            chosenRows = []
        } label: {
            HStack(spacing: 5) {
                Text(title).lineLimit(1)
                Text("\(count)").monospacedDigit().foregroundStyle(on ? Theme.onAccent.opacity(0.8) : Theme.faint)
            }
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(on ? Theme.onAccent : Theme.text)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(on ? Theme.accent : Theme.raised, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    private var title: String {
        switch selection ?? .home {
        case .home: return T("Overview")
        case .attention: return T("To review")
        case .all: return T("All keys")
        case .archive: return T("Archive")
        case .vault: return T("Vault")
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

/// One key in a list: its name first, and the file as a detail.
struct KeyRow: View {
    let item: CatalogItem
    /// With the details open, the row keeps only what fits comfortably.
    let compact: Bool

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 5) {
                    Text(item.title).font(Theme.rowTitle).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    if item.vault != .none {
                        Image(systemName: "lock.shield.fill")
                            .font(Theme.caption)
                            .foregroundStyle(item.vault == .sealed ? Theme.good : Theme.warn)
                            .help(T(item.vault == .sealed ? "In the vault" : "The file changed after it was sealed"))
                            .accessibilityLabel(T(item.vault == .sealed ? "In the vault" : "The file changed after it was sealed"))
                    }
                }
                if !item.name.isEmpty {
                    Text(item.path).font(Theme.code).foregroundStyle(Theme.faint).lineLimit(1).truncationMode(.middle)
                }
                if let attention = item.attention {
                    Text(attention).font(Theme.caption).foregroundStyle(Theme.warn)
                } else if let account = item.details?.fields["account"] {
                    Text(account).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if !compact {
                HStack(spacing: 4) {
                    ForEach(visibleTags, id: \.self) { Chip(text: $0) }
                }
            }
            HStack {
                if item.criticality > 0 {
                    CriticalityMeter(value: item.criticality, suggested: item.criticalitySuggested)
                        .help(
                            "\(T("Criticality")): \(criticalityName(item.criticality))"
                                + (item.criticalitySuggested ? ". \(T("Suggested by the provider's file"))" : ""))
                }
            }
            .frame(width: 34, alignment: .leading)
            HStack {
                Spacer(minLength: 0)
                ResultBadge(item: item)
            }
            .frame(width: 112)
            if !compact {
                Text(levelName(item.level))
                    .font(Theme.caption)
                    .foregroundStyle(item.level == "never" ? Theme.text : Theme.muted)
                    .frame(width: 128, alignment: .trailing)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 5)
    }

    private var visibleTags: [String] {
        item.tags.filter { !$0.contains(":") && !["revoke", "confirm"].contains($0) }.prefix(2).map { $0 }
    }
}

struct ResultBadge: View {
    let item: CatalogItem

    var body: some View {
        switch item.lastResult {
        case "works": Badge(text: T("Works"), icon: "checkmark", tone: .good).help(item.lastChecked)
        case "rejected": Badge(text: T("Rejected"), icon: "xmark", tone: .bad).help(item.lastChecked)
        case "forbidden", "no_result": Badge(text: T("No answer"), icon: "questionmark", tone: .neutral)
        default:
            if item.isSecret {
                Text(T("Never checked")).font(Theme.caption).foregroundStyle(Theme.faint)
            }
        }
    }
}

/// One key's details, which can be edited here. It never holds a value.
struct KeyDetail: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var newTag = ""
    @State private var name = ""
    @State private var note = ""
    @State private var confirmArchive = false
    @State private var host = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if let attention = item.attention {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(attention, systemImage: "exclamationmark.triangle.fill")
                            .font(Theme.body).foregroundStyle(Theme.warn)
                            .fixedSize(horizontal: false, vertical: true)
                        ActionButtons(item: item, model: model)
                    }
                }
                checkButton
                if item.vault != .none { vaultNote }
                customActions
                identity
                naming
                criticality
                if item.isSecret { checkPlace }
                fact(T("Who can use it")) {
                    Picker("", selection: levelBinding) {
                        Text(T("Agents can use it")).tag("free")
                        Text(T("Ask me each time")).tag("ask")
                        Text(T("Only me")).tag("never")
                        Text(T("Not secret")).tag("none")
                    }
                    .labelsHidden()
                }
                fact(T("Tags")) { tagEditor }
                fileFacts
                archiveButton
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
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
    }

    private var vaultNote: some View {
        Label(
            T(item.vault == .sealed ? "In the vault. Checks use the sealed copy." : "The file changed after it was sealed. Checks use the file."),
            systemImage: "lock.shield"
        )
        .font(Theme.caption)
        .foregroundStyle(item.vault == .sealed ? Theme.muted : Theme.warn)
        .fixedSize(horizontal: false, vertical: true)
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
            if let why = item.whyNoCheck {
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
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(item.title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                .textSelection(.enabled)
            Text(item.path).font(Theme.code).foregroundStyle(Theme.faint).textSelection(.enabled)
            HStack(spacing: 6) {
                ResultBadge(item: item)
                if item.criticality > 0 {
                    CriticalityMeter(value: item.criticality, suggested: item.criticalitySuggested)
                }
                if !item.lastChecked.isEmpty {
                    Text(item.lastChecked).font(Theme.caption).foregroundStyle(Theme.faint).monospacedDigit()
                }
            }
            .padding(.top, 4)
            if !item.lastReason.isEmpty {
                Text(item.lastReason).font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
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
        }
    }

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
                    Text(T("None")).tag("")
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
                .foregroundStyle(Theme.accent)
            Text(T("Keyreeve is locked")).font(.system(size: 17, weight: .semibold)).foregroundStyle(Theme.text)
            if let message {
                Text(message).foregroundStyle(Theme.muted).multilineTextAlignment(.center)
            }
            Button(T("Unlock"), action: unlock)
                .buttonStyle(KRButtonStyle(primary: true))
                .keyboardShortcut(.defaultAction)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
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
            Image(systemName: "key.fill")
                .font(.system(size: 34))
                .foregroundStyle(Theme.accent)
                .frame(width: 72, height: 72)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 18))
                .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(Theme.border))
            Text(T("Your keys, without showing them")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("A short list of what to do, and a way to confirm it got done.")).foregroundStyle(Theme.muted)
            if busy {
                ProgressView().controlSize(.small).padding(.top, 6)
            } else {
                Button(T("Choose your keys folder"), action: choose)
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
                    .padding(.top, 6)
            }
            Text(T("Scanning sends nothing out of this Mac. Keyreeve reads your files to describe them, and saves no value."))
                .font(Theme.caption)
                .foregroundStyle(Theme.muted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
    }
}

/// Settings, in the standard window (Command-comma).
public struct SettingsView: View {
    @ObservedObject var model: AppModel
    @AppStorage(Language.settingsKey) private var language = Language.system.rawValue
    @AppStorage(SettingsKey.appearance) private var appearance = "system"
    @AppStorage(SettingsKey.lockMinutes) private var lockMinutes = 5
    @AppStorage(SettingsKey.scanOnOpen) private var scanOnOpen = true
    @AppStorage(SettingsKey.fingerprintMinutes) private var fingerprintMinutes = 5
    @State private var weekly = WeeklySchedule.isOn

    public init(model: AppModel) { self.model = model }

    public var body: some View {
        TabView {
            general.tabItem { Label(T("General"), systemImage: "gearshape") }
            providers.tabItem { Label(T("Providers"), systemImage: "puzzlepiece.extension") }
        }
        .frame(width: 520, height: 460)
        .id(language)
    }

    private var general: some View {
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
            Section {
                Picker(T("Ask for my fingerprint again after"), selection: $fingerprintMinutes) {
                    Text(T("Every time")).tag(0)
                    ForEach([1, 5, 15, 30], id: \.self) { Text("\($0) \(T("minutes"))").tag($0) }
                }
            } footer: {
                Text(T("While this lasts, the app can check keys without asking. Locking it ends the period, and the vault always asks."))
                    .font(.caption)
            }
            Section {
                Toggle(T("Weekly check"), isOn: $weekly)
                    .onChange(of: weekly) { WeeklySchedule.set(weekly, binary: model.commandURL) }
            } footer: {
                Text(T("Check keys set to Agents can use it every Monday, and notify me if one stops working. It needs no fingerprint, so it covers only those."))
                    .font(.caption)
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
                Button(T("Show the app's files")) { NSWorkspace.shared.open(model.files.directory) }
            }
            Section(T("About")) {
                Text(T("Version %@", Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"))
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func providerLine(_ provider: ProviderInfo) -> String {
        if let problem = provider.problem { return problem }
        if let programs = provider.programs, !programs.isEmpty {
            return T("Runs %@", programs.joined(separator: ", "))
        }
        return T("Sent only to %@", provider.hosts.joined(separator: ", "))
    }

    /// A file that runs a program gets a plain warning, because this is the one thing that runs code.
    private func approve(_ provider: ProviderInfo) {
        guard let programs = provider.programs, !programs.isEmpty else {
            model.approve(provider)
            return
        }
        let alert = NSAlert()
        alert.messageText = T("This file runs programs on your Mac")
        alert.informativeText = T("Approve only if you wrote it or read it. Programs: %@", programs.joined(separator: ", "))
        alert.alertStyle = .warning
        alert.addButton(withTitle: T("Approve"))
        alert.addButton(withTitle: T("Cancel"))
        if alert.runModal() == .alertFirstButtonReturn { model.approve(provider) }
    }

    private var providers: some View {
        Form {
            Section {
                ForEach(model.providers.all) { provider in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(provider.name.isEmpty ? provider.id : provider.name)
                            Text(providerLine(provider))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                        Spacer()
                        if provider.needsApproval {
                            Button(T("Approve")) { approve(provider) }
                        } else if provider.source == "local" {
                            Text(T("Your file")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } footer: {
                Text(T("Your files can add more providers, in ~/.keyreeve/providers. Each one needs your approval before it receives a key."))
                    .font(.caption)
            }
        }
        .formStyle(.grouped)
    }
}
