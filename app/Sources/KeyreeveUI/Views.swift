import KeyreeveCatalog
import SwiftUI

public struct CatalogView: View {
    let items: [CatalogItem]
    let source: String
    let reload: () -> Void
    @State private var selection: Sidebar? = .attention
    @State private var search = ""
    @State private var chosenRow: CatalogItem.ID?

    public init(items: [CatalogItem], source: String, reload: @escaping () -> Void = {}) {
        self.items = items
        self.source = source
        self.reload = reload
    }

    private var shown: [CatalogItem] {
        filter(items, by: selection ?? .all, search: search)
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                row("All keys", .all, items.count)
                row("Needs a look", .attention, items.filter { $0.attention != nil }.count)
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
            VStack(spacing: 0) {
                table
                Divider()
                footer
            }
            .searchable(text: $search, prompt: "Name or tag")
        }
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
        Table(shown, selection: $chosenRow) {
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
            Spacer()
            Text(source).lineLimit(1).truncationMode(.head)
            Button("Reload", action: reload).controlSize(.small)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
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
        case "works": line("Works", .green)
        case "rejected": line("Rejected", .red)
        case "forbidden": line("No answer", .secondary)
        case "no_result": line("No answer", .secondary)
        default: Text(item.isSecret ? "Never checked" : "").foregroundStyle(.tertiary)
        }
    }

    private func line(_ title: String, _ color: Color) -> some View {
        HStack(spacing: 6) {
            Text(title).foregroundStyle(color)
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
    }
}
