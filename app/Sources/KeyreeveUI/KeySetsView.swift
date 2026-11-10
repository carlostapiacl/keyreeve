import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Key sets, under Agents: the keys a project needs, asked for in one window with one fingerprint, and the
/// permissions given "always, for this program in this folder".
struct KeySetsCard: View {
    @ObservedObject var model: AppModel
    @State private var sets = KeySets()
    @State private var editing: KeySets.Set?
    @State private var editingName: String?
    @State private var showingSuggestions = false

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("Key sets"))
                    Spacer()
                    Button(T("Make a set from what this project used")) { showingSuggestions.toggle() }
                        .buttonStyle(KRButtonStyle())
                    Button(T("New set")) {
                        editingName = nil
                        editing = KeySets.Set(name: "", keys: [])
                    }
                    .buttonStyle(KRButtonStyle())
                }
                Text(T("The keys a project needs, asked for in one window with one fingerprint: keyreeve-vault use --set NAME -- command. A set grants nothing on its own."))
                    .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                if showingSuggestions { suggestions }
                if sets.sets.isEmpty {
                    Text(T("No set yet.")).font(Theme.caption).foregroundStyle(Theme.muted)
                }
                ForEach(sets.sets) { set in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(set.name).font(Theme.rowTitle).foregroundStyle(Theme.text)
                            Text(set.keys.joined(separator: ", ")).font(Theme.code).foregroundStyle(Theme.muted)
                                .fixedSize(horizontal: false, vertical: true)
                            if let folder = set.folder {
                                Text((folder as NSString).abbreviatingWithTildeInPath).font(Theme.caption).foregroundStyle(Theme.faint)
                            }
                        }
                        Spacer(minLength: 4)
                        Button(T("Edit")) {
                            editingName = set.name
                            editing = set
                        }
                        .buttonStyle(KRButtonStyle())
                        Button(T("Remove")) {
                            model.removeSet(set.name)
                            reload()
                        }
                        .buttonStyle(KRButtonStyle())
                    }
                }
                if !sets.standing.isEmpty { standing }
            }
            .padding(14)
        }
        .onAppear(perform: reload)
        .sheet(item: $editing) { set in
            KeySetEditor(model: model, set: set, original: editingName) {
                editing = nil
                reload()
            }
        }
    }

    private func reload() { sets = model.loadSets() }

    private var suggestions: some View {
        let found = model.setSuggestions
        return VStack(alignment: .leading, spacing: 6) {
            if found.isEmpty {
                Text(T("Nothing used two or more keys from one folder in the last hour."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
            }
            ForEach(found) { suggestion in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\((suggestion.folder as NSString).abbreviatingWithTildeInPath) · \(suggestion.program)")
                            .font(Theme.caption).foregroundStyle(Theme.text)
                        Text(suggestion.keys.joined(separator: ", ")).font(Theme.code).foregroundStyle(Theme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 4)
                    // A suggestion only: the editor opens with it, and nothing is saved until the person saves.
                    Button(T("Review")) {
                        editingName = nil
                        editing = KeySets.Set(name: sets.suggestedName(for: suggestion.folder), keys: suggestion.keys, folder: suggestion.folder)
                    }
                    .buttonStyle(KRButtonStyle())
                }
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: Theme.radius).fill(Theme.border.opacity(0.25)))
    }

    private var standing: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(T("Always, for one program in one folder")).font(Theme.caption).foregroundStyle(Theme.muted).padding(.top, 6)
            ForEach(sets.standing) { grant in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    VStack(alignment: .leading, spacing: 1) {
                        let program = URL(fileURLWithPath: grant.program).lastPathComponent
                            + (grant.script.map { " " + URL(fileURLWithPath: $0).lastPathComponent } ?? "")
                        Text("\(program) · \((grant.folder as NSString).abbreviatingWithTildeInPath)")
                            .font(Theme.code).foregroundStyle(Theme.text)
                        Text(grant.keys.joined(separator: ", ")).font(Theme.caption).foregroundStyle(Theme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 4)
                    Button(T("Remove")) {
                        model.removeStanding(grant)
                        reload()
                    }
                    .buttonStyle(KRButtonStyle())
                }
            }
        }
    }
}

/// Makes or changes one set. Only keys offered to agents can be chosen.
struct KeySetEditor: View {
    @ObservedObject var model: AppModel
    @State var set: KeySets.Set
    let original: String?
    let done: () -> Void
    @State private var filter = ""

    init(model: AppModel, set: KeySets.Set, original: String?, done: @escaping () -> Void) {
        self.model = model
        _set = State(initialValue: set)
        self.original = original
        self.done = done
    }

    private var offered: [KeyIndex.Key] {
        model.keyIndex.keys.filter { filter.isEmpty || $0.id.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(original == nil ? T("New set") : T("Edit set")).font(.headline).foregroundStyle(Theme.text)
            TextField(T("Name, such as weekly-report"), text: $set.name).textFieldStyle(.roundedBorder)
            TextField(T("Folder, optional"), text: Binding(get: { set.folder ?? "" }, set: { set.folder = $0 }))
                .textFieldStyle(.roundedBorder)
            TextField(T("Filter by key"), text: $filter).textFieldStyle(.roundedBorder)
            List(offered) { key in
                Toggle(isOn: Binding(
                    get: { set.keys.contains(key.id) },
                    set: { on in
                        if on { set.keys.append(key.id) } else { set.keys.removeAll { $0 == key.id } }
                    })
                ) {
                    Text(key.id + (key.account.map { " (\($0))" } ?? "")).font(Theme.code)
                }
            }
            .frame(minHeight: 240)
            Text(T("%d keys chosen. Only keys offered to agents are listed.", set.keys.count))
                .font(Theme.caption).foregroundStyle(Theme.muted)
            HStack {
                Spacer()
                Button(T("Cancel")) { done() }.buttonStyle(KRButtonStyle())
                Button(T("Save")) { if model.saveSet(set, replacing: original) { done() } }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(!KeySets.isValid(name: set.name) || set.keys.isEmpty)
            }
        }
        .padding(16)
        .frame(minWidth: 460, minHeight: 480)
    }
}
