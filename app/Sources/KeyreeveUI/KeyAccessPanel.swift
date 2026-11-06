import KeyreeveCatalog
import SwiftUI

/// What a person can do with a sealed key: copy it, and say which programs agents may run with it.
struct KeyAccessPanel: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    private var allowed: [String] { model.agentPolicy.commands[item.path] ?? [] }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            CopyKeyButton(item: item, model: model)
            Text(T("Agents")).font(Theme.caption).foregroundStyle(Theme.muted).padding(.top, 6)
            Text(allowed.isEmpty ? T("No agent can use this key.") : T("Programs an agent may run with this key. Each use asks for your finger, and the agent never gets the value."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(allowed, id: \.self) { program in
                HStack(spacing: 6) {
                    Text(URL(fileURLWithPath: program).lastPathComponent)
                        .font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                        .help(program)
                    Spacer(minLength: 4)
                    Button {
                        model.disallow(program: program, for: item)
                    } label: {
                        Image(systemName: "xmark.circle")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.muted)
                    .accessibilityLabel(T("Remove"))
                }
            }
            Button(T("Allow a program")) {
                model.chooseProgram { model.allow(program: $0, for: item) }
            }
            .buttonStyle(KRButtonStyle())
        }
    }
}

/// Copies a sealed key. A file with named values asks which one, since "the key" could be any of them.
struct CopyKeyButton: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    var body: some View {
        if item.field.isEmpty && item.labels.count > 1 {
            Menu {
                ForEach(item.labels, id: \.self) { label in
                    Button(label) { model.copyKey(item, field: label) }
                }
                Divider()
                Button(T("Whole file")) { model.copyKey(item, field: nil, wholeFile: true) }
            } label: {
                Label(T("Copy the key"), systemImage: "doc.on.doc")
            }
            .fixedSize()
            .disabled(model.busy)
        } else {
            Button {
                model.copyKey(item, field: item.field.isEmpty ? item.labels.first : item.field)
            } label: {
                Label(T("Copy the key"), systemImage: "doc.on.doc")
            }
            .buttonStyle(KRButtonStyle())
            .disabled(model.busy)
        }
    }
}
