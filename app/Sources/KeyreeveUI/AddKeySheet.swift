import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Paste a key, see which provider it is, name it, and it is sealed. The key itself is never shown:
/// only its known start and its length.
struct AddKeySheet: View {
    @ObservedObject var model: AppModel
    @State private var hours: Int? = 1

    private static let durations: [Int?] = AccessDecision.hourChoices.map { $0 } + [nil]

    var body: some View {
        let draft = model.addingKey
        VStack(alignment: .leading, spacing: 14) {
            Text(draft?.request.map { T("%@ asks for a %@ key", $0.agent, $0.provider) } ?? T("Add a key"))
                .font(Theme.title).foregroundStyle(Theme.text)
            if let reason = draft?.request?.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.body).foregroundStyle(Theme.muted)
            }
            Text(T("Copy the key from your provider, then paste it here. It goes straight into the vault and the clipboard is cleared."))
                .font(Theme.body).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                Button {
                    model.pasteKey()
                } label: {
                    Label(T("Paste from the clipboard"), systemImage: "doc.on.clipboard")
                }
                .buttonStyle(KRButtonStyle(primary: draft?.value == nil))
                if let hint = draft?.hint {
                    Label(hint, systemImage: "checkmark.seal.fill").font(Theme.code).foregroundStyle(Theme.good)
                }
                Spacer()
                if let url = model.dashboard(of: draft?.provider) {
                    Link(destination: url) {
                        Label(T("Make one at %@", providerName(draft?.provider)), systemImage: "arrow.up.right.square")
                    }
                    .font(Theme.body)
                }
            }

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 10) {
                GridRow {
                    Text(T("Provider")).font(Theme.body).foregroundStyle(Theme.muted)
                    Picker(T("Provider"), selection: providerBinding) {
                        Text(T("Choose…")).tag(String?.none)
                        ForEach(model.providers.all.filter { $0.problem == nil }.sorted { $0.name < $1.name }) { info in
                            Text(info.name).tag(String?.some(info.id))
                        }
                    }
                    .labelsHidden().fixedSize()
                    .disabled(draft?.request != nil)
                }
                GridRow {
                    Text(T("Name")).font(Theme.body).foregroundStyle(Theme.muted)
                    TextField(T("Name"), text: nameBinding).textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                }
                if draft?.request != nil {
                    GridRow {
                        Text(T("For how long")).font(Theme.body).foregroundStyle(Theme.muted)
                        Picker(T("For how long"), selection: $hours) {
                            ForEach(Self.durations, id: \.self) { value in
                                Text(value.map { T("For %d h", $0) } ?? T("Always")).tag(value)
                            }
                        }
                        .labelsHidden().fixedSize()
                    }
                }
            }

            HStack {
                Spacer()
                Button(T("Cancel"), action: model.cancelAddingKey).buttonStyle(KRButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button(draft?.request == nil ? T("Save") : T("Save and allow")) { model.saveAddedKey(hours: hours) }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
                    .disabled(draft?.value == nil || draft?.provider == nil || (draft?.name.trimmingCharacters(in: .whitespaces).isEmpty ?? true))
            }
        }
        .padding(24)
        .frame(width: 520)
        .background(Theme.background)
        .onAppear { hours = draft?.request.map { Self.durations.contains($0.hours) ? $0.hours : 1 } ?? 1 }
    }

    private func providerName(_ id: String?) -> String {
        model.providers.all.first { $0.id == id }?.name ?? id ?? ""
    }

    private var providerBinding: Binding<String?> {
        Binding(get: { model.addingKey?.provider }, set: { value in
            model.addingKey?.provider = value
            if let value, model.addingKey?.name.isEmpty ?? true { model.addingKey?.name = model.freeIdentifier(value) }
        })
    }

    private var nameBinding: Binding<String> {
        Binding(get: { model.addingKey?.name ?? "" }, set: { model.addingKey?.name = $0 })
    }
}
