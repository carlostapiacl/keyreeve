import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// What a person can do with a sealed key: copy it, and say which programs agents may run with it.
struct KeyAccessPanel: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    @State private var newID = ""
    @State private var newField = ""

    /// Every identifier of the file, offered to agents or not: the person sees them all.
    private var identifiers: [KeyIndex.Key] { model.keyIndex.allKeys(forSource: item.path) }
    private var allowed: [String] { identifiers.flatMap { model.agentPolicy.commands[$0.id] ?? [] } }

    /// How agents reach this key through the proxy, as the permissions say now, one line per identifier.
    private var openToAgents: [String] {
        let policy = model.agentPolicy
        return identifiers.compactMap { key in
            guard let level = policy.level(of: key.id), policy.levels[key.id] != nil else { return nil }
            let who = (policy.agents[key.id] ?? []).isEmpty ? T("any agent") : (policy.agents[key.id] ?? []).joined(separator: ", ")
            var line = "\(key.id): " + level.label + " · " + who
            if let closes = policy.until[key.id] { line += " · " + T("Open until %@", closes.formatted(date: .omitted, time: .shortened)) }
            return line
        }
    }

    var body: some View {
        // Copying lives in the key's header, the first thing on its page.
        VStack(alignment: .leading, spacing: 8) {
            identifierSection
            Text(T("Agents")).font(Theme.caption).foregroundStyle(Theme.muted).padding(.top, 6)
            // From the same permissions the agents read, so this never says less than what is open.
            ForEach(openToAgents, id: \.self) { line in
                Text(line).font(Theme.caption).foregroundStyle(Theme.text)
            }
            if openToAgents.isEmpty && allowed.isEmpty {
                Text(T("No agent can use this key.")).font(Theme.caption).foregroundStyle(Theme.muted)
            }
            if !allowed.isEmpty {
                Text(T("Programs an agent may run with this key. Each use asks for your finger, and the program gets the value."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
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
            .disabled(identifiers.isEmpty)
        }
        .onAppear { newID = model.suggestedIdentifier(for: item) }
        .onChange(of: item.path) { newID = model.suggestedIdentifier(for: item) }
    }

    private var identifierSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(T("Identifier")).font(Theme.caption).foregroundStyle(Theme.muted).padding(.top, 6)
            ForEach(identifiers) { key in
                HStack(spacing: 6) {
                    Text(key.id).font(Theme.code).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    if let field = key.field { Text(field).font(Theme.caption).foregroundStyle(Theme.faint).lineLimit(1) }
                    AccountField(key: key, model: model)
                    Button {
                        model.removeIdentifier(key.id)
                    } label: {
                        Image(systemName: "xmark.circle")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.muted)
                    .accessibilityLabel(T("Remove"))
                }
                // A key with no provider has nowhere to go but a service of yours, approved by address.
                if key.provider == nil || key.local != nil {
                    LocalServiceRow(key: key, model: model)
                }
                Toggle(T("Offered to agents"), isOn: Binding(
                    get: { model.keyIndex.isOffered(key.id) },
                    set: { model.setOffered($0, id: key.id) }))
                    .toggleStyle(.checkbox)
                    .font(Theme.caption)
                    .help(model.keyIndex.isOffered(key.id)
                        ? T("Agents see its name and can ask for it. Unchecked, they do not see it, and it closes.")
                        : T("Agents do not see this key. Checked, they see its name and can ask for it."))
            }
            if identifiers.isEmpty {
                Text(T("What you and your agents call this key."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 6) {
                TextField(T("Identifier"), text: $newID)
                    .textFieldStyle(.roundedBorder)
                    .font(Theme.code)
                    .autocorrectionDisabled()
                if item.labels.count > 1 {
                    Picker("", selection: $newField) {
                        Text(T("Field")).tag("")
                        ForEach(item.labels, id: \.self) { Text($0).tag($0) }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 100)
                }
                Button(T("Add")) {
                    model.addIdentifier(newID, for: item, field: newField.isEmpty ? nil : newField)
                    newID = model.suggestedIdentifier(for: item)
                }
                .buttonStyle(KRButtonStyle())
                .disabled(newID.isEmpty)
            }
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

/// Whose key this is, filled by the provider when it can say, and by you when it cannot.
struct AccountField: View {
    let key: KeyIndex.Key
    @ObservedObject var model: AppModel
    @State private var text = ""

    var body: some View {
        TextField(T("Account"), text: $text)
            .textFieldStyle(.roundedBorder)
            .font(Theme.caption)
            .onAppear { text = key.account ?? "" }
            .onChange(of: key.account) { text = key.account ?? "" }
            .onSubmit { model.setAccount(text, of: key.id) }
    }
}

/// Where a key that a service of yours on this Mac checks may go: one loopback address and port, approved with your
/// finger. Typing it is not approving it, and an address keys.toml names that you did not approve waits here.
struct LocalServiceRow: View {
    let key: KeyIndex.Key
    @ObservedObject var model: AppModel
    @State private var text = ""

    private var approved: String? {
        guard let approved = model.approvedLocalService(of: key.id), key.local.flatMap(LocalServices.address) == approved
        else { return nil }
        return approved
    }

    var body: some View {
        HStack(spacing: 6) {
            if let approved {
                Text(T("Goes to %@ on this Mac", approved)).font(Theme.caption).foregroundStyle(Theme.text)
                    .help(T("Agents use it through the proxy, over plain HTTP, and only toward this address and port."))
                Spacer(minLength: 4)
                Button(T("Remove")) { model.removeLocalService(for: key.id) }
                    .buttonStyle(KRButtonStyle())
            } else {
                TextField(T("Local service, such as 127.0.0.1:8790"), text: $text)
                    .textFieldStyle(.roundedBorder)
                    .font(Theme.caption)
                    .autocorrectionDisabled()
                Button(T("Approve")) { model.approveLocalService(text, for: key.id) }
                    .buttonStyle(KRButtonStyle())
                    .disabled(text.isEmpty)
                    .help(T("With your fingerprint, this key may go to this address on this Mac, and nowhere else."))
            }
        }
        .onAppear { text = key.local ?? "" }
        .onChange(of: key.local) { text = key.local ?? "" }
    }
}
