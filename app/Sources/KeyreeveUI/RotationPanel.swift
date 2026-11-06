import AppKit
import KeyreeveCatalog
import SwiftUI

/// Sets up and starts a rotation for one key. Nothing reaches the provider until the last button.
struct RotationPanel: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var confirming = false
    @State private var newKey = ""

    private var places: KeyPlaces { model.places[item.path] ?? KeyPlaces() }
    private var provider: ProviderInfo? { model.providers.rotator(of: item) }
    private var isOpen: Bool { model.rotations.contains { $0.key == item.path && $0.isOpen } }

    private var yourActions: [(id: String, title: String)] {
        model.providers.usable.flatMap { provider in
            (provider.actions ?? []).filter { $0.run != nil }.map { (id: "\(provider.id)/\($0.id)", title: $0.title) }
        }
    }

    private func change(_ edit: (inout KeyPlaces) -> Void) {
        var value = places
        edit(&value)
        model.savePlaces(value, for: item)
    }

    var body: some View {
        if let provider {
            VStack(alignment: .leading, spacing: 8) {
                Text(T("Rotate")).font(Theme.caption).foregroundStyle(Theme.muted)
                content(provider)
            }
        }
    }

    @ViewBuilder private func content(_ provider: ProviderInfo) -> some View {
        switch item.vault {
        case .none:
            Text(T("Seal this key first, so the new one has a safe place to land."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            Button(T("Seal")) { model.seal([item]) }
                .buttonStyle(KRButtonStyle())
                .disabled(model.busy)
        case .otherFolder:
            EmptyView()
        case .outdated:
            Text(T("Seal the changed file again before rotating."))
                .font(Theme.caption).foregroundStyle(Theme.warn)
                .fixedSize(horizontal: false, vertical: true)
        case .sealed:
            if isOpen {
                Text(T("A rotation of this key is open. Finish it in Vault."))
                    .font(Theme.caption).foregroundStyle(Theme.warn)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                setup(provider)
            }
        }
    }

    @ViewBuilder private func setup(_ provider: ProviderInfo) -> some View {
        if provider.can_rotate && provider.tested.rotate == nil {
            Text(T("This file has never rotated a real key. Try one you can afford to lose first."))
                .font(Theme.caption).foregroundStyle(Theme.warn)
                .fixedSize(horizontal: false, vertical: true)
        }
        if provider.single_rotation {
            Text(T("This provider ends the old key the moment the new one exists, so this cannot be undone. If the answer is lost, you make a new key at its page."))
                .font(Theme.caption).foregroundStyle(Theme.warn)
                .fixedSize(horizontal: false, vertical: true)
        }
        if !provider.can_rotate {
            Text(T("This provider has no way to make keys from here, so you make it at its page and paste it below. It is tested before anything changes."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            if let page = provider.dashboard.flatMap(URL.init(string:)) {
                Button(T("Open its page")) { NSWorkspace.shared.open(page) }.buttonStyle(KRButtonStyle())
            }
            SecureField(T("New key"), text: $newKey)
                .textFieldStyle(.roundedBorder)
                .font(Theme.caption)
        }
        Text(T("Where else is this key used? Each place gets the new key before the old one is revoked."))
            .font(Theme.caption).foregroundStyle(Theme.muted)
            .fixedSize(horizontal: false, vertical: true)
        ForEach(places.files, id: \.self) { file in
            placeRow(URL(fileURLWithPath: file).lastPathComponent, help: file) {
                change { $0.files.removeAll { $0 == file } }
            }
        }
        ForEach(places.actions, id: \.self) { action in
            placeRow(yourActions.first { $0.id == action }?.title ?? action, help: action) {
                change { $0.actions.removeAll { $0 == action } }
            }
        }
        HStack(spacing: 6) {
            Button(T("Add a file")) {
                model.chooseFile { path in
                    change {
                        if !$0.files.contains(path) { $0.files.append(path) }
                        $0.nothingElse = false
                    }
                }
            }
            .buttonStyle(KRButtonStyle())
            if !yourActions.isEmpty {
                Menu(T("Add an action")) {
                    ForEach(yourActions, id: \.id) { action in
                        Button(action.title) {
                            change {
                                if !$0.actions.contains(action.id) { $0.actions.append(action.id) }
                                $0.nothingElse = false
                            }
                        }
                    }
                }
                .fixedSize()
            }
        }
        if places.files.isEmpty && places.actions.isEmpty {
            Toggle(T("Nothing else uses this key"), isOn: Binding(get: { places.nothingElse }, set: { on in change { $0.nothingElse = on } }))
                .toggleStyle(.checkbox)
                .font(Theme.caption)
        }
        if provider.can_rotate && !provider.single_rotation {
        Picker(T("Old key lasts"), selection: Binding(get: { places.overlapMinutes }, set: { minutes in change { $0.overlapMinutes = minutes } })) {
            Text(T("Revoke right away")).tag(0)
            Text(T("1 hour")).tag(60)
            Text(T("1 day")).tag(1440)
            Text(T("7 days")).tag(10080)
        }
        .font(Theme.caption)
        }
        Button {
            confirming = true
        } label: {
            Label(T("Rotate this key"), systemImage: "arrow.triangle.2.circlepath")
        }
        .buttonStyle(KRButtonStyle(primary: true))
        .disabled(model.busy || !places.isDecided || (!provider.can_rotate && newKey.isEmpty))
        .confirmationDialog(T("Rotate this key with %@?", provider.name), isPresented: $confirming, titleVisibility: .visible) {
            Button(T("Rotate this key")) {
                model.rotate(item, handedOver: provider.can_rotate ? nil : newKey)
                newKey = ""
            }
            Button(T("Cancel"), role: .cancel) {}
        } message: {
            Text(T("This makes a real key at the provider. If anything fails before the old key is revoked, it undoes itself."))
        }
    }

    private func placeRow(_ title: String, help: String, remove: @escaping () -> Void) -> some View {
        HStack(spacing: 6) {
            Text(title).font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle).help(help)
            Spacer(minLength: 4)
            Button(action: remove) { Image(systemName: "xmark.circle") }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.muted)
                .accessibilityLabel(T("Remove"))
        }
    }
}
