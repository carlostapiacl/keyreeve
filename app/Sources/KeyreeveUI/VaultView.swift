import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Where keys move into the vault. Sealing needs no fingerprint, and opening always does. The same view
/// shows Security and backup, or the Rotation tool, so each task has one place.
struct VaultView: View {
    enum Part { case security, rotation }

    @ObservedObject var model: AppModel
    var part: Part = .security
    /// Opens another section: Rotation and Agents are linked from here, not repeated.
    var go: (Sidebar) -> Void = { _ in }
    @State private var chosen: Set<String> = []
    /// Lists worked out from the keys, kept until the keys change: each is read many times per draw.
    @State private var memo = ViewMemo()

    private var version: [AnyHashable] { [model.itemsVersion] }
    private var sealed: [CatalogItem] { memo.value("sealed", key: version) { filter(model.items, by: .vault, search: "") } }
    private var candidates: [CatalogItem] { memo.value("candidates", key: version) { vaultCandidates(model.items) } }
    private var outdated: Int { memo.value("outdated", key: version) { sealed.filter { $0.vault == .outdated }.count } }
    private var moved: [CatalogItem] { memo.value("moved", key: version) { model.items.filter(\.originalMoved) } }
    private var openRotations: [RotationStatus] {
        model.rotations.filter { $0.isOpen || (!$0.manual.isEmpty && !model.isDismissed($0)) }
    }

    var body: some View {
        Group {
            if let draft = model.vaultDraft {
                RecoveryKeyView(draft: draft, model: model)
            } else if model.hasVault {
                if part == .rotation { rotationTool } else { ready }
            } else {
                intro
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var intro: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
            Text(T("Keep keys out of plain files")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("The vault seals each key with a key inside this Mac's chip, and your finger opens it. Until you move the original files, any program running as you can still read those."))
                .font(Theme.body).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            Text(T("You get a recovery key once. If this Mac dies, it is the only way back in, so have paper at hand."))
                .font(Theme.body).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            Button(T("Create my vault")) { model.startVault() }
                .buttonStyle(KRButtonStyle(primary: true))
            }
            .frame(maxWidth: 460, alignment: .leading)
            .padding(Theme.pagePadding)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var ready: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                summary
                backupCard
                if let report = model.vaultComparison { comparison(report) }
                if !moved.isEmpty { movedCard }
                addKeys
                if !sealed.isEmpty { sealedCard }
                links
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var summary: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(sealed.count)").font(Theme.figure).monospacedDigit().foregroundStyle(Theme.text)
                    Text(sealed.count == 1 ? T("key sealed") : T("keys sealed")).font(Theme.body).foregroundStyle(Theme.muted)
                    Spacer()
                    Button(T("Compare with the files")) { model.compareVault() }
                        .buttonStyle(KRButtonStyle())
                        .disabled(model.busy || sealed.isEmpty)
                }
                Text(T("Your original files stay where they are. Checks use the sealed copy, and ask for your finger once per batch."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                if outdated > 0 {
                    Label(
                        outdated == 1
                            ? T("1 file changed after it was sealed. Checks use that file.")
                            : T("%d files changed after they were sealed. Checks use those files.", outdated),
                        systemImage: "exclamationmark.triangle.fill")
                        .font(Theme.caption).foregroundStyle(Theme.warn)
                    Button(T("Seal the changed files again")) {
                        model.sealAgain(sealed.filter { $0.vault == .outdated })
                    }
                    .buttonStyle(KRButtonStyle())
                    .disabled(model.busy)
                }
            }
            .padding(14)
        }
    }

    private func comparison(_ report: VaultKeeper.CompareReport) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 6) {
                Label(
                    report.same.count == 1 ? T("1 matches its file") : T("%d match their file", report.same.count),
                    systemImage: "checkmark.circle.fill")
                    .foregroundStyle(report.different.isEmpty && report.noFile.isEmpty ? Theme.good : Theme.text)
                ForEach(report.different, id: \.self) { name in
                    Label(T("Different from its file: %@", name), systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Theme.warn)
                }
                ForEach(report.noFile, id: \.self) { name in
                    Label(T("No file to compare: %@", name), systemImage: "questionmark.circle").foregroundStyle(Theme.muted)
                }
                if !report.same.isEmpty {
                    Button(T("Move these originals out of the folder")) { model.moveOriginals() }
                        .buttonStyle(KRButtonStyle(primary: true))
                        .disabled(model.busy)
                    Text(T("They go to a private folder, still readable, and you can put them back. Delete them yourself once you trust the vault."))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .font(Theme.body)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
        }
    }

    private var rotationsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(T("Rotations"))
                ForEach(openRotations) { status in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(status.key).font(Theme.rowTitle).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            if status.isOpen {
                                Button(status.phase == "waiting" ? T("Revoke the old key now") : T("Finish")) {
                                    model.finishRotation(of: status.key)
                                }
                                .buttonStyle(KRButtonStyle(primary: true))
                                .disabled(model.busy)
                            } else {
                                if status.waitsForManualRevoke {
                                    Button(T("Check that the old key is dead")) { model.confirmOldKeyDead(status) }
                                        .buttonStyle(KRButtonStyle(primary: true))
                                        .disabled(model.busy)
                                }
                                // Hides the reminder and checks nothing, and says so.
                                Button(T("Hide this reminder")) { model.dismiss(status) }
                                    .buttonStyle(KRButtonStyle())
                                    .help(T("Hides it from this list. It does not check that the old key stopped working."))
                            }
                        }
                        if status.phase == "waiting" {
                            Text(T("New key in place. Revoke the old one when your services use the new one."))
                                .font(Theme.caption).foregroundStyle(Theme.muted)
                        }
                        ForEach(status.manual, id: \.self) { line in
                            Label(T(line), systemImage: "hand.raised").font(Theme.caption).foregroundStyle(Theme.warn)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }
            .padding(14)
        }
    }

    /// The keys themselves, since using one is why they are here. Each opens on a fingerprint.
    private var sealedCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("Your sealed keys"))
                    Spacer()
                    if sealed.contains(where: { item in
                        let keys = model.keyIndex.keys(forSource: item.path)
                        return keys.isEmpty || (model.account(of: item) != nil && keys.contains { $0.account == nil })
                    }) {
                        Button(T("Give identifiers to the sealed keys")) { model.assignIdentifiers() }
                            .buttonStyle(KRButtonStyle())
                    }
                }
                ForEach(sealed) { item in
                    HStack(spacing: 10) {
                        KeyRow(item: item, compact: true)
                        if let key = model.keyIndex.keys(forSource: item.path).first {
                            VStack(alignment: .trailing, spacing: 1) {
                                Text(key.id).font(Theme.code).foregroundStyle(Theme.muted).lineLimit(1)
                                if let account = key.account {
                                    Text(account).font(Theme.caption).foregroundStyle(Theme.faint).lineLimit(1)
                                }
                            }
                        }
                        if item.vault == .sealed || item.vault == .outdated {
                            CopyKeyButton(item: item, model: model)
                        }
                    }
                }
            }
            .padding(14)
        }
    }

    /// Rotation and agents have their own sections; here they are a line each, so nothing is said twice.
    private var links: some View {
        let open = sealed.filter { item in
            model.keyIndex.keys(forSource: item.path).contains { model.agentPolicy.level(of: $0.id) != nil }
        }.count
        return HStack(spacing: 8) {
            Button(openRotations.isEmpty ? T("Rotation") : T("Rotation: %d waiting", openRotations.count)) { go(.rotation) }
                .buttonStyle(KRButtonStyle())
            Button(open == 0 ? T("Agents") : T("Agents: %d keys open", open)) { go(.agents) }
                .buttonStyle(KRButtonStyle())
        }
    }

    /// The Rotation tool: what is in progress, and what waits on you.
    private var rotationTool: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(T("Rotation")).font(Theme.title).foregroundStyle(Theme.text)
                if openRotations.isEmpty {
                    EmptyHint(
                        title: T("No rotation in progress"),
                        text: T("Rotate a key from its page, under More details and options."),
                        action: T("See my keys"), run: { go(.all) })
                } else {
                    rotationsCard
                }
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var backupCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("Backup"))
                    Spacer()
                    Button(T("Copy the vault…")) { model.backupVault() }.buttonStyle(KRButtonStyle())
                }
                Text(T("If this Mac is lost, the copy and your recovery key bring every key back on another Mac. The copy is sealed, so keep it anywhere."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Text(model.lastVaultBackup.map { T("Last copy: %@", $0.formatted(date: .abbreviated, time: .omitted)) } ?? T("No copy yet."))
                    .font(Theme.caption).foregroundStyle(Theme.text)
            }
            .padding(14)
        }
    }

    private var movedCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("Originals moved: %d", moved.count))
                    Spacer()
                    Button(T("Show in Finder")) { model.showOriginals() }.buttonStyle(KRButtonStyle())
                    Button(T("Put them back")) { model.putOriginalsBack(moved) }
                        .buttonStyle(KRButtonStyle())
                        .disabled(model.busy)
                }
                Text(T("Those files are still plain text in that folder until you delete them. After a rotation they hold an old key."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
        }
    }

    private var addKeys: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionTitle(T("Add keys"))
                    Spacer()
                    Button(T("Choose 5 to start")) {
                        chosen = Set(candidates.prefix(5).map(\.path))
                    }
                    .buttonStyle(KRButtonStyle())
                    .help(T("Live keys you would miss least"))
                    Button(T("Choose those that work")) {
                        chosen = Set(candidates.filter { $0.lastResult == "works" }.map(\.path))
                    }
                    .buttonStyle(KRButtonStyle())
                    Button(T("Choose all %d", candidates.count)) {
                        chosen = Set(candidates.map(\.path))
                    }
                    .buttonStyle(KRButtonStyle())
                    Button(chosen.isEmpty ? T("Seal") : T("Seal %d", chosen.count)) {
                        model.seal(candidates.filter { chosen.contains($0.path) })
                        chosen = []
                    }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(model.busy || chosen.isEmpty)
                }
                if candidates.isEmpty {
                    Text(T("Nothing left to add.")).font(Theme.body).foregroundStyle(Theme.muted)
                }
                ForEach(candidates) { item in
                    Toggle(isOn: binding(for: item.path)) {
                        KeyRow(item: item, compact: true)
                    }
                    .toggleStyle(.checkbox)
                }
            }
            .padding(14)
        }
    }

    private func binding(for path: String) -> Binding<Bool> {
        Binding(
            get: { chosen.contains(path) },
            set: { isOn in
                if isOn { chosen.insert(path) } else { chosen.remove(path) }
            })
    }
}

/// Shows the recovery key once. The vault is saved only after the person proves they wrote it down.
struct RecoveryKeyView: View {
    let draft: VaultDraft
    @ObservedObject var model: AppModel
    @State private var typed = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
            Text(T("Write down your recovery key")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("It opens every key in this vault, and it is shown only now. Keep it on paper or in a password manager, away from this Mac."))
                .font(Theme.body).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            Text(draft.recoveryKey)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.text)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.raised, in: RoundedRectangle(cornerRadius: Theme.smallRadius))
            VStack(alignment: .leading, spacing: 5) {
                Text(T("Type its last 6 characters to continue")).font(Theme.section).foregroundStyle(Theme.text)
                TextField(T("Last 6 characters"), text: $typed)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 140)
                    .autocorrectionDisabled()
            }
            HStack {
                Button(T("Cancel")) { model.cancelVault() }.buttonStyle(KRButtonStyle())
                Button(T("I wrote it down")) { model.finishVault() }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(!draft.accepts(typed))
            }
            }
            .frame(maxWidth: 520, alignment: .leading)
            .padding(Theme.pagePadding)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
