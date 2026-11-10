import AppKit
import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Where a key lives: the places a procedure updates, with their last check, what used the key lately and where
/// it was found. No value and no hash is ever shown.
struct WhereItLivesPanel: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @State private var adding = false

    private var known: [PlaceBook.Place] { model.knownPlaces(for: item).sorted { $0.label < $1.label } }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(T("Where it lives"))
            if known.isEmpty {
                Text(T("No place known yet. Add one, or let an agent propose where this key is used."))
                    .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(known) { place in
                        PlaceRow(place: place, model: model)
                        if place.id != known.last?.id { Divider() }
                    }
                }
            }
            HStack(spacing: 6) {
                let approved = known.filter { model.status(of: $0) == .approved }
                Button(T("Check places")) { model.checkPlaces(approved) }
                    .buttonStyle(KRButtonStyle())
                    .disabled(approved.isEmpty || !model.placesState.running.isDisjoint(with: approved.map(\.id)))
                    .help(T("Asks each place for a hash of what it holds and compares it here. It needs no fingerprint and shows no value."))
                if known.contains(where: { $0.lastCheck?.result == .notCompared }) {
                    Button(T("Compare with the vault")) { model.compareWithVault(known.filter { $0.lastCheck?.result == .notCompared }) }
                        .buttonStyle(KRButtonStyle())
                        .help(T("Opens the key once with your fingerprint to learn its hash, so later checks compare on their own."))
                }
                Button(T("Add a place…")) { adding = true }
                    .buttonStyle(KRButtonStyle())
                    .disabled(model.keyIDs(of: item).isEmpty)
                    .help(model.keyIDs(of: item).isEmpty ? T("Give this key an identifier first.") : "")
            }
            legacy
            usedBy
            foundAt
        }
        .onAppear { model.reloadPlaces() }
        .sheet(isPresented: $adding) { AddPlaceSheet(item: item, model: model, shown: $adding) }
    }

    /// Files and buttons set for the rotation before procedures, which still work.
    @ViewBuilder private var legacy: some View {
        let set = model.places[item.path] ?? KeyPlaces()
        if !set.files.isEmpty || !set.actions.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text(T("Also updated by a rotation")).font(Theme.caption).foregroundStyle(Theme.muted)
                ForEach(set.files + set.actions, id: \.self) { place in
                    Text(place).font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                }
            }
        }
    }

    @ViewBuilder private var usedBy: some View {
        let uses = model.usedBy(item)
        if !uses.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text(T("Used by, in the last 30 days")).font(Theme.caption).foregroundStyle(Theme.muted)
                ForEach(Array(uses.prefix(8).enumerated()), id: \.offset) { _, use in
                    Text([use.program, use.folder, use.agent.map { T("agent %@", $0) }].compactMap { $0 }.joined(separator: " · "))
                        .font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                }
            }
        }
    }

    @ViewBuilder private var foundAt: some View {
        let origins = model.foundAt(item)
        if !origins.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text(T("Found at")).font(Theme.caption).foregroundStyle(Theme.muted)
                ForEach(origins, id: \.self) { origin in
                    Text(origin).font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                }
            }
        }
    }
}

/// One place: its label, whether it may run, the last check, and what can be done with it.
struct PlaceRow: View {
    let place: PlaceBook.Place
    @ObservedObject var model: AppModel
    @State private var confirmingUpdate = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(place.label).font(Theme.rowTitle).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 6)
                PlaceCheckBadge(check: place.lastCheck, running: model.placesState.running.contains(place.id))
            }
            HStack(spacing: 6) {
                Text(place.procedure).font(Theme.code).foregroundStyle(Theme.muted)
                statusBadge
                if let at = place.lastCheck?.at {
                    Text(at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
                }
                Spacer(minLength: 6)
                switch model.status(of: place) {
                case .approved:
                    Button(T("Update")) { confirmingUpdate = true }
                        .buttonStyle(KRButtonStyle())
                        .help(T("Puts the key's value now in this place, with your fingerprint."))
                case .waiting, .changed:
                    Button(T("Approve…")) { model.approvePlaces([place]) }
                        .buttonStyle(KRButtonStyle())
                        .help(T("Pins this place to its procedure as it is now, with your fingerprint. Read the procedure first."))
                case .missing:
                    EmptyView()
                }
                Menu {
                    if let procedure = model.procedure(named: place.procedure) {
                        Button(T("Show the procedure")) { ProcedureText.show(procedure) }
                    }
                    Button(T("Forget this place"), role: .destructive) { model.removePlace(place) }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton).fixedSize()
                .accessibilityLabel(T("More"))
            }
            if let why = place.why, place.by != nil, place.by != "you" {
                Text(T("%@ said: “%@”", place.by ?? "", why)).font(Theme.caption).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .confirmationDialog(T("Put this key in %@?", place.label), isPresented: $confirmingUpdate, titleVisibility: .visible) {
            Button(T("Update")) { model.updatePlace(place) }
            Button(T("Cancel"), role: .cancel) {}
        } message: {
            Text(T("The procedure %@ receives the key's value and puts it there. Your fingerprint confirms it.", place.procedure))
        }
    }

    @ViewBuilder private var statusBadge: some View {
        switch model.status(of: place) {
        case .approved: EmptyView()
        case .waiting: Badge(text: T("Not approved"), icon: "hand.raised", tone: .warn)
        case .changed: Badge(text: T("Changed, needs approval"), icon: "exclamationmark.triangle", tone: .bad)
        case .missing: Badge(text: T("Procedure missing"), icon: "questionmark.circle", tone: .bad)
        }
    }
}

/// How a place's last check compares with the vault, in a word and an icon.
struct PlaceCheckBadge: View {
    let check: PlaceBook.Check?
    let running: Bool

    var body: some View {
        if running {
            ProgressView().controlSize(.small)
        } else if let check {
            switch check.result {
            case .same: Badge(text: T("Same"), icon: "checkmark.circle.fill", tone: .good)
            case .old: Badge(text: T("Old value"), icon: "clock.arrow.circlepath", tone: .bad)
            case .different: Badge(text: T("Different"), icon: "xmark.circle.fill", tone: .bad)
            case .absent: Badge(text: T("Absent"), icon: "circle.dashed", tone: .warn)
            case .present: Badge(text: T("There, cannot compare"), icon: "eye.slash", tone: .neutral)
            case .notCompared: Badge(text: T("Not compared yet"), icon: "questionmark.circle", tone: .neutral)
            case .changed: Badge(text: T("Not run: changed"), icon: "exclamationmark.triangle", tone: .bad)
            case .error: Badge(text: T("Error"), icon: "exclamationmark.circle", tone: .warn).help(check.detail ?? "")
            }
        } else {
            Badge(text: T("Never checked"), icon: "circle.dashed", tone: .neutral)
        }
    }
}

/// Shows a procedure's whole text in a window, since that is what a person approves.
enum ProcedureText {
    @MainActor static func show(_ procedure: ProcedureInfo) {
        let alert = NSAlert()
        alert.messageText = procedure.name
        alert.informativeText = procedure.description + "\nSHA-256 " + procedure.sha256
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 560, height: 320))
        scroll.hasVerticalScroller = true
        let text = NSTextView(frame: scroll.bounds)
        text.isEditable = false
        text.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        text.string = procedure.text
        scroll.documentView = text
        alert.accessoryView = scroll
        alert.runModal()
    }
}

/// Adds a place by hand: an identifier of this key, a procedure, its parameters and a label. Approving pins it
/// to the procedure as shown, with the fingerprint.
struct AddPlaceSheet: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel
    @Binding var shown: Bool
    @State private var key = ""
    @State private var procedureName = "ssh-env"
    @State private var params: [String: String] = [:]
    @State private var label = ""

    private var procedure: ProcedureInfo? { model.procedure(named: procedureName) }
    private var problem: String? {
        guard let procedure else { return T("Choose a procedure") }
        let missing = procedure.params.filter { !$0.optional && (params[$0.name] ?? "").trimmingCharacters(in: .whitespaces).isEmpty }
        if let first = missing.first { return T("%@ is needed", first.name) }
        do { try PlaceBook.checkParams(cleanParams) } catch { return (error as? VaultError)?.description }
        return nil
    }
    private var cleanParams: [String: String] {
        params.mapValues { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.value.isEmpty }
    }
    private var suggestedLabel: String {
        guard let procedure else { return "" }
        return procedure.params.compactMap { cleanParams[$0.name] }.prefix(3).joined(separator: " · ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(T("Add a place")).font(Theme.title)
            let ids = model.keyIDs(of: item)
            if ids.count > 1 {
                Picker(T("Key"), selection: $key) { ForEach(ids, id: \.self) { Text($0).tag($0) } }
            }
            Picker(T("Procedure"), selection: $procedureName) {
                ForEach(model.placesState.procedures.filter { $0.problem == nil }, id: \.name) { procedure in
                    Text(procedure.isBuiltin ? procedure.name : T("%@ (yours)", procedure.name)).tag(procedure.name)
                }
            }
            if let procedure {
                Text(procedure.description).font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                ForEach(procedure.params, id: \.name) { param in
                    VStack(alignment: .leading, spacing: 2) {
                        TextField(param.optional ? T("%@ (optional)", param.name) : param.name, text: Binding(
                            get: { params[param.name] ?? "" }, set: { params[param.name] = $0 }))
                            .textFieldStyle(.roundedBorder)
                        Text(param.about).font(Theme.caption).foregroundStyle(Theme.faint)
                    }
                }
                TextField(T("Label, such as %@", suggestedLabel.isEmpty ? "VPS2 · /opt/app/.env · API_KEY" : suggestedLabel), text: $label)
                    .textFieldStyle(.roundedBorder)
                DisclosureGroup(T("The procedure you approve")) {
                    ScrollView {
                        Text(procedure.text).font(Theme.code).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 180)
                    Text("SHA-256 \(procedure.sha256)").font(Theme.code).foregroundStyle(Theme.faint).textSelection(.enabled)
                }
                .font(Theme.caption)
            }
            Text(T("A place receives the real key when you update it or rotate the key. Approving pins it to this procedure: if the procedure changes, it does not run until you approve it again."))
                .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            HStack {
                if let problem { Text(problem).font(Theme.caption).foregroundStyle(Theme.warn) }
                Spacer()
                Button(T("Cancel")) { shown = false }.buttonStyle(KRButtonStyle())
                Button(T("Approve with your fingerprint")) {
                    let chosenKey = key.isEmpty ? (ids.first ?? "") : key
                    let place = PlaceBook.Place(
                        key: chosenKey, procedure: procedureName, params: cleanParams,
                        label: label.trimmingCharacters(in: .whitespaces).isEmpty ? suggestedLabel : label, by: "you")
                    model.approvePlaces([place]) { count in if count > 0 { shown = false } }
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .disabled(problem != nil || (label.isEmpty && suggestedLabel.isEmpty))
            }
        }
        .padding(20)
        .frame(width: 520)
        .onAppear {
            key = model.keyIDs(of: item).first ?? ""
            model.reloadPlaces()
        }
    }
}

/// An agent's proposal of places, in one list: each place with its procedure, every one chosen to start, the
/// text of any procedure of the person's folder shown, and one fingerprint to approve the chosen ones.
struct PlacesProposalRow: View {
    let request: AccessRequests.Entry
    @ObservedObject var model: AppModel
    @State private var proposed: [PlaceBook.Place] = []
    @State private var chosen: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(T("%@ proposes %d places where keys live", request.agent, proposed.count))
                    .font(Theme.rowTitle).foregroundStyle(Theme.text)
                Spacer(minLength: 8)
                Text(request.at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
            }
            if let reason = request.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(proposed) { place in
                        Toggle(isOn: Binding(
                            get: { chosen.contains(place.id) },
                            set: { on in if on { chosen.insert(place.id) } else { chosen.remove(place.id) } })
                        ) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(place.key).font(Theme.rowTitle).foregroundStyle(Theme.text)
                                    Text(place.label).font(Theme.body).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                                }
                                HStack(spacing: 6) {
                                    Text(place.procedure).font(Theme.code).foregroundStyle(Theme.muted)
                                    Text(place.params.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))
                                        .font(Theme.code).foregroundStyle(Theme.faint).lineLimit(1).truncationMode(.middle)
                                }
                                if let why = place.why {
                                    Text("\u{201C}\(why)\u{201D}").font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(2)
                                }
                                procedureNote(place)
                            }
                        }
                        .toggleStyle(.checkbox)
                        .disabled(model.procedure(named: place.procedure) == nil)
                    }
                }
            }
            .frame(maxHeight: 320)
            HStack(spacing: 8) {
                Text(T("Each place receives the real key when you update it or rotate. Read any procedure of yours before approving."))
                    .font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button(T("Decline")) { model.declinePlaces(request) }.buttonStyle(KRButtonStyle())
                Button(T("Approve %d", chosen.count)) {
                    model.approveProposal(request, chosen: proposed.filter { chosen.contains($0.id) })
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .disabled(model.busy || chosen.isEmpty)
            }
        }
        .onAppear {
            model.reloadPlaces()
            proposed = model.proposedPlaces(for: request)
            chosen = Set(proposed.map(\.id))
        }
        .onChange(of: model.placesState.procedures) { _, _ in
            chosen = chosen.filter { id in proposed.first { $0.id == id }.map { model.procedure(named: $0.procedure) != nil } ?? false }
        }
    }

    /// A procedure of the person's folder is shown in full, since an agent may have just written it. One that is
    /// not there cannot be approved.
    @ViewBuilder private func procedureNote(_ place: PlaceBook.Place) -> some View {
        if let procedure = model.procedure(named: place.procedure) {
            if !procedure.isBuiltin {
                VStack(alignment: .leading, spacing: 2) {
                    Text(T("%@ is a procedure of your folder. This is what you approve:", procedure.name))
                        .font(Theme.caption).foregroundStyle(Theme.warn)
                    ScrollView {
                        Text(procedure.text).font(Theme.code).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 120)
                    .background(Theme.raised, in: RoundedRectangle(cornerRadius: Theme.smallRadius))
                    Text("SHA-256 \(procedure.sha256)").font(Theme.code).foregroundStyle(Theme.faint)
                }
            }
        } else {
            Text(T("There is no procedure %@ yet, so this place cannot be approved", place.procedure))
                .font(Theme.caption).foregroundStyle(Theme.warn)
        }
    }
}

/// The places a rotation will update, shown before it starts: those approved go, the rest are named and left out.
struct RotationPlacesList: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    var body: some View {
        let known = model.knownPlaces(for: item).sorted { $0.label < $1.label }
        if !known.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(known) { place in
                    HStack(spacing: 6) {
                        Image(systemName: model.status(of: place) == .approved ? "arrow.right.circle" : "nosign")
                            .foregroundStyle(model.status(of: place) == .approved ? Theme.text : Theme.warn)
                        Text(place.label).font(Theme.caption).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 4)
                        PlaceCheckBadge(check: place.lastCheck, running: model.placesState.running.contains(place.id))
                    }
                }
                if !model.placesNeedingApproval(for: item).isEmpty {
                    Text(T("Places waiting for your approval are left out of the rotation. Approve them under Usage, Where it lives."))
                        .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
                }
            }
            .onAppear { model.reloadPlaces() }
        }
    }
}
