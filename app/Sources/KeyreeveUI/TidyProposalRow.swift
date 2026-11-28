import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// An agent's proposal to tidy keys: each key, what changes and why, chosen all or some, applied with one click.
struct TidyProposalRow: View {
    let request: AccessRequests.Entry
    @ObservedObject var model: AppModel
    @State private var changes: [KeyTidy.Change] = []
    @State private var chosen: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(T("%@ proposes tidying %d keys", request.agent, changes.count))
                    .font(Theme.rowTitle).foregroundStyle(Theme.text)
                Spacer(minLength: 8)
                Text(request.at, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint)
            }
            if let reason = request.reason {
                Text("\u{201C}\(reason)\u{201D}").font(Theme.body).foregroundStyle(Theme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(T("Only names and notes change, never a value. A renamed key keeps working by its old name."))
                .font(Theme.caption).foregroundStyle(Theme.muted)
            HStack(spacing: 8) {
                Button(T("Choose all")) { chosen = Set(changes.map(\.key)) }.buttonStyle(.link).font(Theme.caption)
                Button(T("Choose none")) { chosen = [] }.buttonStyle(.link).font(Theme.caption)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(changes, id: \.key) { change in
                        Toggle(isOn: Binding(
                            get: { chosen.contains(change.key) },
                            set: { on in if on { chosen.insert(change.key) } else { chosen.remove(change.key) } })
                        ) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(change.key).font(Theme.body).foregroundStyle(Theme.text)
                                    if change.archive == true {
                                        Text(T("archive")).font(Theme.caption).foregroundStyle(Theme.warn)
                                    }
                                    if let project = change.project, !model.knownProjects.contains(project) {
                                        Text(T("new project")).font(Theme.caption).foregroundStyle(Theme.warn)
                                    }
                                }
                                Text(change.summary(from: model.tidyKey(change.key)))
                                    .font(Theme.caption).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
                                Text(change.why).font(Theme.caption).foregroundStyle(Theme.faint).lineLimit(2)
                            }
                        }
                        .toggleStyle(.checkbox)
                    }
                }
            }
            .frame(maxHeight: 360)
            HStack(spacing: 8) {
                Spacer()
                Button(T("Decline")) { model.decline(request) }.buttonStyle(KRButtonStyle())
                Button(T("Apply %d", chosen.count)) {
                    model.applyTidy(changes.filter { chosen.contains($0.key) }, for: request)
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .disabled(model.busy || chosen.isEmpty)
            }
        }
        .onAppear {
            guard changes.isEmpty else { return }
            changes = model.tidyChanges(for: request)
            chosen = Set(changes.map(\.key))
        }
    }
}
