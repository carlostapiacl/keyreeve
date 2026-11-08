import KeyreeveCatalog
import SwiftUI

/// Sort many keys at once: what keyreeve proposes from tags and field names, and, for the rest, what the
/// person's own assistant proposes. Nothing changes until the person applies it.
struct SortSheet: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var suggestions: [Suggestion] = []
    @State private var chosen: Set<String> = []
    @State private var asking = false
    @State private var problem: String?
    @State private var task: Task<Void, Never>?

    private var groups: [(title: String, rows: [Suggestion])] {
        [
            (T("A provider keyreeve knows"), suggestions.filter { if case .provider = $0.kind { true } else { false } }),
            (T("Nothing to check"), suggestions.filter { $0.kind == .untestable }),
            (T("Internal secret, no provider"), suggestions.filter { $0.kind == .internalSecret }),
        ].filter { !$0.rows.isEmpty }
    }

    var body: some View {
        let assistant = Assistants.chosen()
        let rest = model.unsortedKeys.filter { key in !suggestions.contains { $0.path == key.path } }
        VStack(alignment: .leading, spacing: 14) {
            Text(T("Sort your keys")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("From each file's tags and the names of its fields, never a value. Nothing changes until you apply it."))
                .font(Theme.body).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            if suggestions.isEmpty {
                EmptyStateText(text: T("Nothing to propose from tags. Your assistant may know more."))
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(groups, id: \.title) { group in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(group.title) · \(group.rows.count)").font(Theme.section).foregroundStyle(Theme.text)
                            ForEach(group.rows) { row in
                                Toggle(isOn: Binding(
                                    get: { chosen.contains(row.path) },
                                    set: { on in if on { chosen.insert(row.path) } else { chosen.remove(row.path) } })
                                ) {
                                    HStack(spacing: 8) {
                                        Text(row.path).font(Theme.body).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                                        Spacer(minLength: 6)
                                        Text(label(row)).font(Theme.caption).foregroundStyle(Theme.text)
                                        Text(row.why == "assistant" ? T("assistant") : row.why).font(Theme.code).foregroundStyle(Theme.muted)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .frame(minHeight: 200, maxHeight: 420)
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill").font(Theme.body).foregroundStyle(Theme.bad)
            }
            // Said each time, next to the button: file names can say a lot.
            if let assistant, !rest.isEmpty {
                Text(T("Asking sends %@ the names of %d files, their tags and the names of their fields, with your account. Never a value.", assistant.name, rest.count))
                    .font(Theme.caption).foregroundStyle(Theme.warn).fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 8) {
                if !rest.isEmpty {
                    if let assistant {
                        Button(asking ? T("Asking %@…", assistant.name) : T("Ask %@ about the other %d", assistant.name, rest.count)) {
                            ask(assistant, about: rest)
                        }
                        .buttonStyle(KRButtonStyle())
                        .disabled(asking)
                        if asking {
                            Button(T("Cancel")) {
                                task?.cancel()
                                Assistants.stopAll()
                                asking = false
                            }
                            .buttonStyle(KRButtonStyle())
                        }
                    } else {
                        Text(T("%d more need a provider of their own, or an assistant in Settings.", rest.count))
                            .font(Theme.caption).foregroundStyle(Theme.muted)
                    }
                }
                Spacer()
                Button(T("Cancel")) {
                    if asking { Assistants.stopAll() }
                    dismiss()
                }
                .buttonStyle(KRButtonStyle()).keyboardShortcut(.cancelAction)
                Button(T("Apply %d", chosen.count)) {
                    model.apply(suggestions.filter { chosen.contains($0.path) })
                    dismiss()
                }
                .buttonStyle(KRButtonStyle(primary: true))
                .keyboardShortcut(.defaultAction)
                .disabled(chosen.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 720)
        .background(Theme.background)
        .onAppear {
            suggestions = model.sortSuggestions
            chosen = Set(suggestions.map(\.path))
        }
    }

    private func label(_ suggestion: Suggestion) -> String {
        switch suggestion.kind {
        case .provider(let id, let field):
            let name = model.providers.all.first { $0.id == id }?.name ?? id
            return field.map { "\(name) · \($0)" } ?? name
        case .untestable: return T("Nothing to check")
        case .internalSecret: return T("Internal secret")
        }
    }

    private func ask(_ assistant: Assistant, about keys: [CatalogItem]) {
        asking = true
        problem = nil
        let prompt = Suggester.prompt(for: keys, providers: model.providers)
        let providers = model.providers
        task = Task.detached {
            do {
                let answer = try Assistants.ask(assistant, prompt)
                let found = Suggester.read(answer, items: keys, providers: providers)
                await MainActor.run {
                    guard asking else { return }
                    suggestions += found
                    chosen.formUnion(found.map(\.path))
                    asking = false
                    if found.isEmpty { problem = T("%@ had nothing sure to propose.", assistant.name) }
                }
            } catch {
                await MainActor.run {
                    asking = false
                    problem = (error as? CheckError)?.description ?? T("%@ did not answer", assistant.name)
                }
            }
        }
    }
}

/// A short line in the place of a list with nothing in it.
private struct EmptyStateText: View {
    let text: String
    var body: some View { Text(text).font(Theme.body).foregroundStyle(Theme.muted) }
}
