import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// Projects, under Tools: each folder with the keys it uses (in the vault, new, or missing from it), the files on this
/// Mac where they live, and its key set. Projects come from Bring in, kept by the person.
struct ProjectsView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(T("Projects")).font(Theme.title).foregroundStyle(Theme.text)
                Text(T("A project is a folder, the keys it uses and where they live. Bring in finds them; you keep the ones you want."))
                    .font(Theme.body).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button(T("Bring in your keys"), action: model.startBringIn).buttonStyle(KRButtonStyle())
                    if model.vaultCoverage().map({ !$0.complete }) ?? model.hasVault {
                        Button(T("Learn what the vault holds")) { model.learnWhatTheVaultHolds() }.buttonStyle(KRButtonStyle())
                    }
                }
                if model.projectBook.projects.isEmpty {
                    EmptyHint(title: T("No project yet"), text: T("Bring in your keys, then keep the projects it found."))
                }
                ForEach(model.projectBook.projects) { project in ProjectCard(model: model, project: project) }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { model.reloadProjects() }
    }
}

private struct ProjectCard: View {
    @ObservedObject var model: AppModel
    let project: Projects.Project

    var body: some View {
        let states = model.keyStates(of: project)
        let fresh = model.newKeys(in: project)
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(project.name).font(Theme.rowTitle).foregroundStyle(Theme.text)
                        Text(shortPath(project.folder)).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    Chip(text: T("%d in the vault", states.sealed.count))
                    if fresh > 0 { Chip(text: T("%d new", fresh)) }
                    if !states.missing.isEmpty { Chip(text: T("%d missing", states.missing.count)) }
                }
                if !project.keys.isEmpty {
                    FlowRow(spacing: 4) {
                        ForEach(states.sealed, id: \.self) { Text($0).font(Theme.code).foregroundStyle(Theme.text) }
                        ForEach(states.missing, id: \.self) { Text($0).font(Theme.code).foregroundStyle(Theme.bad).strikethrough() }
                    }
                }
                if !project.places.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(project.places, id: \.self) { place in
                            Label(shortPath(place), systemImage: FileManager.default.fileExists(atPath: place) ? "doc.text" : "questionmark.folder")
                                .font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1).truncationMode(.middle)
                        }
                    }
                }
                HStack {
                    if let set = project.set {
                        Text(T("Key set: %@", set)).font(Theme.caption).foregroundStyle(Theme.text)
                    }
                    Spacer()
                    Button(project.set == nil ? T("Make its key set") : T("Update its key set")) { model.makeKeySet(for: project) }
                        .buttonStyle(KRButtonStyle())
                    Button(T("Remove")) { model.removeProject(project) }.buttonStyle(KRButtonStyle())
                }
            }
            .padding(14)
        }
    }
}
