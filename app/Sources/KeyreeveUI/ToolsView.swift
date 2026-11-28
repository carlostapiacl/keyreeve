import KeyreeveCatalog
import SwiftUI

/// What stands behind the keys, one part at a time: agents, the vault and its backup, rotation, the log and
/// providers. Each was a row of the sidebar; together they are one place, so the sidebar keeps three.
struct ToolsView: View {
    @ObservedObject var model: AppModel
    @Binding var part: Sidebar
    let go: (Sidebar) -> Void

    static let parts: [(Sidebar, String)] = [
        (.agents, "Agents"), (.vault, "Security and backup"), (.rotation, "Rotation"), (.log, "Log"),
        (.providers, "Providers"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            Picker(T("Tools"), selection: $part) {
                ForEach(Self.parts, id: \.0) { part, title in Text(T(title)).tag(part) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, Theme.pagePadding)
            .padding(.vertical, 10)
            Rectangle().fill(Theme.border).frame(height: 1)
            switch part {
            case .vault: VaultView(model: model, part: .security, go: go)
            case .rotation: VaultView(model: model, part: .rotation, go: go)
            case .log: UsageLogSheet(model: model, inline: true)
            case .providers: ProvidersView(model: model)
            default: AgentsView(model: model)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}
