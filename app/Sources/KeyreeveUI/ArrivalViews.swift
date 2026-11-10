import KeyreeveCatalog
import SwiftUI

/// On a key's page: how it got in, when that still needs the person. A value that waits, a key sealed with no
/// record, or a key an agent or a program added. Nothing here offers a key to agents.
struct ArrivalBanner: View {
    let item: CatalogItem
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let from = item.waitingFrom {
                box(
                    T("A new value for %@ is waiting, from %@", item.title, from),
                    T("The current value stays in force until you accept this one. Accepting asks for your finger, and the old value stays sealed as history.")
                ) {
                    Button(T("Accept the new value")) { model.acceptWaiting(item) }.buttonStyle(KRButtonStyle(primary: true))
                    Button(T("Discard it")) { model.discardWaiting(item) }.buttonStyle(KRButtonStyle())
                }
            }
            if item.withoutRecord {
                box(
                    T("Sealed without a record"),
                    T("It is in the vault with no identifier in keys.toml. Give it one to name it and use it like any other key. It stays not offered to agents.")
                ) {
                    Button(T("Give it an identifier")) { model.giveRecord(to: item) }.buttonStyle(KRButtonStyle(primary: true))
                }
            } else if let from = item.newFrom {
                box(
                    T("New, not reviewed: added by %@", from),
                    T("No agent sees it until you offer it. Look at it, name it in your own words, then mark it reviewed.")
                ) {
                    Button(T("Mark reviewed")) { model.markReviewed([item]) }.buttonStyle(KRButtonStyle(primary: true))
                }
            }
        }
    }

    private func box<Buttons: View>(_ title: String, _ text: String, @ViewBuilder buttons: () -> Buttons) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: "sparkles").font(Theme.rowTitle).foregroundStyle(Theme.warn)
            Text(text).font(Theme.caption).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) { buttons() }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.warn.opacity(0.10), in: RoundedRectangle(cornerRadius: Theme.smallRadius))
    }
}

/// In the menu bar and under Agents: "claude added 21 keys", and values that wait.
struct ArrivalNotice: View {
    let news: ArrivalNews
    let review: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(T("New in the vault"), systemImage: "sparkles").font(Theme.section).foregroundStyle(Theme.accent)
            ForEach(news.lines, id: \.self) { line in
                Text(line).font(Theme.body).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
            }
            if !news.added.isEmpty || news.withoutRecord > 0 {
                Text(T("Agents do not see new keys until you offer them."))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
            }
            Button(T("Review them"), action: review).buttonStyle(KRButtonStyle(primary: true))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
