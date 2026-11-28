import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// The first screen: what needs you, and the keys in use. Everything else is in My keys and Tools.
struct HomeView: View {
    let stats: CatalogStats
    let activity: [ActivityItem]
    @ObservedObject var model: AppModel
    /// Every key that can be checked, after the same question My keys asks.
    let checkAll: () -> Void
    let open: (Sidebar, String?) -> Void

    private let shownFirst = 5

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                if let progress = model.progress { progressCard(progress) }
                if let run = model.lastRun { summaryCard(run) }
                // What needs you, answered here: no trip to Agents.
                let news = ArrivalNews.make(items: model.items, index: model.keyIndex)
                if !news.isEmpty { Card { ArrivalNotice(news: news, review: model.showNewKeysNow).padding(14) } }
                if !model.pendingRequests.isEmpty { requestsCard }
                if !model.inUse.isEmpty { inUseCard }
                if !stats.needLook.isEmpty { toReview }
                if model.pendingRequests.isEmpty && model.inUse.isEmpty && stats.needLook.isEmpty && news.isEmpty {
                    Text(T("All in order: nothing waits on you and no key was used in the last 30 days."))
                        .font(Theme.body).foregroundStyle(Theme.muted)
                }
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 1040, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.background)
    }

    private var header: some View {
        HStack(alignment: .bottom) {
            VStack(alignment: .leading, spacing: 4) {
                Text(Date.now, format: .dateTime.weekday(.wide).day().month(.wide))
                    .font(Theme.caption).foregroundStyle(Theme.muted)
                Text(headline).font(Theme.title).foregroundStyle(Theme.text)
            }
            Spacer()
            if stats.canCheck > 0 {
                Button(action: checkAll) {
                    Label(T("Check all"), systemImage: "checkmark.shield")
                }
                .buttonStyle(KRButtonStyle())
                .disabled(model.busy)
                .help(T("Each key goes to its own provider, and only to read. Keys set to Only me stay out."))
            }
            Button {
                model.startAddingKey()
            } label: {
                Label(T("Add a key"), systemImage: "plus")
            }
            .buttonStyle(KRButtonStyle(primary: true))
        }
    }

    private var headline: String {
        switch stats.needLook.count {
        case 0: return T("No alerts found.")
        case 1: return T("1 thing to review")
        default: return T("%d things to review", stats.needLook.count)
        }
    }

    /// An agent waiting, said here without taking you anywhere until you choose.
    private var requestsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "hand.raised.fill").foregroundStyle(Theme.accent)
                    SectionTitle(T("Waiting on you"))
                }
                PendingRequestsList(model: model)
            }
            .padding(14)
        }
        .overlay(RoundedRectangle(cornerRadius: Theme.radius).strokeBorder(Theme.accent.opacity(0.6)))
    }

    /// The keys in use, by project, with who used them and where to. The rest stay in My keys.
    private var inUseCard: some View {
        let groups = Dictionary(grouping: model.inUse) { $0.project ?? T("No project") }
            .sorted { $0.key.localizedCaseInsensitiveCompare($1.key) == .orderedAscending }
        return Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    SectionTitle(T("In use"))
                    Text(T("%d keys used in the last %d days", model.inUse.count, KeyInUse.days))
                        .font(Theme.caption).foregroundStyle(Theme.muted)
                    Spacer()
                    Button(T("All my keys")) { open(.all, nil) }.buttonStyle(.link).font(Theme.caption)
                }
                ForEach(groups, id: \.key) { group in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(group.key).font(Theme.caption.weight(.semibold)).foregroundStyle(Theme.muted)
                        ForEach(group.value) { key in
                            Button { open(.all, key.source) } label: { InUseRow(key: key) }.buttonStyle(.plain)
                        }
                    }
                }
            }
            .padding(14)
        }
    }

    private func progressCard(_ progress: (done: Int, total: Int)) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(T("Checking…")).font(Theme.section).foregroundStyle(Theme.text)
                    Spacer()
                    Text(T("%d of %d keys", progress.done, progress.total))
                        .font(Theme.body).monospacedDigit().foregroundStyle(Theme.muted)
                }
                ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1)))
                    .tint(Theme.accent)
            }
            .padding(14)
        }
    }

    private func summaryCard(_ run: RunSummary) -> some View {
        Card {
            HStack(spacing: 8) {
                Text(T("Last run")).font(Theme.section).foregroundStyle(Theme.text)
                Text(T("%d checked", run.checked)).font(Theme.body).foregroundStyle(Theme.muted)
                Spacer()
                resultButton(T("Works"), run.works, "checkmark", .good, "works")
                resultButton(T("Rejected"), run.rejected, "xmark", .bad, "rejected")
                resultButton(T("No answer"), run.noAnswer, "questionmark", .neutral, "no_answer")
                if run.gone > 0 { resultButton(T("Not in the vault"), run.gone, "exclamationmark.triangle", .bad, "gone") }
            }
            .padding(12)
        }
    }

    private func resultButton(_ title: String, _ count: Int, _ icon: String, _ tone: Tone, _ result: String) -> some View {
        Button {
            open(.result(result), nil)
        } label: {
            Badge(text: "\(title): \(count)", icon: icon, tone: tone).contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    private var toReview: some View {
        VStack(alignment: .leading, spacing: 10) {
            Card {
                VStack(spacing: 0) {
                    ForEach(Array(stats.needLook.prefix(shownFirst).enumerated()), id: \.element.id) { index, item in
                        if index > 0 { Rectangle().fill(Theme.border).frame(height: 1) }
                        row(item)
                    }
                }
            }
            if stats.needLook.count > shownFirst {
                Button(T("All %d", stats.needLook.count)) { open(.attention, nil) }
                    .buttonStyle(KRButtonStyle())
            }
        }
    }

    private func row(_ item: CatalogItem) -> some View {
        HStack(alignment: .center, spacing: 12) {
            Circle().fill(urgent(item) ? Theme.bad : Theme.warn).frame(width: 8, height: 8)
            Button {
                open(.attention, item.path)
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title).font(Theme.rowTitle).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Text(item.attention ?? "").font(Theme.caption).foregroundStyle(Theme.muted)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            ActionButtons(item: item, model: model).fixedSize()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    private func urgent(_ item: CatalogItem) -> Bool { (item.attentionRanked?.rank ?? 9) <= 2 }
}

/// One key in use: its name, what it is, and who used it, from where, to where.
struct InUseRow: View {
    let key: KeyInUse

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(key.id).font(Theme.body).foregroundStyle(Theme.text).lineLimit(1)
            if let description = key.description, !description.isEmpty {
                Text(description).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
            }
            Spacer(minLength: 8)
            Text(usedBy).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1).truncationMode(.middle)
            if let last = key.use.last {
                Text(last, style: .relative).font(Theme.caption).foregroundStyle(Theme.faint).monospacedDigit()
            }
        }
        .contentShape(Rectangle())
    }

    private var usedBy: String {
        let who = key.use.agents.sorted().prefix(3).joined(separator: ", ")
        let hosts = key.use.hosts.sorted().prefix(2).joined(separator: ", ")
        return [who.isEmpty ? nil : who, hosts.isEmpty ? nil : "→ " + hosts].compactMap { $0 }.joined(separator: " ")
    }
}
