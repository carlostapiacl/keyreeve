import KeyreeveCatalog
import KeyreeveVault
import SwiftUI

/// The first screen: what needs you and the one step for each, then how things stand. Batch checks and the
/// charts live in My keys and under Analysis, not up front.
struct HomeView: View {
    let stats: CatalogStats
    let activity: [ActivityItem]
    @ObservedObject var model: AppModel
    let open: (Sidebar, String?) -> Void

    private let shownFirst = 5
    @State private var showsAnalysis = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                if let progress = model.progress { progressCard(progress) }
                if let run = model.lastRun { summaryCard(run) }
                if let request = model.pendingRequests.first { requestBanner(request) }
                if !stats.needLook.isEmpty { toReview }
                cards
                recent
                analysis
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
    private func requestBanner(_ request: AccessRequests.Entry) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "hand.raised.fill").foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(T("%@ asks for a %@ key", request.agent, request.provider)).font(Theme.rowTitle).foregroundStyle(Theme.text)
                if let reason = request.reason {
                    Text("\u{201C}\(reason)\u{201D}").font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(2)
                }
            }
            Spacer()
            if model.pendingRequests.count > 1 {
                Text(T("%d waiting", model.pendingRequests.count)).font(Theme.caption).foregroundStyle(Theme.muted)
            }
            Button(T("Review")) { open(.agents, nil) }.buttonStyle(KRButtonStyle(primary: true))
        }
        .padding(14)
        .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: Theme.radius))
        .overlay(RoundedRectangle(cornerRadius: Theme.radius).strokeBorder(Theme.accent.opacity(0.45)))
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

    /// The last date a check passed, as the catalog writes it.
    private var lastPassed: String? {
        model.items.filter { $0.lastResult == "works" }.map(\.lastChecked).filter { !$0.isEmpty }.max()
    }

    private var cards: some View {
        let grants = model.usage.grants
        let keys = Array(Set(grants.map(\.key))).sorted()
        return HStack(alignment: .top, spacing: 14) {
            figure(
                T("Checked successfully"), stats.works,
                lastPassed.map { T("Last check: %@", $0) } ?? T("None checked yet"),
                T("See them")) { open(.result("works"), nil) }
            figure(
                T("Open to agents now"), keys.count,
                keys.isEmpty ? T("No agent holds a key now.") : keys.prefix(3).joined(separator: ", "),
                T("See them")) { open(.agents, nil) }
            figure(
                T("Never checked"), stats.neverChecked, T("A check sends one read-only request to the provider."),
                T("Check the ones I can")) { open(.checkable, nil) }
        }
    }

    private func figure(_ title: String, _ value: Int, _ detail: String, _ action: String, run: @escaping () -> Void) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(Theme.caption).foregroundStyle(Theme.muted)
                Text("\(value)").font(Theme.figure).monospacedDigit().foregroundStyle(Theme.text)
                Text(detail).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(2)
                Button(action, action: run).buttonStyle(.link).font(Theme.caption).padding(.top, 2)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }

    private var recent: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(T("Lately"))
            Card {
                VStack(alignment: .leading, spacing: 8) {
                    if activity.isEmpty {
                        Text(T("No checks yet, and no key used through the vault.")).font(Theme.body).foregroundStyle(Theme.muted)
                    }
                    ForEach(activity) { entry in
                        HStack(spacing: 10) {
                            Text(entry.at, format: .dateTime.day().month(.abbreviated).hour().minute())
                                .font(Theme.caption)
                                .monospacedDigit()
                                .foregroundStyle(Theme.muted)
                                .frame(width: 120, alignment: .leading)
                            Text(entry.key).font(Theme.code).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(describe(entry.kind)).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                        }
                    }
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// The charts and the results by kind, folded away until wanted.
    private var analysis: some View {
        DisclosureGroup(isExpanded: $showsAnalysis) {
            HStack(alignment: .top, spacing: 16) {
                Card { bars(T("Secrets by project"), stats.projects).padding(16) }
                    .frame(maxWidth: .infinity)
                VStack(spacing: 16) {
                    Card { checks.padding(16) }
                    Card { bars(T("Age of the files"), stats.ages).padding(16) }
                }
                .frame(width: 290)
            }
            .padding(.top, 10)
        } label: {
            Text(T("Analysis")).font(Theme.section).foregroundStyle(Theme.text)
        }
    }

    private var checks: some View {
        VStack(alignment: .leading, spacing: 9) {
            SectionTitle(T("Last checks"))
            status(T("Works"), stats.works, "checkmark.circle.fill", Theme.good)
            status(T("Rejected"), stats.rejected, "xmark.circle.fill", Theme.bad)
            status(T("No answer"), stats.noAnswer, "questionmark.circle", Theme.muted)
            status(T("Never checked"), stats.neverChecked, "circle.dashed", Theme.muted)
            FlowRow(spacing: 6) {
                Button(T("Can be checked") + ": \(stats.canCheck)") { open(.checkable, nil) }
                    .buttonStyle(KRButtonStyle())
                if stats.stale > 0 {
                    Button(T("Older than suggested") + ": \(stats.stale)") { open(.stale, nil) }
                        .buttonStyle(KRButtonStyle())
                }
            }
            .padding(.top, 2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func status(_ title: String, _ count: Int, _ icon: String, _ color: Color) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).imageScale(.small).frame(width: 16)
            Text(title).font(Theme.body).foregroundStyle(Theme.text)
            Spacer()
            Text("\(count)").font(Theme.body).monospacedDigit().foregroundStyle(Theme.muted)
        }
    }

    /// One series in one hue, with each value written beside its bar.
    private func bars(_ title: String, _ buckets: [CatalogStats.Bucket]) -> some View {
        let largest = max(buckets.map(\.count).max() ?? 1, 1)
        return VStack(alignment: .leading, spacing: 9) {
            SectionTitle(title)
            ForEach(buckets) { bucket in
                if let target = bucket.target {
                    Button {
                        open(target, nil)
                    } label: {
                        barRow(bucket, largest: largest).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                } else {
                    barRow(bucket, largest: largest)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func barRow(_ bucket: CatalogStats.Bucket, largest: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(bucket.label).font(Theme.body).foregroundStyle(Theme.text).lineLimit(1)
                Spacer()
                Text("\(bucket.count)").font(Theme.body).monospacedDigit().foregroundStyle(Theme.muted)
            }
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2).fill(Theme.raised)
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Theme.bar)
                        .frame(
                            width: bucket.count == 0
                                ? 0
                                : max(4, geometry.size.width * CGFloat(bucket.count) / CGFloat(largest)))
                }
            }
            .frame(height: 4)
        }
        .help("\(bucket.label): \(bucket.count)")
    }

    private func describe(_ kind: ActivityItem.Kind) -> String {
        switch kind {
        case .checked(let result):
            switch result {
            case "works": return T("Checked: works")
            case "rejected": return T("Checked: rejected")
            default: return T("Checked: no answer")
            }
        case .used(let program): return T("Used by %@", program)
        }
    }
}
