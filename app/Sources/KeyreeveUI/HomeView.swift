import KeyreeveCatalog
import SwiftUI

/// The first screen: what to do next, then how things stand. Every figure opens its keys.
struct HomeView: View {
    let stats: CatalogStats
    let activity: [ActivityItem]
    @ObservedObject var model: AppModel
    let open: (Sidebar, String?) -> Void

    private let shownFirst = 5
    @State private var confirmCheck = false
    @State private var confirmIdentify = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                if let progress = model.progress { progressCard(progress) }
                if let run = model.lastRun { summaryCard(run) }
                if !stats.needLook.isEmpty { doFirst }
                HStack(alignment: .top, spacing: 16) {
                    Card { bars(T("Secrets by project"), stats.projects).padding(16) }
                        .frame(maxWidth: .infinity)
                    VStack(spacing: 16) {
                        Card { checks.padding(16) }
                        Card { bars(T("Age of the files"), stats.ages).padding(16) }
                    }
                    .frame(width: 290)
                }
                recent
            }
            .padding(Theme.pagePadding)
            .frame(maxWidth: 1040, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.background)
    }

    private var checkable: [CatalogItem] { model.items.filter { model.providers.canCheck($0) && !$0.isArchived } }
    private var identifiable: [CatalogItem] { checkable.filter(model.providers.canIdentify) }

    private var header: some View {
        HStack(alignment: .top) {
            Button {
                open(stats.needLook.isEmpty ? .all : .attention, nil)
            } label: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(headline).font(Theme.title).foregroundStyle(Theme.text)
                    Text(T("Secrets: %d · Critical: %d · Checked: %d · Identified: %d", stats.secrets, stats.critical, stats.checked, stats.identified))
                        .font(Theme.body)
                        .foregroundStyle(Theme.muted)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Spacer()
            HStack(spacing: 6) {
                Button(T("Identify all")) { confirmIdentify = true }
                    .buttonStyle(KRButtonStyle())
                    .disabled(model.busy || identifiable.isEmpty)
                Button(T("Check all")) { confirmCheck = true }
                    .buttonStyle(KRButtonStyle(primary: true))
                    .disabled(model.busy || checkable.isEmpty)
            }
        }
        .confirmationDialog(
            T("Check all %d keys?", checkable.count), isPresented: $confirmCheck, titleVisibility: .visible
        ) {
            Button(T("Check all")) { model.check(checkable) }
            Button(T("Cancel"), role: .cancel) {}
        } message: {
            Text(T("Each key goes to its own provider, and only to read. Keys set to Only me stay out."))
        }
        .confirmationDialog(
            T("Identify all %d keys?", identifiable.count), isPresented: $confirmIdentify, titleVisibility: .visible
        ) {
            Button(T("Identify all")) { model.identify(identifiable) }
            Button(T("Cancel"), role: .cancel) {}
        } message: {
            Text(T("Each provider says whose key it is. Only the fields its file declares are kept."))
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

    private var headline: String {
        switch stats.needLook.count {
        case 0: return T("No alerts found.")
        case 1: return T("1 key needs you")
        default: return T("%d keys need you", stats.needLook.count)
        }
    }

    private var doFirst: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(T("Do first"))
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
            Image(systemName: urgent(item) ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(urgent(item) ? Theme.bad : Theme.warn)
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
            if item.criticality > 0 {
                CriticalityMeter(value: item.criticality, suggested: item.criticalitySuggested)
            }
            ActionButtons(item: item, model: model).fixedSize()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    private func urgent(_ item: CatalogItem) -> Bool { (item.attentionRanked?.rank ?? 9) <= 2 }

    private var checks: some View {
        VStack(alignment: .leading, spacing: 9) {
            SectionTitle(T("Last checks"))
            status(T("Works"), stats.works, "checkmark.circle.fill", Theme.good)
            status(T("Rejected"), stats.rejected, "xmark.circle.fill", Theme.bad)
            status(T("No answer"), stats.noAnswer, "questionmark.circle", Theme.muted)
            status(T("Never checked"), stats.neverChecked, "circle.dashed", Theme.faint)
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
                                .foregroundStyle(Theme.faint)
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
