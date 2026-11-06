import KeyreeveCatalog
import SwiftUI

/// The first screen: what to do next, then how things stand. Every figure opens its keys.
struct HomeView: View {
    let stats: CatalogStats
    let activity: [ActivityItem]
    @ObservedObject var model: AppModel
    let open: (Sidebar, String?) -> Void

    private let shownFirst = 5

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                summary
                doFirst
                HStack(alignment: .top, spacing: 36) {
                    bars(T("Secrets by project"), stats.projects).frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 28) {
                        checks
                        bars(T("Age of the files"), stats.ages)
                    }
                    .frame(width: 260, alignment: .leading)
                }
                recent
            }
            .padding(24)
            .frame(maxWidth: 980, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var summary: some View {
        HStack(alignment: .firstTextBaseline, spacing: 36) {
            figure("\(stats.secrets)", T("secrets"), .all)
            figure("\(stats.needLook.count)", T("need a look"), .attention)
            figure(T("%d of %d", stats.checked, stats.secrets), T("checked"), .all)
            figure("\(stats.canCheck)", T("can be checked"), .checkable)
        }
    }

    private func figure(_ value: String, _ caption: String, _ target: Sidebar) -> some View {
        Button {
            open(target, nil)
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text(value).font(.system(size: 26, weight: .semibold)).monospacedDigit()
                Text(caption).font(.callout).foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
    }

    private var doFirst: some View {
        VStack(alignment: .leading, spacing: 10) {
            heading(T("Do first"))
            if stats.needLook.isEmpty {
                Label(T("Everything looks fine."), systemImage: "checkmark.seal.fill").foregroundStyle(.secondary)
            }
            VStack(spacing: 0) {
                ForEach(Array(stats.needLook.prefix(shownFirst).enumerated()), id: \.element.id) { index, item in
                    if index > 0 { Divider() }
                    row(item)
                }
            }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
            .opacity(stats.needLook.isEmpty ? 0 : 1)
            if stats.needLook.count > shownFirst {
                Button(T("All %d", stats.needLook.count)) { open(.attention, nil) }
                    .buttonStyle(.link)
                    .font(.callout)
            }
        }
    }

    private func row(_ item: CatalogItem) -> some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: urgent(item) ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(urgent(item) ? .red : .orange)
            Button {
                open(.attention, item.path)
            } label: {
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.path).lineLimit(1).truncationMode(.middle)
                    Text(item.attention ?? "").font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            ActionButtons(item: item, model: model).fixedSize()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
    }

    private func urgent(_ item: CatalogItem) -> Bool { (item.attentionRanked?.rank ?? 9) <= 2 }

    private var checks: some View {
        VStack(alignment: .leading, spacing: 8) {
            heading(T("Last checks"))
            status(T("Works"), stats.works, "checkmark.circle.fill", .green)
            status(T("Rejected"), stats.rejected, "xmark.circle.fill", .red)
            status(T("No answer"), stats.noAnswer, "questionmark.circle", .secondary)
            status(T("Never checked"), stats.neverChecked, "circle.dashed", .secondary)
        }
    }

    private func status(_ title: String, _ count: Int, _ icon: String, _ color: Color) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).imageScale(.small).frame(width: 16)
            Text(title)
            Spacer()
            Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
        }
    }

    /// One series in one hue, with each value written beside its bar.
    private func bars(_ title: String, _ buckets: [CatalogStats.Bucket]) -> some View {
        let largest = max(buckets.map(\.count).max() ?? 1, 1)
        return VStack(alignment: .leading, spacing: 8) {
            heading(title)
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
    }

    private func barRow(_ bucket: CatalogStats.Bucket, largest: Int) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(bucket.label).lineLimit(1)
                Spacer()
                Text("\(bucket.count)").monospacedDigit().foregroundStyle(.secondary)
            }
            GeometryReader { geometry in
                RoundedRectangle(cornerRadius: 2)
                    .fill(Color.accentColor)
                    .frame(
                        width: bucket.count == 0
                            ? 0
                            : max(4, geometry.size.width * CGFloat(bucket.count) / CGFloat(largest)))
            }
            .frame(height: 5)
        }
        .help("\(bucket.label): \(bucket.count)")
    }

    private var recent: some View {
        VStack(alignment: .leading, spacing: 6) {
            heading(T("Lately"))
            if activity.isEmpty {
                Text(T("No checks yet, and no key used through the vault.")).foregroundStyle(.secondary)
            }
            ForEach(activity) { entry in
                HStack(spacing: 8) {
                    Text(entry.at, format: .dateTime.day().month(.abbreviated).hour().minute())
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .frame(width: 130, alignment: .leading)
                    Text(entry.key).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(describe(entry.kind)).foregroundStyle(.secondary).lineLimit(1)
                }
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

    private func heading(_ text: String) -> some View {
        Text(text).font(.headline)
    }
}
