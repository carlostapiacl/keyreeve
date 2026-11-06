import KeyreeveCatalog
import SwiftUI

/// The first screen: what to do next, then how things stand. Every figure opens its keys.
struct HomeView: View {
    let stats: CatalogStats
    let activity: [ActivityItem]
    let open: (Sidebar, String?) -> Void

    private let shownFirst = 6

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                summary
                HStack(alignment: .top, spacing: 32) {
                    doFirst.frame(maxWidth: .infinity, alignment: .leading)
                    checks.frame(width: 250, alignment: .leading)
                }
                HStack(alignment: .top, spacing: 32) {
                    bars("Secrets by project", stats.projects).frame(maxWidth: .infinity, alignment: .leading)
                    bars("Age of the files", stats.ages).frame(width: 250, alignment: .leading)
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
            figure("\(stats.secrets)", "secrets", .all)
            figure("\(stats.needLook.count)", "need a look", .attention)
            figure("\(stats.checked) of \(stats.secrets)", "checked", .all)
            figure("\(stats.canCheck)", "can be checked", .checkable)
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
        VStack(alignment: .leading, spacing: 8) {
            heading("Do first")
            if stats.needLook.isEmpty {
                Text("Nothing needs a look.").foregroundStyle(.secondary)
            }
            ForEach(stats.needLook.prefix(shownFirst)) { item in
                Button {
                    open(.attention, item.path)
                } label: {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: icon(for: item)).foregroundStyle(color(for: item)).imageScale(.small)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(item.path).lineLimit(1).truncationMode(.middle)
                            Text(item.attention ?? "").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            if stats.needLook.count > shownFirst {
                Button("All \(stats.needLook.count)") { open(.attention, nil) }
                    .buttonStyle(.link)
                    .font(.callout)
            }
        }
    }

    private func icon(for item: CatalogItem) -> String {
        (item.attentionRanked?.rank ?? 9) <= 2 ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill"
    }

    private func color(for item: CatalogItem) -> Color {
        (item.attentionRanked?.rank ?? 9) <= 2 ? .red : .orange
    }

    private var checks: some View {
        VStack(alignment: .leading, spacing: 8) {
            heading("Last checks")
            status("Works", stats.works, "checkmark.circle.fill", .green)
            status("Rejected", stats.rejected, "xmark.circle.fill", .red)
            status("No answer", stats.noAnswer, "questionmark.circle", .secondary)
            status("Never checked", stats.neverChecked, "circle.dashed", .secondary)
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
            heading("Lately")
            if activity.isEmpty {
                Text("No checks yet, and no key used through the vault.").foregroundStyle(.secondary)
            }
            ForEach(activity) { entry in
                HStack(spacing: 8) {
                    Text(entry.at, format: .dateTime.day().month(.abbreviated).hour().minute())
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .frame(width: 120, alignment: .leading)
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
            case "works": return "Checked: works"
            case "rejected": return "Checked: rejected"
            default: return "Checked: no answer"
            }
        case .used(let program): return "Used by \(program)"
        }
    }

    private func heading(_ text: String) -> some View {
        Text(text).font(.headline)
    }
}
