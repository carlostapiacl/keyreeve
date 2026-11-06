import AppKit
import KeyreeveCatalog
import SwiftUI

/// One key in a list: its name first, and the file as a detail.
struct KeyRow: View {
    let item: CatalogItem
    /// With the details open, the row keeps only what fits comfortably.
    let compact: Bool

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 5) {
                    Text(item.title).font(Theme.rowTitle).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    if item.vault == .sealed || item.vault == .outdated {
                        Image(systemName: "lock.shield.fill")
                            .font(Theme.caption)
                            .foregroundStyle(item.vault == .sealed ? Theme.good : Theme.warn)
                            .help(T(item.vault == .sealed ? "In the vault" : "The file changed after it was sealed"))
                            .accessibilityLabel(T(item.vault == .sealed ? "In the vault" : "The file changed after it was sealed"))
                    }
                }
                if !item.name.isEmpty {
                    Text(item.path).font(Theme.code).foregroundStyle(Theme.faint).lineLimit(1).truncationMode(.middle)
                }
                if let attention = item.attention {
                    Text(attention).font(Theme.caption).foregroundStyle(Theme.warn)
                } else if let account = item.details?.fields["account"] {
                    Text(account).font(Theme.caption).foregroundStyle(Theme.muted).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if !compact {
                HStack(spacing: 4) {
                    ForEach(visibleTags, id: \.self) { Chip(text: $0) }
                }
            }
            HStack {
                if item.criticality > 0 {
                    CriticalityMeter(value: item.criticality, suggested: item.criticalitySuggested)
                        .help(
                            "\(T("Criticality")): \(criticalityName(item.criticality))"
                                + (item.criticalitySuggested ? ". \(T("Suggested by the provider's file"))" : ""))
                }
            }
            .frame(width: 34, alignment: .leading)
            HStack {
                Spacer(minLength: 0)
                ResultBadge(item: item)
            }
            .frame(width: 112)
            if !compact {
                Text(levelName(item.level))
                    .font(Theme.caption)
                    .foregroundStyle(item.level == "never" ? Theme.text : Theme.muted)
                    .frame(width: 128, alignment: .trailing)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 5)
    }

    private var visibleTags: [String] {
        item.tags.filter { !$0.contains(":") && !["revoke", "confirm"].contains($0) }.prefix(2).map { $0 }
    }
}

struct ResultBadge: View {
    let item: CatalogItem

    var body: some View {
        switch item.lastResult {
        case "works": Badge(text: T("Works"), icon: "checkmark", tone: .good).help(item.lastChecked)
        case "rejected": Badge(text: T("Rejected"), icon: "xmark", tone: .bad).help(item.lastChecked)
        case "forbidden", "no_result": Badge(text: T("No answer"), icon: "questionmark", tone: .neutral)
        default:
            if item.isSecret {
                Text(T("Never checked")).font(Theme.caption).foregroundStyle(Theme.faint)
            }
        }
    }
}
