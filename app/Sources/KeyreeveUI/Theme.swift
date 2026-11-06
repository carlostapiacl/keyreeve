import AppKit
import SwiftUI

/// The app's visual language, in one place. Views use these and never a raw color or size, and each
/// color has a light and a dark value chosen for contrast.
enum Theme {
    private static func dynamic(light: UInt32, dark: UInt32) -> Color {
        Color(
            nsColor: NSColor(name: nil) { appearance in
                let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                let hex = isDark ? dark : light
                return NSColor(
                    srgbRed: CGFloat((hex >> 16) & 255) / 255, green: CGFloat((hex >> 8) & 255) / 255,
                    blue: CGFloat(hex & 255) / 255, alpha: 1)
            })
    }

    static let background = dynamic(light: 0xF4F5F7, dark: 0x0E1116)
    static let surface = dynamic(light: 0xFFFFFF, dark: 0x171B22)
    static let raised = dynamic(light: 0xEEF0F3, dark: 0x20252E)
    static let border = dynamic(light: 0xDFE3E8, dark: 0x2A303A)
    static let text = dynamic(light: 0x161A20, dark: 0xEDF0F4)
    static let muted = dynamic(light: 0x59626F, dark: 0x9AA4B2)
    static let faint = dynamic(light: 0x848D9A, dark: 0x6B7482)
    static let accent = dynamic(light: 0x8F5B00, dark: 0xF2B544)
    static let onAccent = dynamic(light: 0xFFFFFF, dark: 0x1B1405)
    static let good = dynamic(light: 0x177245, dark: 0x4ADE80)
    static let warn = dynamic(light: 0xA65A00, dark: 0xFBBF24)
    static let bad = dynamic(light: 0xC02B2B, dark: 0xF87171)
    static let bar = dynamic(light: 0x3B6FB5, dark: 0x6C9BD9)

    static let radius: CGFloat = 10
    static let smallRadius: CGFloat = 6
    static let pagePadding: CGFloat = 28

    static let title = Font.system(size: 24, weight: .semibold)
    static let section = Font.system(size: 13, weight: .semibold)
    static let body = Font.system(size: 13)
    static let rowTitle = Font.system(size: 13, weight: .medium)
    static let caption = Font.system(size: 11)
    static let code = Font.system(size: 11, design: .monospaced)
    static let figure = Font.system(size: 22, weight: .semibold)
}

struct Card<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.radius))
            .overlay(RoundedRectangle(cornerRadius: Theme.radius).strokeBorder(Theme.border))
    }
}

enum Tone {
    case good, warn, bad, neutral

    var color: Color {
        switch self {
        case .good: return Theme.good
        case .warn: return Theme.warn
        case .bad: return Theme.bad
        case .neutral: return Theme.muted
        }
    }
}

/// A state, always with an icon and a word, so color is never the only signal.
struct Badge: View {
    let text: String
    let icon: String
    let tone: Tone

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon).imageScale(.small)
            Text(text).lineLimit(1)
        }
        .font(.system(size: 11, weight: .medium))
        .foregroundStyle(tone.color)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(tone.color.opacity(0.12), in: Capsule())
    }
}

struct Chip: View {
    let text: String

    var body: some View {
        Text(text)
            .font(Theme.caption)
            .foregroundStyle(Theme.muted)
            .lineLimit(1)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Theme.raised, in: RoundedRectangle(cornerRadius: 4))
    }
}

/// The app's buttons, with a hover and a pressed state.
struct KRButtonStyle: ButtonStyle {
    var primary = false
    @State private var hovering = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(primary ? Theme.onAccent : Theme.text)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(
                primary ? Theme.accent : (hovering ? Theme.border : Theme.raised),
                in: RoundedRectangle(cornerRadius: Theme.smallRadius)
            )
            .opacity(!enabled ? 0.45 : configuration.isPressed ? 0.7 : (primary && hovering ? 0.88 : 1))
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
    }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text).font(Theme.section).foregroundStyle(Theme.text)
    }
}

/// Criticality as five marks and a number, so color is never the only signal.
struct CriticalityMeter: View {
    let value: Int
    /// Faded when the number is a suggestion that nobody has confirmed.
    var suggested = false

    private var tone: Color {
        switch value {
        case 5: return Theme.bad
        case 4: return Theme.warn
        default: return Theme.muted
        }
    }

    var body: some View {
        HStack(spacing: 2) {
            ForEach(1...5, id: \.self) { step in
                RoundedRectangle(cornerRadius: 1)
                    .fill(step <= value ? tone : Theme.raised)
                    .frame(width: 5, height: 11)
            }
        }
        .opacity(suggested ? 0.45 : 1)
        .accessibilityLabel(Text("\(value) / 5"))
    }
}
