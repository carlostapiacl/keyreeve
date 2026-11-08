import Foundation

/// The words under the fingerprint sensor. macOS shows them as "<program> is trying to <these words>", so each one
/// says who asks, for which key and account, with what, for how long, and, short and in quotes, what the asker says
/// it is for. The quotes set the asker's words apart from keyreeve's own.
public enum FingerPrompt {
    public enum Lasts: Equatable, Sendable {
        case once
        case minutes(Int)
        case hours(Int)
        case untilQuit
    }

    static var spanish: Bool { Locale.preferredLanguages.first?.hasPrefix("es") ?? false }

    /// What the asker says, on one line and cut, so a long reason cannot crowd out who is asking.
    static func said(_ reason: String?) -> String {
        guard let reason else { return "" }
        let line = AgentRequest.oneLine(reason)
        guard !line.isEmpty else { return "" }
        let cut = line.count > 60 ? String(line.prefix(59)) + "…" : line
        return spanish ? ": «\(cut)»" : ": \u{201C}\(cut)\u{201D}"
    }

    static func account(_ account: String?) -> String { account.map { " (\($0))" } ?? "" }

    static func lasts(_ lasts: Lasts?) -> String {
        switch lasts {
        case nil, .once?: return ""
        case .minutes(let n)?: return spanish ? ", por \(n) min" : ", for \(n) min"
        case .hours(let n)?: return spanish ? ", por \(n) h" : ", for \(n) h"
        case .untilQuit?: return spanish ? " hasta que salgas de Keyreeve" : " until you quit Keyreeve"
        }
    }

    /// "let claude use pexels with curl, for 1 h: “find a photo”"
    public static func use(
        who: String, key: String, account: String? = nil, program: String? = nil, lasts: Lasts? = nil, reason: String? = nil
    ) -> String {
        let with = program.map { spanish ? " con \($0)" : " with \($0)" } ?? ""
        let head = spanish ? "dejar que \(who) use \(key)" : "let \(who) use \(key)"
        return head + Self.account(account) + with + Self.lasts(lasts) + said(reason)
    }

    /// "give the real key resend to node: “send the test email”"
    public static func real(who: String, key: String, account: String? = nil, reason: String? = nil) -> String {
        let head = spanish ? "dar la clave real de \(key)" + Self.account(account) + " a \(who)"
            : "give the real key \(key)" + Self.account(account) + " to \(who)"
        return head + said(reason)
    }
}
