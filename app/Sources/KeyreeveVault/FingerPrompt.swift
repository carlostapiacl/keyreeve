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
        who: String, key: String, account: String? = nil, program: String? = nil, lasts: Lasts? = nil, to local: String? = nil,
        reason: String? = nil
    ) -> String {
        let with = program.map { spanish ? " con \($0)" : " with \($0)" } ?? ""
        let head = spanish ? "dejar que \(who) use \(key)" : "let \(who) use \(key)"
        let to = local.map { spanish ? " hacia \($0)" : " at \($0)" } ?? ""
        return head + Self.account(account) + to + with + Self.lasts(lasts) + said(reason)
    }

    /// "let python3 use 3 keys (meta-ads, calcom, sentry) with python3, for 5 min: “weekly report”". One finger for all.
    public static func useMany(
        who: String, keys: [String], program: String? = nil, lasts: Lasts? = nil, always: String? = nil, reason: String? = nil
    ) -> String {
        let shown = keys.prefix(6).joined(separator: ", ") + (keys.count > 6 ? (spanish ? " y \(keys.count - 6) más" : " and \(keys.count - 6) more") : "")
        let with = program.map { spanish ? " con \($0)" : " with \($0)" } ?? ""
        let count = spanish ? "\(keys.count) claves" : "\(keys.count) keys"
        let head = spanish ? "dejar que \(who) use \(count) (\(shown))" : "let \(who) use \(count) (\(shown))"
        let how = always.map { spanish ? ", siempre en \($0)" : ", always in \($0)" } ?? Self.lasts(lasts)
        return head + with + how + said(reason)
    }

    /// "send mesa-token to 127.0.0.1:8790 on this Mac": what approving a local service lets through, from then on.
    public static func local(_ pairs: [(key: String, address: String)]) -> String {
        let list = pairs.prefix(6).map { spanish ? "\($0.key) a \($0.address)" : "\($0.key) to \($0.address)" }
            .joined(separator: ", ") + (pairs.count > 6 ? (spanish ? " y \(pairs.count - 6) más" : " and \(pairs.count - 6) more") : "")
        return spanish ? "enviar \(list) en este Mac, por HTTP" : "send \(list) on this Mac, over plain HTTP"
    }

    /// "print the SHA-256 of mesa-token, for a server that checks it"
    public static func verifier(key: String) -> String {
        spanish ? "mostrar el SHA-256 de \(key), para un servidor que la verifica"
            : "print the SHA-256 of \(key), for a server that checks it"
    }

    /// "give the real key resend to node: “send the test email”"
    public static func real(who: String, key: String, account: String? = nil, reason: String? = nil) -> String {
        let head = spanish ? "dar la clave real de \(key)" + Self.account(account) + " a \(who)"
            : "give the real key \(key)" + Self.account(account) + " to \(who)"
        return head + said(reason)
    }
}
