import Foundation

/// Takes a key out of what a program prints, as the output streams by.
///
/// When a command gets the real value (`run`, `env`, `use --real`), whatever it prints goes back to whoever started
/// it, often an agent whose transcript is kept. This catches the value written plainly, in base64 and percent-encoded,
/// also when it is split across two reads. It cannot catch a program that hides the value on purpose: that is what the
/// stand-in and the proxy are for.
public struct OutputRedactor: Sendable {
    public static let mark = Data("[redacted]".utf8)
    /// Shorter than this, a value would black out ordinary words.
    public static let shortest = 4

    private let patterns: [Data]
    private let keep: Int
    private var pending = Data()

    public init(secrets: [Data]) {
        var seen = Set<Data>()
        var found: [Data] = []
        for secret in secrets {
            for part in [secret] + Self.parts(of: secret) {
                for form in Self.forms(of: part) where form.count >= Self.shortest && seen.insert(form).inserted {
                    found.append(form)
                }
            }
        }
        // The longest first, so a value that holds another is taken out whole.
        patterns = found.sorted { $0.count > $1.count }
        keep = max((patterns.first?.count ?? 1) - 1, 0)
    }

    public init(secrets: [String]) { self.init(secrets: secrets.map { Data($0.utf8) }) }

    public var isEmpty: Bool { patterns.isEmpty }

    /// The ways a program usually prints a value: as it is, without its last line break, in base64 and in a URL.
    public static func forms(of secret: Data) -> [Data] {
        var plain = [secret]
        if let text = String(data: secret, encoding: .utf8) {
            // A key sealed with its last line break is printed without it, and the line break that follows is not
            // part of the key.
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            plain = [Data(trimmed.utf8)]
            // Programs differ on which marks they leave as they are in a URL: none, or the four RFC 3986 allows.
            var unreserved = CharacterSet.alphanumerics
            unreserved.insert(charactersIn: "-._~")
            for allowed in [CharacterSet.alphanumerics, unreserved] {
                if let encoded = trimmed.addingPercentEncoding(withAllowedCharacters: allowed) { plain.append(Data(encoded.utf8)) }
            }
            // As JSON writes it: quotes, backslashes and line breaks escaped, and slashes with or without.
            let escaped = trimmed.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "\\r")
                .replacingOccurrences(of: "\t", with: "\\t")
            plain.append(Data(escaped.utf8))
            plain.append(Data(escaped.replacingOccurrences(of: "/", with: "\\/").utf8))
        }
        var all = plain
        for each in plain {
            let encoded = each.base64EncodedString()
            all.append(Data(encoded.utf8))
            all.append(Data(encoded.trimmingCharacters(in: CharacterSet(charactersIn: "=")).utf8))
            all.append(Data(encoded.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .trimmingCharacters(in: CharacterSet(charactersIn: "=")).utf8))
        }
        return all
    }

    /// Parts long enough to give a value away printed on their own: each line of a value on several (the body of a
    /// PEM, or one variable of an .env), and each string of a JSON file (the private key of a service account), as
    /// a program prints one field of it. Headers such as `-----BEGIN` and plain addresses are left as they are.
    public static func parts(of secret: Data) -> [Data] {
        guard let text = String(data: secret, encoding: .utf8) else { return [] }
        var found: [String] = []
        if text.contains("\n") {
            for line in text.split(whereSeparator: \.isNewline) {
                found.append(line.trimmingCharacters(in: .whitespaces))
                // NAME=value, as an .env holds it: the value is what a program prints.
                if let equals = line.firstIndex(of: "=") {
                    found.append(line[line.index(after: equals)...].trimmingCharacters(in: CharacterSet(charactersIn: "\"' ")))
                }
            }
        }
        if let json = try? JSONSerialization.jsonObject(with: secret) {
            func strings(_ any: Any) {
                if let text = any as? String { found.append(text) }
                if let list = any as? [Any] { list.forEach(strings) }
                if let object = any as? [String: Any] { object.values.forEach(strings) }
            }
            strings(json)
        }
        let whole = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return found.filter { $0.count >= partShortest && $0 != whole && !$0.hasPrefix("-----") && !$0.hasPrefix("http") }
            .map { Data($0.utf8) }
    }

    /// A part shorter than this is left alone: field names and words would black out with it.
    public static let partShortest = 16

    /// What can be passed on now. A few bytes stay behind, in case a value starts at the end of this read.
    public mutating func feed(_ chunk: Data) -> Data {
        guard !patterns.isEmpty else { return chunk }
        pending.append(chunk)
        pending = Self.replace(pending, patterns)
        guard pending.count > keep else { return Data() }
        let cut = pending.count - keep
        let out = Data(pending.prefix(cut))
        pending = Data(pending.suffix(keep))
        return out
    }

    /// What was held back, once the program is done.
    public mutating func finish() -> Data {
        defer { pending = Data() }
        return Self.replace(pending, patterns)
    }

    /// The whole text at once.
    public static func redact(_ data: Data, secrets: [Data]) -> Data {
        var one = OutputRedactor(secrets: secrets)
        return one.feed(data) + one.finish()
    }

    public static func redact(_ text: String, secrets: [String]) -> String {
        String(decoding: redact(Data(text.utf8), secrets: secrets.map { Data($0.utf8) }), as: UTF8.self)
    }

    private static func replace(_ data: Data, _ patterns: [Data]) -> Data {
        var data = data
        for pattern in patterns {
            var result = Data()
            var start = data.startIndex
            var changed = false
            while let found = data.range(of: pattern, in: start..<data.endIndex) {
                result.append(data[start..<found.lowerBound])
                result.append(mark)
                start = found.upperBound
                changed = true
            }
            if changed {
                result.append(data[start..<data.endIndex])
                data = result
            }
        }
        return data
    }
}
