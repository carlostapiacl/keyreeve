import Foundation

/// A file of notes that holds more than one key of a provider, told apart by the provider's prefixes the
/// same way keyreeve's own check reads them, so each key can have a file of its own.
public enum KeySplit {
    /// The distinct words that start with one of the prefixes, in the order the file has them. A word that
    /// starts with a longer prefix of another provider is that provider's, so ElevenLabs' `sk_` does not take
    /// Stripe's `sk_test_…`: pass the other providers' prefixes as `others`.
    public static func keys(in text: String, prefixes: [String], others: [String] = []) -> [String] {
        guard !prefixes.isEmpty else { return [] }
        let words = text.split { !($0.isASCII && ($0.isLetter || $0.isNumber || "_-.".contains($0))) }.map(String.init)
        var found: [String] = []
        for word in words where !found.contains(word) {
            let own = prefixes.filter { word.hasPrefix($0) && word.count > $0.count }.map(\.count).max() ?? 0
            guard own > 0, !others.contains(where: { word.hasPrefix($0) && $0.count > own }) else { continue }
            found.append(word)
        }
        return found
    }

    /// Names for the new files beside the old one, such as `resend-hz-1.txt`, skipping names already taken.
    public static func names(for path: String, count: Int, taken: (String) -> Bool) -> [String] {
        let url = URL(fileURLWithPath: path)
        let ext = url.pathExtension
        let stem = ext.isEmpty ? path : String(path.dropLast(ext.count + 1))
        var names: [String] = []
        var number = 1
        while names.count < count {
            let name = "\(stem)-\(number)" + (ext.isEmpty ? "" : ".\(ext)")
            if !taken(name) { names.append(name) }
            number += 1
        }
        return names
    }
}
