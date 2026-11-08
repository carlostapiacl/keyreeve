import Foundation
import KeyreeveCatalog
import Testing

/// Recognising a pasted key without ever showing it.
struct AddKeyTests {
    let providers = ProviderDirectory([
        ProviderInfo(id: "elevenlabs", name: "ElevenLabs", prefixes: ["sk_"]),
        ProviderInfo(id: "stripe", name: "Stripe", prefixes: ["sk_live_", "sk_test_"]),
        ProviderInfo(id: "resend", name: "Resend", prefixes: ["re_"]),
        ProviderInfo(id: "meta", name: "Meta"),
    ])

    @Test func theLongestPrefixWins() {
        #expect(providers.recognize("sk_live_abc123")?.id == "stripe")
        #expect(providers.recognize("sk_abc123")?.id == "elevenlabs")
        #expect(providers.recognize("re_123")?.id == "resend")
        #expect(providers.recognize("EAAB123") == nil)
    }

    @Test func theHintShowsTheKnownStartAndTheLengthOnly() {
        let key = "re_SECRETPART_0123456789"
        let hint = ProviderDirectory.hint(of: key, provider: providers.recognize(key))
        #expect(hint == "re_… (\(key.count))")
        #expect(!hint.contains("SECRET"))
        // With no known start, nothing of the key at all.
        #expect(ProviderDirectory.hint(of: "EAABsecret", provider: nil) == "… (10)")
    }

    @Test func noSpanishWordIsGivenTwice() throws {
        let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Sources/KeyreeveCatalog/Strings.swift")
        let text = try String(contentsOf: file, encoding: .utf8)
        var seen = Set<String>(), twice: [String] = []
        for line in text.split(separator: "\n") where line.hasPrefix("    \"") {
            guard let end = line.range(of: "\": \"") else { continue }
            let key = String(line[line.index(line.startIndex, offsetBy: 5)..<end.lowerBound])
            if !seen.insert(key).inserted { twice.append(key) }
        }
        #expect(twice.isEmpty, "\(twice)")
    }
}
