import Foundation
import KeyreeveVault
import Testing

/// keys.toml as `keyreeve migrate` writes it: every key, with what is known of it, in one file.
struct KeyBookTests {
    /// The shape `keyreeve migrate` writes, with no real name or value: an identifier agents use, a key of
    /// two parts not offered yet, an archived one, and the room kept for keys signed in with OAuth.
    static let book = """
        # Your keys by identifier. This file holds no value. Edit it in the app, or here.
        schema = 2

        [[key]]
        id = "google"
        description = "Search Console"
        provider = "google"
        source = "gsc-token.json"
        parts = ["client_id", "client_secret", "refresh_token"]
        auth = "oauth"
        state = "reauthorize"
        level = "ask"
        tags = ["kind:google-oauth", "seo"]

        [[key]]
        id = "meta-old"
        provider = "meta"
        source = "meta-old.txt"
        level = "ask"
        tags = ["status:archived"]
        archived = true

        [[key]]
        id = "paypal-lh"
        name = "PayPal · LH"
        provider = "paypal"
        recipes = ["paypal"]
        account = "lh@example.com"
        source = "paypal-lh.json"
        parts = ["client_id", "secret"]
        level = "never"
        tags = []
        host = "api.example.com"
        expires = "2027-02-08"
        criticality = 5
        offered = false

        [[key]]
        id = "telegram"
        provider = "telegram"
        account = "a_bot"
        source = "telegram-agentes.env"
        field = "TELEGRAM_BOT_TOKEN"
        variable = "TELEGRAM_BOT_TOKEN"
        level = "free"

        """

    @Test func aBookOfEveryKeyReadsAndAgentsSeeOnlyTheKeysOfferedToThem() throws {
        let index = try KeyIndex.parse(Self.book)
        #expect(index.schema == 2)
        #expect(index.keys.map(\.id) == ["google", "meta-old", "telegram"])
        #expect(index.unoffered.map(\.id) == ["paypal-lh"])
        #expect(index.key("paypal-lh") == nil, "a key not offered is not one agents can name")
        #expect(index.isTaken("paypal-lh"))
        let google = try #require(index.key("google"))
        #expect(google.field == "client_id+client_secret+refresh_token")
        #expect(google.more.auth == "oauth")
        #expect(google.more.state == "reauthorize")
        #expect(index.key("meta-old")?.more.archived == true)
        let paypal = try #require(index.unoffered.first)
        #expect(paypal.more.criticality == 5)
        #expect(paypal.more.host == "api.example.com")
        #expect(paypal.more.tags == [])
    }

    @Test func writingItAgainKeepsEveryLine() throws {
        let index = try KeyIndex.parse(Self.book)
        #expect(index.toml == Self.book)
        #expect(try KeyIndex.parse(index.toml) == index)
    }

    @Test func aBookOfTheFirstVersionIsWrittenAsItWas() throws {
        let first = """
            # Your keys by identifier. This file holds no value. Edit it in the app, or here.

            [[key]]
            id = "google"
            provider = "google"
            source = "gsc-token.json"
            field = "client_id+client_secret+refresh_token"

            """
        let index = try KeyIndex.parse(first)
        #expect(index.schema == 1)
        #expect(index.toml == first, "an older Keyreeve still reads what this one writes")
    }

    @Test func givingAWaitingKeyToAgentsTakesItOverAndNoIdentifierIsGivenTwice() throws {
        var index = try KeyIndex.parse(Self.book)
        // A new name is never one a waiting key already has.
        #expect(index.identifier(for: "paypal lh") == "paypal-lh-2")
        #expect(index.suggestion(provider: "paypal", project: nil, source: "other.json") == "paypal")
        // Saving the waiting file for agents takes the waiting key over, with what it knew.
        try index.add(KeyIndex.Key(id: "paypal", source: "paypal-lh.json", variable: "PAYPAL_CLIENT"))
        #expect(index.unoffered.isEmpty)
        let paypal = try #require(index.key("paypal"))
        #expect(paypal.field == "client_id+secret")
        #expect(paypal.account == "lh@example.com")
        #expect(paypal.more.level == "never")
        #expect(index.toml.contains("parts = [\"client_id\", \"secret\"]"))
        #expect(!index.toml.contains("offered = false"))
    }

    @Test func whatTheFileCannotSayIsRefused() {
        let start = "schema = 2\n[[key]]\nid = \"a\"\nsource = \"a.txt\"\n"
        for bad in [
            "auth = \"magic\"", "state = \"lost\"", "level = \"sometimes\"", "parts = [\"one\"]",
            "field = \"x\"\nparts = [\"a\", \"b\"]", "offered = maybe", "criticality = high", "archived = true\narchived = true",
        ] {
            #expect(throws: (any Error).self, "\(bad)") { try KeyIndex.parse(start + bad + "\n") }
        }
        #expect(throws: (any Error).self) { try KeyIndex.parse("other = 1\n") }
    }
}
