import Foundation
import KeyreeveCatalog
import Testing

/// What helps finish sorting: which field, several keys in one file, the same account twice, and what a key is.
struct CleanupTests {
    @Test func aFileWithSeveralKeysIsSplitByThePrefixesInTheOrderItHasThem() {
        let notes = "main: re_AAAA1111\nold one re_BBBB2222, again re_AAAA1111\nre_ alone, sk_other"
        #expect(KeySplit.keys(in: notes, prefixes: ["re_"]) == ["re_AAAA1111", "re_BBBB2222"])
        #expect(KeySplit.keys(in: notes, prefixes: []).isEmpty)
        let names = KeySplit.names(for: "mail/resend-hz.txt", count: 2) { $0 == "mail/resend-hz-1.txt" }
        #expect(names == ["mail/resend-hz-2.txt", "mail/resend-hz-3.txt"])
        #expect(KeySplit.names(for: "token", count: 1) { _ in false } == ["token-1"])
    }

    @Test func whatTheLastCheckSaidTurnsIntoTheStepThatHelps() {
        let several = CatalogItem(path: "a.json", lastResult: "no_result", recipes: ["meta"], labels: ["access_token", "app_id"],
                                  lastReason: "the file holds more than one value, so name one with --field")
        #expect(several.needsField && several.attention == T("Choose which field holds the key"))
        var named = several
        named.field = "access_token"
        #expect(!named.needsField)
        let twoKeys = CatalogItem(path: "b.txt", lastResult: "no_result", recipes: ["resend"],
                                  lastReason: "the file holds several keys of this provider, so name one with --field")
        #expect(twoKeys.holdsSeveralKeys && twoKeys.attention == T("This file holds several keys: split it"))
    }

    @Test func aValueThatIsNotSecretIsNotFlaggedForAnOldRefusal() {
        let id = CatalogItem(path: "cloudflare-account-id.txt", level: "none", lastResult: "rejected", recipes: [])
        #expect(id.attention == nil)
        let token = CatalogItem(path: "t.txt", lastResult: "rejected", recipes: ["github"])
        #expect(token.attention == T("The last check was rejected"))
    }

    @Test func keysWhoseProviderSaidTheSameAccountAreFoundTogether() {
        let orgs = ["organizations": "jane-doe, acme"]
        let items = [
            CatalogItem(path: "a.txt", recipes: ["sentry"], details: KeyDetails(provider: "sentry", fields: orgs)),
            CatalogItem(path: "b.txt", recipes: ["sentry"], details: KeyDetails(provider: "sentry", fields: orgs)),
            CatalogItem(path: "c.txt", recipes: ["sentry"], details: KeyDetails(provider: "sentry", fields: ["account": "globex"])),
            CatalogItem(path: "d.txt", recipes: ["github"], details: KeyDetails(provider: "github", fields: orgs)),
        ]
        let same = CatalogSummary(items: items).sameAccount
        #expect(same["a.txt"] == ["b.txt"] && same["b.txt"] == ["a.txt"])
        #expect(same["c.txt"] == nil && same["d.txt"] == nil)
    }

    @Test func theAssistantSaysWhatAKeyIsAndADescriptionIsNeverWrittenOver() {
        let items = [CatalogItem(path: "id.txt"), CatalogItem(path: "x.txt", description: "mine"), CatalogItem(path: "y.txt")]
        let answer = #"""
            [{"path":"id.txt","kind":"public","what":"Cloudflare\naccount ID"},
             {"path":"x.txt","kind":"unknown","what":"Something"},
             {"path":"y.txt","kind":"unknown"}]
            """#
        let found = Suggester.read(answer, items: items, providers: ProviderDirectory())
        #expect(found.count == 2)
        #expect(found[0].kind == .notSecret && found[0].what == "Cloudflare account ID")
        let edit = found[0].edit(for: items[0])
        #expect(edit.level == "none" && edit.description == "Cloudflare account ID")
        #expect(found[1].kind == .described && found[1].edit(for: items[1]).description == nil)
    }

    @Test func placesSavedBeforeThePageToRevokeStillRead() throws {
        let old = #"{"files":[],"actions":["mis-lugares/vps1"],"nothingElse":false,"overlapMinutes":0}"#
        let places = try JSONDecoder().decode(KeyPlaces.self, from: Data(old.utf8))
        #expect(places.revokePage == nil && places.isDecided)
    }
}
