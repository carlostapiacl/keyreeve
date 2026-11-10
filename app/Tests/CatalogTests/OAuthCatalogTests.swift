import Foundation
import KeyreeveCatalog
import Testing

/// An OAuth credential: recognized when pasted, and shown like an expired key when its provider stops accepting it.
struct OAuthCatalogTests {
    let providers = ProviderDirectory([
        ProviderInfo(id: "google", name: "Google account", client_id_ends: ".apps.googleusercontent.com"),
        ProviderInfo(id: "paypal", name: "PayPal"),
        ProviderInfo(id: "resend", name: "Resend", prefixes: ["re_"]),
    ])

    @Test func aPastedCredentialsFileIsRecognizedByItsClientId() {
        let file = #"{"type":"authorized_user","client_id":"764-abc.apps.googleusercontent.com","client_secret":"CANARY","refresh_token":"1//CANARY"}"#
        #expect(providers.recognize(file)?.id == "google")
        // Another client, or no secret, is not guessed at.
        #expect(providers.recognize(#"{"client_id":"abc","client_secret":"x"}"#) == nil)
        #expect(providers.recognize(#"{"client_id":"764-abc.apps.googleusercontent.com"}"#) == nil)
        #expect(providers.recognize("re_123")?.id == "resend")
        // The hint says nothing of what is inside.
        #expect(!ProviderDirectory.hint(of: file, provider: providers.recognize(file)).contains("CANARY"))
    }

    @Test func aKeyItsProviderNoLongerAcceptsIsFlaggedLikeAnExpiredOne() {
        var item = CatalogItem(path: "google.json")
        #expect(item.attentionRanked == nil)
        item.needsReauthorizing = true
        #expect(item.attentionRanked?.rank == 1)
        #expect(item.attention == T("The provider no longer accepts it: authorize it again"))
        // Not for a value that is no secret, nor for one already retired.
        #expect(CatalogItem(path: "a", level: "none").attentionRanked == nil)
        var retired = CatalogItem(path: "b", tags: ["status:retired"])
        retired.needsReauthorizing = true
        #expect(retired.attentionRanked == nil)
    }
}
