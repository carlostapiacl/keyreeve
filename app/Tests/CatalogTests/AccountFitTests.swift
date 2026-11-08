import Foundation
import KeyreeveCatalog
import Testing

/// Telling apart several keys of one provider by the account an agent names.
struct AccountFitTests {
    let user = CatalogItem(
        path: "sentry-restoiq-mgmt.txt", tags: ["restoiq", "provider:sentry"],
        details: KeyDetails(provider: "sentry", fields: ["account": "carlos-tapia", "organizations": "carlos-tapia, liquidity-hunters, restoiq"]))
    let personal = CatalogItem(
        path: "sentry-carlos-tapia.txt", tags: ["carlostapia"],
        details: KeyDetails(provider: "sentry", fields: ["account": "carlos-tapia"]))
    let lh = CatalogItem(path: "sentry-lh.env", tags: ["liquidity-hunters"])

    @Test func whatTheProviderSaidCountsMoreThanATagOrAFileName() {
        #expect(user.fit(account: "restoiq") == 2)
        #expect(personal.fit(account: "restoiq") == 0)
        #expect(personal.fit(account: "Carlos Tapia") == 2)
        #expect(lh.fit(account: "liquidity-hunters") == 1)
        #expect(lh.fit(account: "lh") == 1)
        #expect(user.reaches == "carlos-tapia, liquidity-hunters, restoiq")
    }

    @Test func onlyWholeWordsFitAndNoAccountFitsNothing() {
        let github = CatalogItem(path: "github-token.txt")
        #expect(github.fit(account: "lh") == 0)
        #expect(github.fit(account: "hub") == 0)
        #expect(user.fit(account: nil) == 0)
        #expect(user.fit(account: " - ") == 0)
    }
}
