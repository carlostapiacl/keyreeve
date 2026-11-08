import Foundation
import KeyreeveCatalog
import Testing

/// Telling apart several keys of one provider by the account an agent names.
struct AccountFitTests {
    let user = CatalogItem(
        path: "sentry-acme-mgmt.txt", tags: ["acme", "provider:sentry"],
        details: KeyDetails(provider: "sentry", fields: ["account": "jane-doe", "organizations": "jane-doe, globex-labs, acme"]))
    let personal = CatalogItem(
        path: "sentry-jane-doe.txt", tags: ["janedoe"],
        details: KeyDetails(provider: "sentry", fields: ["account": "jane-doe"]))
    let labs = CatalogItem(path: "sentry-globex.env", tags: ["globex-labs"])

    @Test func whatTheProviderSaidCountsMoreThanATagOrAFileName() {
        #expect(user.fit(account: "acme") == 2)
        #expect(personal.fit(account: "acme") == 0)
        #expect(personal.fit(account: "Jane Doe") == 2)
        #expect(labs.fit(account: "globex-labs") == 1)
        #expect(labs.fit(account: "globex") == 1)
        #expect(user.reaches == "jane-doe, globex-labs, acme")
    }

    @Test func onlyWholeWordsFitAndNoAccountFitsNothing() {
        let github = CatalogItem(path: "github-token.txt")
        #expect(github.fit(account: "globex") == 0)
        #expect(github.fit(account: "hub") == 0)
        #expect(user.fit(account: nil) == 0)
        #expect(user.fit(account: " - ") == 0)
    }
}
