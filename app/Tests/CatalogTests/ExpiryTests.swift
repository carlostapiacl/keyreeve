import Foundation
import KeyreeveCatalog
import Testing

/// When keys stop working, and what is said before and after.
struct ExpiryTests {
    let now = Date(timeIntervalSince1970: 1_794_096_000)  // 2026-11-08 UTC

    @Test func aKeyIsFlaggedTwoWeeksBeforeItEndsAndOnceItHas() {
        #expect(CatalogItem(path: "a", expires: "2026-11-13").attentionRanked(at: now)?.text == T("Expires in %d days", 5))
        #expect(CatalogItem(path: "a", expires: "2026-11-09").attentionRanked(at: now)?.text == T("Expires tomorrow"))
        #expect(CatalogItem(path: "a", expires: "2026-11-01").attentionRanked(at: now)?.rank == 1)
        #expect(CatalogItem(path: "a", expires: "2027-01-31").attentionRanked(at: now) == nil)
        #expect(CatalogItem(path: "a", level: "none", expires: "2026-11-01").attentionRanked(at: now) == nil)
        #expect(CatalogItem(path: "a", expires: "2026-11-15").daysLeft(at: now) == 7)
    }

    @Test func whatTheProviderSaidCountsWhenNobodyWroteADay() {
        let item = CatalogItem(path: "gh", details: KeyDetails(provider: "github", fields: ["expires": "2026-12-01 00:00:00 UTC"]))
        #expect(item.expiryDay == "2026-12-01")
        var written = item
        written.expires = "2026-11-20"
        #expect(written.expiryDay == "2026-11-20")
        #expect(CatalogItem(path: "x", details: KeyDetails(provider: "p", fields: ["expires": "never"])).expiryDay == nil)
    }

    @Test func aCloudflareTokenIsFlaggedFromTheDayItsProviderGave() {
        let ending = CatalogItem(path: "cf", details: KeyDetails(provider: "cloudflare", fields: ["expires": "2026-11-18T00:00:00Z", "token_status": "active"]))
        #expect(ending.expiryDay == "2026-11-18")
        #expect(ending.attentionRanked(at: now)?.text == T("Expires in %d days", 10))
        let forever = CatalogItem(path: "cf", details: KeyDetails(provider: "cloudflare", fields: ["token_status": "active"]))
        #expect(forever.expiryDay == nil && forever.attentionRanked(at: now) == nil)
    }

    @Test func theCatalogCarriesTheDayAndAFilterShowsThoseEndingSoon() throws {
        let text = "path,level,tags,format,modified,mode,reviewed,expires\na,ask,,text,2026-01-01,600,true,2026-11-20\nb,ask,,text,2026-01-01,600,true,\n"
        let items = try CatalogParser.parse(text)
        #expect(items[0].expires == "2026-11-20" && items[1].expires.isEmpty)
        #expect(filter(items, by: .expiring, search: "").map(\.path) == ["a"])
    }

    @Test func anAgentCanSayWhenAKeyEnds() {
        let items = [CatalogItem(path: "a"), CatalogItem(path: "b")]
        let json = #"[{"path":"a","expires":"2026-12-31"},{"path":"b","expires":"soon"}]"#
        let proposal = SortProposal.read(Data(json.utf8), items: items, providers: ProviderDirectory())
        #expect(proposal.expires == ["a": "2026-12-31"] && proposal.paths == ["a"])
    }
}
