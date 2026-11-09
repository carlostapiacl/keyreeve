import Foundation
import KeyreeveCatalog
import Testing

struct SortProposalTests {
    let items = [
        CatalogItem(path: "a.txt"), CatalogItem(path: "b.env", labels: ["TOKEN", "URL"]), CatalogItem(path: "c.txt"),
    ]
    let providers = ProviderDirectory([ProviderInfo(id: "github", name: "GitHub", hosts: ["api.github.com"])])

    @Test func aProposalKeepsOnlyKnownFilesProvidersAndFields() {
        let json = #"""
            [{"path":"b.env","kind":"provider","provider":"github","field":"TOKEN","check":true,"seal":true},
             {"path":"a.txt","kind":"public","what":"An id"},
             {"path":"c.txt","kind":"provider","provider":"nobody","archive":true},
             {"path":"zzz.txt","kind":"public","seal":true}]
            """#
        let proposal = SortProposal.read(Data(json.utf8), items: items, providers: providers)
        #expect(proposal.paths == ["b.env", "a.txt", "c.txt"])
        #expect(proposal.suggestion(for: "b.env")?.kind == .provider("github", field: "TOKEN"))
        #expect(proposal.suggestion(for: "c.txt") == nil)
        #expect(proposal.check == ["b.env"] && proposal.seal == ["b.env"] && proposal.archive == ["c.txt"])
    }

    @Test func aKeyAsAnEditLeavesIt() {
        let item = CatalogItem(path: "b.env", level: "ask", tags: ["x"], labels: ["TOKEN"])
        let after = item.applying(KeyEdit(tags: ["x", "y"], level: "none", recipes: ["github"], field: "TOKEN", description: "d"))
        #expect(after.tags == ["x", "y"] && after.level == "none" && after.recipes == ["github"] && after.field == "TOKEN" && after.description == "d")
        #expect(item.applying(KeyEdit()) == item)
    }

    @Test func aServerIsKeptOnlyOverHttpsAndSplittingIsAsked() {
        let json = #"[{"path":"a.txt","host":"https://panel.example.com"},{"path":"b.env","host":"http://x.example.com"},{"path":"c.txt","split":true}]"#
        let proposal = SortProposal.read(Data(json.utf8), items: items, providers: providers)
        #expect(proposal.hosts == ["a.txt": "panel.example.com"])
        #expect(proposal.split == ["c.txt"] && proposal.paths == ["a.txt", "c.txt"])
        #expect(SortProposal.server("panel.example.com:8443") == "panel.example.com:8443")
        #expect(SortProposal.server("https://panel.example.com/") == "panel.example.com")
        #expect(SortProposal.server("ftp://panel.example.com") == nil)
        #expect(SortProposal.server("panel.example.com/admin") == nil)
        #expect(SortProposal.server("me@panel.example.com") == nil)
        #expect(CatalogItem(path: "a.txt").applying(KeyEdit(host: "panel.example.com")).host == "panel.example.com")
    }
}


/// What a key already has stays: an empty field never takes away a field, and an assistant only fills gaps.
struct KeepWhatAKeyHasTests {
    let combined = "client_id+client_secret+refresh_token"
    var gsc: CatalogItem {
        CatalogItem(
            path: "gsc-token.json", level: "ask", tags: ["provider:google"], recipes: ["google"], field: combined,
            labels: ["client_id", "client_secret", "refresh_token", "token"], description: "Search Console")
    }

    @Test func anEmptyFieldNeverTakesAwayTheFieldAKeyHas() {
        let base = KeyEdit(recipes: ["google"], field: combined)
        #expect(KeyEdit.merging(KeyEdit(field: ""), into: base).field == combined)
        #expect(KeyEdit.merging(KeyEdit(field: "token"), into: base).field == "token")
        #expect(gsc.applying(KeyEdit(field: "")).field == combined)
    }

    @Test func anApprovedProposalWithAFieldInPartsSetsIt() {
        let bare = CatalogItem(path: "gsc-token.json", recipes: ["google"], labels: ["client_id", "client_secret", "refresh_token", "token"])
        let providers = ProviderDirectory([ProviderInfo(id: "google", name: "Google", hosts: ["oauth2.googleapis.com"])])
        let json = #"[{"path":"gsc-token.json","kind":"provider","provider":"google","field":"client_id+client_secret+refresh_token"}]"#
        let edit = SortProposal.read(Data(json.utf8), items: [bare], providers: providers).suggestion(for: bare.path)?.edit(for: bare)
        #expect(edit?.field == combined)
        // Over an empty field an older edit left behind, the proposal's field is what stays.
        #expect(KeyEdit.merging(edit ?? KeyEdit(), into: KeyEdit(field: "")).field == combined)
    }

    @Test func anAssistantNeverChangesWhatAKeyAlreadyHas() {
        let item = gsc
        for kind: Suggestion.Kind in [
            .provider("google", field: "refresh_token"), .provider("youtube", field: nil), .untestable, .internalSecret, .notSecret,
            .described,
        ] {
            let edit = Suggestion(path: item.path, kind: kind, why: "assistant", what: "Something else").edit(for: item, fillingOnly: true)
            #expect(edit == KeyEdit(), "\(kind) changed \(edit)")
        }
    }

    @Test func anAssistantFillsOnlyWhatIsMissing() {
        let bare = CatalogItem(path: "x.env", level: "ask", tags: ["infra"], labels: ["A", "B"])
        let edit = Suggestion(path: bare.path, kind: .provider("github", field: "A"), why: "assistant", what: "GitHub").edit(for: bare, fillingOnly: true)
        #expect(edit.recipes == ["github"] && edit.field == "A" && edit.description == "GitHub" && edit.level == nil)
        let named = CatalogItem(path: "y.env", level: "ask", recipes: ["github"], labels: ["A", "B"])
        let fieldOnly = Suggestion(path: named.path, kind: .provider("github", field: "B"), why: "assistant").edit(for: named, fillingOnly: true)
        #expect(fieldOnly == KeyEdit(field: "B"))
    }
}

/// An agent's proposal as it was approved on 2026-11-09: four keys with fields in parts.
struct FieldsInPartsTests {
    static let approved = #"""
        [{"check":true,"field":"client_id+client_secret+refresh_token","kind":"provider","path":"gsc-token.json","provider":"google"},
         {"check":true,"field":"client_id+client_secret+refresh_token","kind":"provider","path":"youtube_token_restoiq.json","provider":"google"},
         {"field":"client_id+secret","kind":"provider","path":"paypal-lh.json","provider":"paypal"},
         {"field":"client_id+secret","kind":"provider","path":"paypal-recetas.json","provider":"paypal"}]
        """#
    static let providers = ProviderDirectory([
        ProviderInfo(id: "google", name: "Google account", can_identify: true), ProviderInfo(id: "paypal", name: "PayPal", can_identify: true),
    ])
    static let paths = ["gsc-token.json", "youtube_token_restoiq.json", "paypal-lh.json", "paypal-recetas.json"]

    @Test func aFieldTheListCannotVouchForYetIsKeptFromTheAgentsProposal() {
        // The list of a key whose field names were not read yet, as when the app has just opened.
        let items = Self.paths.map { CatalogItem(path: $0, level: "ask", recipes: [$0.hasPrefix("paypal") ? "paypal" : "google"]) }
        let proposal = SortProposal.read(Data(Self.approved.utf8), items: items, providers: Self.providers)
        for path in Self.paths {
            guard case .provider(_, let field)? = proposal.suggestion(for: path)?.kind else {
                Issue.record("no suggestion for \(path)")
                continue
            }
            #expect(field == (path.hasPrefix("paypal") ? "client_id+secret" : "client_id+client_secret+refresh_token"))
        }
        #expect(proposal.fieldsLeftOut.isEmpty)
    }

    @Test func aFieldTheListSaysTheFileLacksIsLeftOutAndSaid() {
        let items = [CatalogItem(path: "paypal-lh.json", recipes: ["paypal"], labels: ["api_base", "client_id"])]
        let proposal = SortProposal.read(Data(Self.approved.utf8), items: items, providers: Self.providers)
        #expect(proposal.suggestion(for: "paypal-lh.json")?.kind == .provider("paypal", field: nil))
        #expect(proposal.fieldsLeftOut == ["paypal-lh.json": "client_id+secret"])
    }

    @Test func anEmptyFieldAlreadyWrittenIsDroppedAtTheNextWrite() {
        #expect(KeyEdit.merging(KeyEdit(description: "d"), into: KeyEdit(field: "")).field == nil)
        #expect(KeyEdit.merging(KeyEdit(field: "client_id+secret"), into: KeyEdit(field: "")).field == "client_id+secret")
    }

    @Test func anAssistantStillNeedsTheFieldNamesToNameAField() {
        let items = [CatalogItem(path: "gsc-token.json", recipes: ["google"])]
        let answer = #"[{"path":"gsc-token.json","kind":"provider","provider":"google","field":"client_id+client_secret+refresh_token"}]"#
        #expect(Suggester.read(answer, items: items, providers: Self.providers).first?.kind == .provider("google", field: nil))
    }
}
