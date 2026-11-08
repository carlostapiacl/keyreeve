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
        #expect(proposal.hosts == ["a.txt": "https://panel.example.com"])
        #expect(proposal.split == ["c.txt"] && proposal.paths == ["a.txt", "c.txt"])
        #expect(CatalogItem(path: "a.txt").applying(KeyEdit(host: "https://panel.example.com")).host == "https://panel.example.com")
    }
}

