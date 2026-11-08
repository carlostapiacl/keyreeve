import Foundation
import KeyreeveCatalog
import Testing

/// Proposals for keys keyreeve cannot check yet, from tags and field names, and what an assistant may add.
struct SuggestTests {
    let providers = ProviderDirectory([
        ProviderInfo(id: "sentry", name: "Sentry", env_var: "SENTRY_AUTH_TOKEN"),
        ProviderInfo(id: "meta", name: "Meta"),
    ])

    func item(_ path: String, tags: [String], labels: [String] = [], recipes: [String] = []) -> CatalogItem {
        CatalogItem(path: path, tags: tags, recipes: recipes, labels: labels)
    }

    @Test func aTagNamingAKnownProviderProposesItAndItsField() {
        let found = Suggester.suggest([
            item("a.env", tags: ["provider:sentry"], labels: ["DSN", "SENTRY_AUTH_TOKEN"]),
            item("b.txt", tags: ["provider:meta"]),
            item("c.env", tags: ["provider:meta"], labels: ["IG_TOKEN", "FB_TOKEN"]),
            item("d.txt", tags: ["provider:tiktok"]),
        ], providers: providers)
        #expect(found.map(\.path) == ["a.env", "b.txt", "c.env"])
        #expect(found[0].kind == .provider("sentry", field: "SENTRY_AUTH_TOKEN"))
        #expect(found[1].kind == .provider("meta", field: nil))
        // Two fields could be Meta's, so it does not guess.
        #expect(found[2].kind == .provider("meta", field: nil))
    }

    @Test func loginsDatabasesAndDocumentsHaveNothingToCheck() {
        let found = Suggester.suggest([
            item("a", tags: ["type:login"]), item("b", tags: ["type:base-de-datos"]), item("c", tags: ["type:document"]),
            item("d", tags: ["type:secreto-interno"]), item("e", tags: ["type:api-token"]),
        ], providers: providers)
        #expect(found.map(\.kind) == [.untestable, .untestable, .untestable, .internalSecret])
    }

    @Test func whatIsSortedOrHasARecipeIsLeftAlone() {
        let found = Suggester.suggest([
            item("a", tags: ["provider:sentry"], recipes: ["sentry"]),
            item("b", tags: ["provider:sentry", "untestable"]),
            item("c", tags: ["provider:sentry", "internal"]),
            item("d", tags: ["provider:sentry", "status:archived"]),
        ], providers: providers)
        #expect(found.isEmpty)
    }

    @Test func anUntestableKeyIsNotCheckableNorCountedAsUnchecked() {
        let key = item("a", tags: ["untestable"], recipes: ["sentry"])
        #expect(!key.canCheck)
        #expect(CatalogStats(items: [key]).neverChecked == 0)
    }

    @Test func anAssistantIsBelievedOnlyAboutProvidersAndFieldsThatExist() {
        let keys = [item("a.env", tags: [], labels: ["X", "Y"]), item("b.txt", tags: []), item("c.txt", tags: [])]
        let answer = """
            Sure:
            ```json
            [{"path": "a.env", "kind": "provider", "provider": "sentry", "field": "Z"},
             {"path": "b.txt", "kind": "provider", "provider": "made-up"},
             {"path": "c.txt", "kind": "untestable"},
             {"path": "nowhere", "kind": "untestable"}]
            ```
            """
        let read = Suggester.read(answer, items: keys, providers: providers)
        #expect(read.map(\.path) == ["a.env", "c.txt"])
        #expect(read[0].kind == .provider("sentry", field: nil))
    }

    @Test func whatGoesToTheAssistantHoldsNamesOnly() {
        let text = Suggester.describe([item("a.env", tags: ["provider:x"], labels: ["TOKEN"])])
        #expect(text.contains("a.env") && text.contains("TOKEN") && text.contains("provider:x"))
        #expect(!text.contains("value"))
    }

    @Test func manyEditsAreOneWriteAndKeepWhatWasThere() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("edits-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let files = KeyreeveFiles(directory: folder)
        try files.saveEdit(KeyEdit(name: "Mine"), for: "a.env")
        try files.saveEdits(["a.env": KeyEdit(recipes: ["sentry"]), "b.txt": KeyEdit(tags: ["untestable"])])
        let read = try JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: files.edits))
        #expect(read["a.env"]?.name == "Mine" && read["a.env"]?.recipes == ["sentry"])
        #expect(read["b.txt"]?.tags == ["untestable"])
    }
}
