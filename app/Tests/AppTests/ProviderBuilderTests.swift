import Foundation
import KeyreeveCatalog
import Testing
@testable import KeyreeveUI

/// Making a provider file in basic and advanced use, with a stand-in for the assistant and for keyreeve's check.
@MainActor
struct ProviderBuilderTests {
    static let good = "schema: 1\nprovider: my-panel\nname: My panel\nhosts: [panel.example.com]\nauth: { header: Authorization, prefix: \"Bearer \" }\nverify: { method: GET, path: /api/v1/version }\n"
    static let assistant = Assistant(id: "t", name: "Test", command: ["/bin/echo", "{prompt}"], readsFiles: false)

    final class Saved: @unchecked Sendable { var files: [String] = [] }

    func builder(answer: Result<String, Error>, valid: Bool = true, saved: Saved = Saved()) -> ProviderBuilder {
        ProviderBuilder(
            draft: { _, _ in
                let yaml = try answer.get()
                return (yaml, CheckRunner.RecipeReport(ok: valid, lines: [valid ? "draft: ok" : "draft: bad host"], provider: "my-panel"))
            },
            validate: { text in CheckRunner.RecipeReport(ok: text.contains("verify"), lines: ["checked"], provider: CheckRunner.providerID(in: text)) },
            save: { text in
                saved.files.append(text)
                return CheckRunner.providerID(in: text) ?? "x"
            })
    }

    func settle(until done: () -> Bool) async {
        for _ in 0..<200 where !done() { try? await Task.sleep(for: .milliseconds(10)) }
    }

    @Test func aDraftThatPassesIsReadyAndReadsInPlainWords() async {
        let b = builder(answer: .success(Self.good))
        b.description = "my panel at panel.example.com"
        b.ask(Self.assistant)
        #expect(b.phase == .asking)
        await settle { b.phase != .asking }
        #expect(b.phase == .ready)
        #expect(b.summary.hosts == ["panel.example.com"])
        #expect(b.summary.auth == "header Authorization")
        #expect(b.summary.verify == "GET /api/v1/version")
    }

    @Test func aDraftThatFailsSaysWhyAndAnAssistantErrorToo() async {
        let bad = builder(answer: .success(Self.good), valid: false)
        bad.description = "x"
        bad.ask(Self.assistant)
        await settle { bad.phase != .asking }
        #expect(bad.phase == .failed("draft: bad host"))
        let broken = builder(answer: .failure(CheckError("Test: not logged in")))
        broken.description = "x"
        broken.ask(Self.assistant)
        await settle { broken.phase != .asking }
        #expect(broken.phase == .failed("Test: not logged in"))
    }

    @Test func aCancelledAnswerLandsNowhere() async {
        let b = builder(answer: .success(Self.good))
        b.description = "x"
        b.ask(Self.assistant)
        b.cancel()
        try? await Task.sleep(for: .milliseconds(200))
        #expect(b.phase == .writing && b.yaml.isEmpty)
    }

    @Test func aProviderThatShipsIsOfferedFirst() {
        let directory = ProviderDirectory([
            ProviderInfo(id: "sentry", name: "Sentry"),
            ProviderInfo(id: "mine", name: "Mine", source: "local", approved: true),
        ])
        let b = builder(answer: .success(Self.good))
        b.description = "Sentry, the error tracker"
        #expect(b.lookForExisting(in: directory))
        #expect(b.offered?.id == "sentry")
        b.description = "Mine, my own"
        #expect(!b.lookForExisting(in: directory))
    }

    @Test func savingKeepsTheFileAndValidatingChecksIt() {
        let saved = Saved()
        let b = builder(answer: .success(Self.good), saved: saved)
        b.yaml = Self.good
        b.check()
        #expect(b.phase == .ready)
        #expect(b.saveNow() == "my-panel")
        #expect(b.phase == .saved("my-panel") && saved.files == [Self.good])
        b.yaml = "schema: 1\nprovider: x\n"
        b.check()
        #expect(b.phase == .failed("checked"))
    }

    @Test func aShippedProviderStartsAFileOfYourOwn() {
        let b = builder(answer: .success(Self.good))
        b.start(from: ProviderInfo(id: "resend", name: "Resend", hosts: ["api.resend.com"], prefixes: ["re_"]))
        #expect(b.advanced && b.editing == nil)
        #expect(CheckRunner.providerID(in: b.yaml) == "resend-mine")
        #expect(b.summary.hosts == ["api.resend.com"])
        #expect(b.yaml.contains("prefixes: [re_]"))
    }

    @Test func yourOwnFileIsFoundByTheIdItDeclares() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("providers-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try Self.good.write(to: folder.appendingPathComponent("whatever.yaml"), atomically: true, encoding: .utf8)
        #expect(ProviderBuilder.ownFile("my-panel", in: folder) == Self.good)
        #expect(ProviderBuilder.ownFile("other", in: folder) == nil)
    }

    @Test func aShippedRecipeIsCopiedWhole() {
        let builder = ProviderBuilder(
            draft: { _, _ in throw CheckError("no") }, validate: { _ in throw CheckError("no") }, save: { _ in "" },
            shipped: { id in id == "resend" ? "schema: 1\nprovider: resend\nname: Resend\ntested: { check: 2026-11 }\nverify: { method: GET, path: /domains }\n" : nil })
        builder.start(from: ProviderInfo(id: "resend", name: "Resend"))
        #expect(builder.yaml.contains("provider: resend-mine"))
        #expect(builder.yaml.contains("name: Resend (mine)"))
        #expect(builder.yaml.contains("path: /domains"))
        #expect(!builder.yaml.contains("tested:"))
        #expect(builder.advanced)
    }
}
