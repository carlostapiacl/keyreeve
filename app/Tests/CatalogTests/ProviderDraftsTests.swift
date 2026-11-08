import Foundation
import KeyreeveCatalog
import Testing

/// Reading a drafted provider file in plain words, and which assistant the person chose.
struct ProviderDraftsTests {
    @Test func aFileInBlockStyleReadsToo() {
        let summary = RecipeSummary("""
            schema: 1
            provider: sentry
            name: Sentry
            hosts:
              - sentry.io
              - us.sentry.io
            auth:
              header: Authorization
              prefix: "Bearer "
            verify:
              method: GET
              path: /api/0/organizations/
            create: { method: POST, path: /keys }
            revoke: { method: DELETE, path: "/keys/{id}" }
            """)
        #expect(summary.provider == "sentry" && summary.name == "Sentry")
        #expect(summary.hosts == ["sentry.io", "us.sentry.io"])
        #expect(summary.auth == "header Authorization")
        #expect(summary.verify == "GET /api/0/organizations/")
        #expect(summary.rotates && !summary.runsPrograms)
    }

    @Test func aTypeOfAuthAndAProgramAreSaid() {
        let summary = RecipeSummary("provider: x\nhosts: []\nauth:\n  type: command\n  run: { program: check.sh }\n")
        #expect(summary.auth == "command" && summary.runsPrograms && summary.hosts.isEmpty)
    }

    @Test func whatCannotBeReadIsLeftOut() {
        let summary = RecipeSummary("not a provider file")
        #expect(summary.provider == nil && summary.hosts.isEmpty && summary.verify == nil)
    }

    @Test func theChosenAssistantIsReadFromSettings() throws {
        let defaults = try #require(UserDefaults(suiteName: "assistant-\(UUID().uuidString)"))
        let found = [Assistant(id: "claude", name: "Claude Code", command: ["/x/claude", "{prompt}"], readsFiles: false)]
        #expect(AssistantChoice.current(defaults: defaults, available: found) == nil)
        defaults.set("claude", forKey: Assistant.settingsKey)
        #expect(AssistantChoice.current(defaults: defaults, available: found)?.name == "Claude Code")
        defaults.set("codex", forKey: Assistant.settingsKey)
        #expect(AssistantChoice.current(defaults: defaults, available: found) == nil)
        defaults.set(AssistantChoice.custom, forKey: Assistant.settingsKey)
        defaults.set("mycli ask {prompt}", forKey: Assistant.customKey)
        #expect(AssistantChoice.current(defaults: defaults, available: found)?.command == ["mycli", "ask", "{prompt}"])
    }

    @Test func onlyAShippedProviderNamedInTheWordsIsOffered() {
        let directory = ProviderDirectory([
            ProviderInfo(id: "github", name: "GitHub"),
            ProviderInfo(id: "panel", name: "Panel", source: "local", approved: true),
        ])
        #expect(directory.shipped(matching: "my github deploy key")?.id == "github")
        #expect(directory.shipped(matching: "the Panel at home") == nil)
        #expect(directory.shipped(matching: "githubber") == nil)
    }
}
