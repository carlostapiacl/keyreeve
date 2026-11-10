import AppKit
import CryptoKit
@testable import KeyreeveCatalog
@testable import KeyreeveVault
import Foundation
@testable import KeyreeveUI
import SwiftUI
import Testing

/// Draws the real views with made-up data. Set KEYREEVE_RENDER_DIR to keep the images.
@MainActor
struct RenderTests {
    static let sample = [
        CatalogItem(path: "old-cloud.csv", tags: ["revoke", "provider:aws", "infra"], modified: "2024-02-13", lastResult: "works", lastChecked: "2026-11-06", recipes: ["aws"], name: "AWS · deploy-user", description: "Old deploy user", details: KeyDetails(provider: "aws", fields: ["account": "111122223333", "arn": "arn:aws:iam::111122223333:user/deploy-user"], suggested_name: "AWS · 111122223333"), criticality: 4),
        CatalogItem(path: "backups/billing-old.env", tags: ["shop", "status:backup"], modified: "2025-03-02", lastResult: "works", lastChecked: "2026-11-06", recipes: ["github"], labels: ["GITHUB_TOKEN", "OTHER"]),
        CatalogItem(path: "hosting-readonly.txt", level: "free", tags: ["infra", "read-only"], modified: "2026-04-19", lastResult: "works", lastChecked: "2026-11-06", criticality: 4, criticalitySuggested: true, rotateDays: 180),
        CatalogItem(path: "notes/legacy-mail.txt", tags: ["blog"], modified: "2024-02-13", mode: "644"),
        CatalogItem(path: "payments.json", level: "never", tags: ["shop", "money"], modified: "2026-05-30", criticality: 5),
        CatalogItem(path: "deploy.pub", level: "none", tags: ["infra"], modified: "2026-07-03", mode: "644"),
        CatalogItem(path: "mail-token.txt", tags: ["blog", "provider:mail"], modified: "2026-01-11", lastResult: "rejected", lastChecked: "2026-11-06"),
    ]

    static let bringReport: BringReport = {
        func part(_ name: String?, line: Int, whole: Bool = false) -> BringCandidate.Part {
            .init(name: name, section: nil, line: line, span: whole ? nil : [0, 1], json: nil, whole: whole)
        }
        func key(_ id: Int, _ group: BringCandidate.Group, _ kind: String, _ provider: String?, _ paths: [String], _ parts: [BringCandidate.Part], reason: String? = nil) -> BringCandidate {
            BringCandidate(
                id: id, group: group, kind: kind, why: "", provider: provider, recipes: provider.map { [$0] } ?? [],
                check: reason.map { .init(recipe: provider ?? "", result: "no_result", reason: $0, tried: []) }, server: nil,
                origins: paths.map { .init(path: $0, area: $0.contains("/code/") ? "project" : "home", bytes: 1, modified: 1, parts: parts) },
                duplicate: paths.count > 1, from_project: paths.contains { $0.contains("/code/") },
                suggested: group == .works ? "seal" : group == .doubtful ? "decide" : "skip")
        }
        let candidates = [
            key(1, .works, "key", "github", ["/Users/demo/.config/gh/hosts.yml"], [part("oauth_token", line: 2)]),
            key(2, .works, "key", "aws", ["/Users/demo/.aws/credentials"], [part("aws_access_key_id", line: 2), part("aws_secret_access_key", line: 3)]),
            key(3, .works, "key", "openai", ["/Users/demo/.zshrc", "/Users/demo/code/shop/.env"], [part("OPENAI_API_KEY", line: 4)]),
            key(4, .doubtful, "key", nil, ["/Users/demo/.ssh/id_ed25519"], [part(nil, line: 1, whole: true)]),
            key(5, .doubtful, "login", nil, ["/Users/demo/.netrc"], [part("login", line: 2), part("password", line: 3)]),
            key(6, .doubtful, "key", "r2", ["/Users/demo/code/shop/.env"], [part("R2_ACCESS_KEY_ID", line: 5), part("R2_SECRET_ACCESS_KEY", line: 6)], reason: "its server is not approved yet"),
            key(7, .dead, "key", "telegram", ["/Users/demo/code/bot/.env"], [part("TELEGRAM_BOT_TOKEN", line: 1)]),
            key(8, .other, "configuration", nil, ["/Users/demo/code/bot/.env"], [part("TELEGRAM_CHAT_ID", line: 2)]),
            key(9, .other, "public", nil, ["/Users/demo/.ssh/id_ed25519.pub"], [part(nil, line: 1, whole: true)]),
        ]
        return BringReport(
            schema: 1, scope: "places", roots: [], suggested_projects: [], files: 9, checked: true, skipped: .init(),
            summary: .init(works: 3, doubtful: 3, other: 2, dead: 1, duplicates: 1), candidates: candidates)
    }()

    func render<V: View>(_ view: V, named name: String, appearance: NSAppearance.Name) throws {
        let host = NSHostingView(rootView: view.frame(width: 1000, height: 560))
        host.frame = NSRect(x: 0, y: 0, width: 1000, height: 560)
        host.appearance = NSAppearance(named: appearance)
        let window = NSWindow(contentRect: host.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        window.appearance = host.appearance
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
        host.layoutSubtreeIfNeeded()
        let image = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: image)
        let png = try XCTUnwrap(image.representation(using: .png, properties: [:]))
        XCTAssertGreaterThan(png.count, 1000)
        if let dir = ProcessInfo.processInfo.environment["KEYREEVE_RENDER_DIR"] {
            try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
        }
    }

    func model() -> AppModel {
        let model = AppModel(
            files: KeyreeveFiles(directory: FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-render")),
            binary: nil)
        model.items = Self.sample
        model.providers = ProviderDirectory([
            ProviderInfo(id: "aws", name: "AWS", dashboard: "https://console.aws.amazon.com/iam/home", hosts: ["sts.amazonaws.com"], can_identify: true, actions: [CustomAction(id: "runbook", label: "Open the runbook", label_es: "Abrir el runbook", open: "https://example.com")]),
            ProviderInfo(id: "github", name: "GitHub", dashboard: "https://github.com/settings/tokens", hosts: ["api.github.com"], can_identify: true),
            ProviderInfo(id: "acme", name: "Acme", hosts: ["api.acme.com"], source: "local", approved: false),
        ])
        model.hasCatalog = true
        model.unlocked = true
        let at = Date(timeIntervalSince1970: 1_793_900_000)
        model.activity = [
            ActivityItem(at: at, key: "hosting-readonly.txt", kind: .checked(result: "works")),
            ActivityItem(at: at, key: "mail-token.txt", kind: .checked(result: "rejected")),
            ActivityItem(at: at.addingTimeInterval(-90_000), key: "hosting-token", kind: .used(by: "deploy.sh")),
        ]
        model.message = "Up to date"
        model.lastRun = RunSummary(items: Self.sample, checked: Set(Self.sample.map(\.path)))
        return model
    }

    @Test func testAWeeklyScheduleIsAValidPlist() throws {
        let data = try WeeklySchedule.plist(binary: URL(fileURLWithPath: "/Applications/K.app/keyreeve-cli"), spanish: true)
        let parsed = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        let arguments = try #require(parsed?["ProgramArguments"] as? [String])
        XCTAssertEqual(arguments, ["/Applications/K.app/keyreeve-cli", "check-free", "--notify", "--spanish"])
        XCTAssertEqual((parsed?["StartCalendarInterval"] as? [String: Int])?["Weekday"], 1)
    }

    @Test func testClaudeCodesSettingsSayWhereKeyreeveIsConnected() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("claude-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: file) }
        let server = #"{"type":"stdio","command":"/x/dist/keyreeve-vault","args":["mcp"]}"#
        try #"{"projects":{"/p/b":{"mcpServers":{"k":\#(server)}},"/p/a":{"mcpServers":{"other":{"command":"/bin/other","args":["mcp"]}}}}}"#
            .write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(AgentConnection.read(from: file), .folders(["/p/b"]))
        try #"{"mcpServers":{"vault":\#(server)},"projects":{"/p/b":{"mcpServers":{"k":\#(server)}}}}"#
            .write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(AgentConnection.read(from: file), .everywhere)
        // Another server of the same program that is not the agent server does not count.
        try #"{"mcpServers":{"k":{"command":"/x/keyreeve-vault","args":["serve"]}}}"#.write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(AgentConnection.read(from: file), .none)
        XCTAssertEqual(AgentConnection.read(from: file.appendingPathExtension("missing")), .none)
    }

    @Test func testTheViewsDrawInEachLanguageAndAppearance() throws {
        // Each language only for the drawing, never the setting other tests read at the same time.
        for language in [Language.english, Language.spanish] {
            try Language.$override.withValue(language) {
                try draw(in: language)
            }
        }
    }

    private func draw(in language: Language) throws {
            let code = language == .spanish ? "es" : "en"
            let model = self.model()
            try render(MainView(model: model), named: "home-\(code)-light", appearance: .aqua)
            try render(MainView(model: model), named: "home-\(code)-dark", appearance: .darkAqua)
            let detail = MainView(model: model, initial: .attention, chosen: "old-cloud.csv")
            try render(detail, named: "detail-\(code)", appearance: .aqua)
            try render(MainView(model: model, initial: .all), named: "list-\(code)", appearance: .darkAqua)
            try render(WelcomeView(choose: {}), named: "welcome-\(code)", appearance: .aqua)
            try render(WelcomeView(choose: {}, withoutFolder: {}, bringIn: {}), named: "welcome-bring-\(code)", appearance: .aqua)
            let bring = self.model()
            bring.bringing = BringState(projects: [URL(fileURLWithPath: "/Users/demo/code"), URL(fileURLWithPath: "/Users/demo/Desktop")])
            try render(BringSheet(model: bring), named: "bring-choose-\(code)", appearance: .aqua)
            bring.bringing?.report = Self.bringReport
            bring.bringing?.decisions = AppModel.firstDecisions(Self.bringReport)
            bring.bringing?.step = .review
            try render(BringSheet(model: bring), named: "bring-review-\(code)", appearance: .darkAqua)
            bring.bringing?.sealed = [("openai", true), ("aws", false)]
            bring.bringing?.step = .done
            try render(BringSheet(model: bring), named: "bring-done-\(code)", appearance: .aqua)
            try render(SettingsView(model: model), named: "settings-\(code)", appearance: .aqua)
            try render(LockedView(message: nil, unlock: {}), named: "locked-\(code)", appearance: .aqua)
            try render(MainView(model: model, initial: .providers), named: "providers-\(code)", appearance: .aqua)
            let basic = ProviderBuilder(model: model)
            basic.description = "My Coolify panel at coolify.example.com"
            basic.yaml = ProviderBuilderTests.good
            basic.phase = .ready
            try render(ProviderBuilderView(model: model, builder: basic, close: {}), named: "provider-basic-\(code)", appearance: .aqua)
            let advanced = ProviderBuilder(model: model)
            advanced.yaml = ProviderBuilderTests.good
            advanced.advanced = true
            try render(ProviderBuilderView(model: model, builder: advanced, close: {}), named: "provider-advanced-\(code)", appearance: .darkAqua)

            try render(MainView(model: model, initial: .vault), named: "vault-intro-\(code)", appearance: .aqua)
            let setup = self.model()
            setup.vaultDraft = VaultDraft(enclave: SoftwareRecipient(), blob: Data())
            try render(MainView(model: setup, initial: .vault), named: "vault-recovery-\(code)", appearance: .aqua)
            let ready = self.model()
            ready.hasVault = true
            ready.items[2].vault = .sealed
            ready.items[4].vault = .outdated
            ready.message = nil
            ready.vaultComparison = {
                var report = VaultKeeper.CompareReport()
                report.same = ["hosting-readonly.txt"]
                report.different = ["payments.json"]
                return report
            }()
            try render(MainView(model: ready, initial: .vault), named: "vault-ready-\(code)", appearance: .darkAqua)
            ready.items[3].originalMoved = true
            ready.rotations = [RotationStatus(key: "mail-token.txt", phase: "waiting", manual: ["the id of the previous key is unknown: revoke it by hand"])]
            try render(MainView(model: ready, initial: .vault), named: "vault-rotations-\(code)", appearance: .aqua)
            // Rotations have their own section now, and the log is a page of the window.
            try render(MainView(model: ready, initial: .rotation), named: "rotation-\(code)", appearance: .aqua)
            try render(MainView(model: ready, initial: .log), named: "log-\(code)", appearance: .darkAqua)
            ready.providers = ProviderDirectory([ProviderInfo(id: "aws", name: "AWS", can_rotate: true)])
            ready.items[0].vault = .sealed
            try render(MainView(model: ready, initial: .vault), named: "vault-sealed-\(code)", appearance: .aqua)
            try render(MainView(model: ready, initial: .all, chosen: "old-cloud.csv"), named: "rotate-\(code)", appearance: .aqua)
            let log = AuditLog(url: FileManager.default.temporaryDirectory.appendingPathComponent("usage-\(UUID().uuidString).jsonl"))
            defer { try? FileManager.default.removeItem(at: log.url) }
            let caller = AuditLog.Observed(pid: 1, program: "/usr/bin/ssh", chain: ["ssh", "zsh", "claude"])
            try log.append(event: "granted", key: "vps", grant: "g-1", observed: caller, detail: "3600 seconds, ssh")
            try log.append(event: "signed", key: "vps", grant: "g-1", observed: caller, detail: "root at SHA256:ab12cd34")
            try log.append(event: "server", key: "vps", grant: "g-1", detail: "SHA256:ef56, asked")
            try log.append(event: "copied", key: "vps", detail: "to the clipboard")
            ready.keyIndex = KeyIndex(keys: [KeyIndex.Key(id: "vps", source: "old-cloud.csv", provider: KeyService.sshProvider)])
            ready.usage.entries = try log.entries().reversed()
            ready.usage.grants = [KeyService.GrantInfo(id: "g-1", key: "vps", program: "ssh", expires: Date().addingTimeInterval(1800))]
            try render(
                KeyUsagePanel(item: ready.items[0], model: ready).padding(24).frame(width: 420).background(Theme.background),
                named: "usage-\(code)", appearance: .darkAqua)
            ready.usage.brokenLine = 3
            try render(UsageLogSheet(model: ready), named: "usage-log-\(code)", appearance: .aqua)
            ready.usage.brokenLine = nil
            ready.keyIndex = KeyIndex(keys: [
                KeyIndex.Key(id: "vps", source: "old-cloud.csv", provider: KeyService.sshProvider),
                KeyIndex.Key(id: "hosting", source: "hosting-readonly.txt", provider: "hosting", variable: "HOSTING_TOKEN"),
                KeyIndex.Key(id: "legacy", source: "notes/legacy-mail.txt"),
            ])
            ready.items[1].vault = .sealed
            ready.items[3].originalMoved = true
            ready.agentPolicy = AgentPolicy(
                commands: ["legacy": ["/Users/a/.keyreeve/agent-tools/check-mail.sh"]], levels: ["hosting": .free, "vps": .ask],
                agents: ["vps": ["claude"]], hashes: ["vps": ["/Users/a/.keyreeve/agent-tools/check-mail.sh": "abc"]])
            let runs = AgentTranscript(url: ready.files.directory.appendingPathComponent(AgentTranscript.fileName))
            try? FileManager.default.createDirectory(at: ready.files.directory, withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: runs.url)
            runs.append(AgentTranscript.Entry(
                at: Date(timeIntervalSince1970: 1_793_900_000), agent: "claude", key: "hosting", command: "curl -s https://api.hosting.example/v1/sites",
                reason: "list the sites before deploying", exit: 0, output: "{\"sites\":[{\"name\":\"blog\"}]}", milliseconds: 412))
            runs.append(AgentTranscript.Entry(
                at: Date(timeIntervalSince1970: 1_793_900_060), agent: "codex", key: "vps", command: "ssh root@203.0.113.7 uptime", reason: "check the server",
                exit: 255, output: "Permission denied (publickey).", milliseconds: 1830))
            try render(MainView(model: ready, initial: .agents), named: "agents-\(code)", appearance: .aqua)
            try render(MainView(model: ready, initial: .agents), named: "agents-dark-\(code)", appearance: .darkAqua)
            try render(
                VStack(alignment: .leading, spacing: 10) { ForEach(Array(runs.entries().enumerated()), id: \.offset) { TerminalRow(run: $0.element) } }
                    .padding(24).frame(width: 700).background(Theme.background),
                named: "agents-terminal-\(code)", appearance: .darkAqua)
    }
}
