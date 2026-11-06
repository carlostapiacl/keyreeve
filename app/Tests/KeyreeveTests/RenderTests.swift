import AppKit
import CryptoKit
import KeyreeveCatalog
import KeyreeveVault
import Foundation
import KeyreeveUI
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

    @Test func testTheViewsDrawInEachLanguageAndAppearance() throws {
        defer { UserDefaults.standard.removeObject(forKey: Language.settingsKey) }
        for language in [Language.english, Language.spanish] {
            UserDefaults.standard.set(language.rawValue, forKey: Language.settingsKey)
            let code = language == .spanish ? "es" : "en"
            let model = self.model()
            try render(MainView(model: model), named: "home-\(code)-light", appearance: .aqua)
            try render(MainView(model: model), named: "home-\(code)-dark", appearance: .darkAqua)
            let detail = MainView(model: model, initial: .attention, chosen: "old-cloud.csv")
            try render(detail, named: "detail-\(code)", appearance: .aqua)
            try render(MainView(model: model, initial: .all), named: "list-\(code)", appearance: .darkAqua)
            try render(WelcomeView(choose: {}), named: "welcome-\(code)", appearance: .aqua)
            try render(SettingsView(model: model), named: "settings-\(code)", appearance: .aqua)
            try render(LockedView(message: nil, unlock: {}), named: "locked-\(code)", appearance: .aqua)

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
            ready.providers = ProviderDirectory([ProviderInfo(id: "aws", name: "AWS", can_rotate: true)])
            ready.items[0].vault = .sealed
            try render(MainView(model: ready, initial: .all, chosen: "old-cloud.csv"), named: "rotate-\(code)", appearance: .aqua)
        }
    }
}
