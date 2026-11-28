import AppKit
@testable import KeyreeveCatalog
@testable import KeyreeveVault
import Foundation
@testable import KeyreeveUI
import SwiftUI
import Testing

/// The screenshots of the README and the site, drawn from the real views over made-up keys, in a real window
/// with its title bar. Off unless KEYREEVE_DOCS_SHOTS names a folder: the images go to <folder>/en and
/// <folder>/es, and `app/docs-screenshots.sh` copies them to docs/img.
@MainActor
struct DocsScreenshots {
    static let folder = ProcessInfo.processInfo.environment["KEYREEVE_DOCS_SHOTS"]

    static let keys: [(source: String, id: String, provider: String, name: String, description: String, tags: [String], result: String?)] = [
        ("acme-app.env", "acme-app", "cloudflare", "Acme · DNS", "DNS for example.com", ["acme", "infra"], "works"),
        ("github-demo.txt", "github-demo", "github", "GitHub · demo", "Deploys for the demo site", ["demo"], "works"),
        ("openai-demo.txt", "openai-demo", "openai", "OpenAI · demo", "Model key for the coding agent", ["demo", "agents"], "works"),
        ("mcp-example.json", "mcp-example", "example-mcp", "Example MCP", "Remote MCP server, signed in by keyreeve", ["agents"], "works"),
        ("resend-demo.txt", "resend-demo", "resend", "Resend · shop", "Mail for the demo shop", ["shop"], "works"),
        ("stripe-demo.txt", "stripe-demo", "stripe", "Stripe · test mode", "Test mode payments", ["shop", "money"], nil),
        ("hetzner-example.txt", "hetzner-example", "hetzner", "Hetzner · example", "Example server, read only", ["infra"], "works"),
        ("telegram-demo.env", "telegram-demo", "telegram", "Telegram · alerts", "Alerts bot", ["infra"], "rejected"),
    ]

    func model() -> AppModel {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("keyreeve-docs-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: home), binary: nil)
        model.items = Self.keys.map { key in
            var item = CatalogItem(
                path: key.source, tags: key.tags + ["provider:\(key.provider)"], modified: "2026-10-02", lastResult: key.result ?? "",
                lastChecked: key.result == nil ? "" : "2026-11-27", recipes: [key.provider], name: key.name, description: key.description)
            item.vault = .sealed
            return item
        }
        model.providers = ProviderDirectory(Self.keys.map {
            ProviderInfo(id: $0.provider, name: $0.name.components(separatedBy: " · ").first ?? $0.provider, hosts: ["api.\($0.provider).com"], can_identify: true)
        })
        model.keyIndex = KeyIndex(keys: Self.keys.map {
            KeyIndex.Key(id: $0.id, source: $0.source, provider: $0.provider, variable: $0.provider.uppercased().replacingOccurrences(of: "-", with: "_") + "_TOKEN")
        })
        model.agentPolicy = AgentPolicy(
            levels: ["openai-demo": .free, "mcp-example": .free, "github-demo": .ask, "resend-demo": .ask, "hetzner-example": .ask],
            agents: ["openai-demo": ["opencode"], "mcp-example": ["opencode", "claude"]])
        model.hasCatalog = true
        model.hasVault = true
        model.unlocked = true
        model.message = nil
        model.lastRun = RunSummary(items: model.items, checked: Set(model.items.map(\.path)))
        var use = KeyTidy.Use()
        use.count = 42
        use.last = Date().addingTimeInterval(-7200)
        use.agents = ["opencode"]
        use.hosts = ["api.openai.com"]
        var mcp = use
        mcp.count = 17
        mcp.agents = ["opencode", "claude"]
        mcp.hosts = ["mcp.example.com"]
        var mail = use
        mail.count = 3
        mail.last = Date().addingTimeInterval(-86_400)
        mail.agents = ["claude"]
        mail.hosts = ["api.resend.com"]
        model.inUse = [
            KeyInUse(id: "openai-demo", source: "openai-demo.txt", project: "demo", provider: "openai", description: "Model key for the coding agent", use: use),
            KeyInUse(id: "mcp-example", source: "mcp-example.json", project: "demo", provider: "example-mcp", description: "Remote MCP server", use: mcp),
            KeyInUse(id: "resend-demo", source: "resend-demo.txt", project: "shop", provider: "resend", description: "Mail for the demo shop", use: mail),
        ]
        return model
    }

    /// Draws a view in a titled window, as the app shows it, and keeps it as a PNG.
    func shoot<V: View>(_ view: V, named name: String, in folder: URL, locale: Locale) throws {
        _ = NSApplication.shared
        let size = NSSize(width: 1180, height: 700)
        let window = NSWindow(
            contentRect: NSRect(origin: NSPoint(x: -20000, y: -20000), size: size),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .aqua)
        window.titleVisibility = .hidden
        window.contentViewController = NSHostingController(rootView: view.frame(width: size.width, height: size.height).environment(\.locale, locale))
        window.setFrame(NSRect(origin: NSPoint(x: -20000, y: -20000), size: size), display: true)
        window.orderFrontRegardless()
        window.makeKey()
        RunLoop.main.run(until: Date().addingTimeInterval(1.5))
        defer { window.orderOut(nil) }
        let frame = try #require(window.contentView?.superview)
        frame.layoutSubtreeIfNeeded()
        // Twice the points, as on a Retina screen, whatever screen this runs on.
        let image = try #require(NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: Int(frame.bounds.width * 2), pixelsHigh: Int(frame.bounds.height * 2), bitsPerSample: 8,
            samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0))
        image.size = frame.bounds.size
        frame.cacheDisplay(in: frame.bounds, to: image)
        let png = try #require(image.representation(using: .png, properties: [:]))
        try png.write(to: folder.appendingPathComponent("\(name).png"))
    }

    @Test func testTheDocsScreenshots() throws {
        guard let root = Self.folder else { return }
        for language in [Language.english, Language.spanish] {
            let folder = URL(fileURLWithPath: root).appendingPathComponent(language == .spanish ? "es" : "en")
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let locale = Locale(identifier: language == .spanish ? "es_CL" : "en_US")
            try Language.$override.withValue(language) {
                try shoot(MainView(model: model(), initial: .home), named: "home", in: folder, locale: locale)
                try shoot(MainView(model: model(), initial: .all), named: "keys", in: folder, locale: locale)
                try shoot(MainView(model: model(), initial: .all, chosen: "openai-demo.txt", keyTab: .use), named: "key-usage", in: folder, locale: locale)
                try shoot(MainView(model: model(), initial: .agents), named: "agents", in: folder, locale: locale)
                try shoot(MainView(model: model(), initial: .vault), named: "vault", in: folder, locale: locale)
            }
        }
    }
}
