import AppKit
import KeyreeveCatalog
import KeyreeveUI
import SwiftUI
import Testing

/// Draws the real views with made-up data. Set KEYREEVE_RENDER_DIR to keep the images.
@MainActor
struct RenderTests {
    static let sample = [
        CatalogItem(path: "backups/billing-old.env", tags: ["shop", "status:backup"], modified: "2025-03-02", lastResult: "works", lastChecked: "2026-11-06", recipes: ["github"]),
        CatalogItem(path: "hosting-readonly.txt", level: "free", tags: ["infra", "read-only"], modified: "2026-04-19", lastResult: "works", lastChecked: "2026-11-06"),
        CatalogItem(path: "notes/legacy-mail.txt", tags: ["blog"], modified: "2024-02-13", mode: "644"),
        CatalogItem(path: "payments.json", level: "never", tags: ["shop", "money"], modified: "2026-05-30"),
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

    @Test func testTheViewsDrawInBothAppearances() throws {
        let catalog = CatalogView(
            items: Self.sample, source: "~/.keyreeve/catalog.csv", message: "Checked 1: 1 work", initial: .attention)
        try render(catalog, named: "catalog-light", appearance: .aqua)
        try render(catalog, named: "catalog-dark", appearance: .darkAqua)
        let detail = CatalogView(
            items: Self.sample, source: "~/.keyreeve/catalog.csv", initial: .attention,
            chosen: "backups/billing-old.env")
        try render(detail, named: "detail", appearance: .aqua)
        let at = Date(timeIntervalSince1970: 1_793_900_000)
        let home = CatalogView(
            items: Self.sample, source: "~/.keyreeve/catalog.csv",
            activity: [
                ActivityItem(at: at, key: "hosting-readonly.txt", kind: .checked(result: "works")),
                ActivityItem(at: at, key: "mail-token.txt", kind: .checked(result: "rejected")),
                ActivityItem(at: at.addingTimeInterval(-90_000), key: "hosting-token", kind: .used(by: "deploy.sh")),
            ])
        try render(home, named: "home-light", appearance: .aqua)
        try render(home, named: "home-dark", appearance: .darkAqua)
        try render(LockedView(message: nil, unlock: {}), named: "locked", appearance: .aqua)
        try render(EmptyCatalogView(problem: "There is no catalog yet", path: "~/.keyreeve/catalog.csv"), named: "empty", appearance: .aqua)
    }
}
