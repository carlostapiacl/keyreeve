import Foundation
import KeyreeveVault
import Testing

/// An OAuth credential goes through the proxy like any other key: the same permissions, scoped the same way.
final class OAuthFixture: @unchecked Sendable {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("oauth-\(UUID().uuidString)")
    let proxy = FakeProxy()
    var prompts = 0
    var markedAlways = false
    static let sealed = #"{"type":"authorized_user","client_id":"764-a.apps.googleusercontent.com","client_secret":"CANARYsecret","refresh_token":"1//CANARYrefresh"}"#
    lazy var log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"))
    lazy var service: KeyService = {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return KeyService(
            index: {
                try KeyIndex.parse(
                    "[[key]]\nid = \"search-console\"\nsource = \"added/search-console\"\nprovider = \"google\"\nvariable = \"GOOGLE_APPLICATION_CREDENTIALS\"\n")
            },
            open: { _, _ in
                self.prompts += 1
                return Data(Self.sealed.utf8)
            },
            proxy: proxy, log: log,
            openUnattended: { _, _, _ in self.markedAlways ? Data(Self.sealed.utf8) : nil })
    }()

    func use(_ program: String, real: Bool? = nil, anyProgram: Bool? = nil, unattended: Bool? = nil, seconds: Int? = nil) -> KeyService.Response {
        var request = KeyService.Request(
            op: "use", key: "search-console", seconds: seconds, program: program, arguments: 1, agent: "cron", reason: "weekly report",
            cwd: "/w", real: real, anyProgram: anyProgram)
        request.unattended = unattended
        return service.handle(request, caller: nil)
    }

    deinit { try? FileManager.default.removeItem(at: folder) }
}

struct OAuthKeyTests {
    @Test func aPermissionCoversOneProgramAndAnotherAsks() throws {
        let f = OAuthFixture()
        let first = f.use("/usr/bin/python3")
        #expect(first.ok && first.standIn == "STAND-IN" && first.variable == "GOOGLE_APPLICATION_CREDENTIALS")
        #expect(f.use("/usr/bin/python3").ok)
        #expect(f.prompts == 1)
        // The proxy gets the sealed file whole, with no field: it reads the credential from it.
        #expect(f.proxy.added.count == 1 && f.proxy.added[0].provider == "google" && f.proxy.added[0].field == nil)
        #expect(f.use("/usr/bin/curl").ok)
        #expect(f.prompts == 2)
        let log = try String(contentsOf: f.log.url, encoding: .utf8)
        #expect(!log.contains("CANARY"))
        let answer = String(decoding: try JSONEncoder().encode(first), as: UTF8.self)
        #expect(!answer.contains("CANARY"))
    }

    @Test func aKeyMarkedAlwaysNeedsNoFingerAndTheRealOneAlwaysDoes() throws {
        let f = OAuthFixture()
        f.markedAlways = true
        #expect(f.use("/usr/bin/python3", unattended: true).ok)
        #expect(f.prompts == 0)
        // --real is the credential itself: asked each time, never remembered.
        #expect(f.use("/usr/bin/python3", real: true).value == OAuthFixture.sealed)
        #expect(f.use("/usr/bin/python3", real: true).ok)
        #expect(f.prompts == 2)
    }

    @Test func theMarkIsWrittenOnceAndTakenOffWhenATokenComesAgain() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("keys-\(UUID().uuidString).toml")
        defer { try? FileManager.default.removeItem(at: url) }
        var index = KeyIndex()
        try index.add(.init(id: "search-console", source: "g.json", provider: "google"))
        try index.add(.init(id: "other", source: "o.txt"))
        try Data(index.toml.utf8).write(to: url)

        try KeyIndex.markAuthorization(id: "search-console", active: false, in: url)
        let marked = try KeyIndex.load(from: url)
        #expect(marked.key("search-console")?.more.state == "reauthorize")
        #expect(marked.key("other")?.more.state == nil)
        var again = marked
        let markedTwice = again.markAuthorization(id: "search-console", active: false)
        #expect(!markedTwice, "already marked")
        // A token for a key never marked leaves the file alone.
        let clearedUnmarked = again.markAuthorization(id: "other", active: true)
        #expect(!clearedUnmarked)

        try KeyIndex.markAuthorization(id: "search-console", active: true, in: url)
        #expect(try KeyIndex.load(from: url).key("search-console")?.more.state == nil)
    }
}
