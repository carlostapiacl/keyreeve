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

    @Test func theMarkIsWrittenOnceKeepsItsDayAndGoesWhenATokenComesAgain() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("state-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: folder) }
        let url = folder.appendingPathComponent(KeyStates.fileName)
        #expect(KeyStates.needingReauthorization(in: url).isEmpty)
        let first = Date(timeIntervalSince1970: 1_800_000_000)
        try KeyStates.mark(id: "search-console", active: false, in: url, now: first)
        #expect(KeyStates.needingReauthorization(in: url) == ["search-console"])
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
        // A service started again finds the mark, tries once, and is refused again: the day stays the first one.
        try KeyStates.mark(id: "search-console", active: false, in: url, now: first.addingTimeInterval(3600))
        #expect(KeyStates.load(from: url)["search-console"]?.since == first)
        // A token for a key never marked leaves the file alone, and one for the marked key takes the mark off.
        try KeyStates.mark(id: "other", active: true, in: url)
        try KeyStates.mark(id: "search-console", active: true, in: url)
        #expect(KeyStates.load(from: url).isEmpty)
        // A file that cannot be read marks nothing, and is no reason to stop.
        try Data("not json".utf8).write(to: url)
        #expect(KeyStates.needingReauthorization(in: url).isEmpty)
    }

    /// The app writes keys.toml and only the service writes its own file, so a mark and an edit made at the
    /// same moment are both kept. Marks made at once from several threads are all kept too.
    @Test func anEditToKeysTomlAndAMarkAtTheSameTimeAreBothKept() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("both-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: folder) }
        let keys = folder.appendingPathComponent(KeyIndex.fileName)
        let states = folder.appendingPathComponent(KeyStates.fileName)
        var index = KeyIndex()
        try index.add(.init(id: "search-console", source: "g.json", provider: "google"))
        try PrivateFile.write(Data(index.toml.utf8), to: keys)

        // The app adds a key to keys.toml while the service marks keys, at the same moments.
        DispatchQueue.concurrentPerform(iterations: 2) { side in
            for turn in 0..<20 {
                if side == 0 {
                    guard var edited = try? KeyIndex.load(from: keys) else { continue }
                    try? edited.add(.init(id: "added-\(turn)", source: "s\(turn)"))
                    try? PrivateFile.write(Data(edited.toml.utf8), to: keys)
                } else {
                    try? KeyStates.mark(id: "key-\(turn)", active: false, in: states)
                }
            }
        }
        let after = try KeyIndex.load(from: keys)
        #expect((0..<20).allSatisfy { after.key("added-\($0)") != nil }, "no edit of the app was lost")
        #expect(after.key("search-console")?.more.state == nil, "the service never writes keys.toml")
        #expect(KeyStates.needingReauthorization(in: states) == Set((0..<20).map { "key-\($0)" }))

        // The service's own marks, from several threads at once, all stay.
        DispatchQueue.concurrentPerform(iterations: 20) { turn in
            try? KeyStates.mark(id: "more-\(turn)", active: false, in: states)
        }
        #expect(KeyStates.needingReauthorization(in: states).count == 40)
    }
}
