import CryptoKit
import Foundation
import KeyreeveVault
import Testing

/// An agent finding keys and proposing which to bring in: it reads names and places, never a value, and
/// its proposal only waits for the person.
struct AgentBringTests {
    final class World: @unchecked Sendable {
        var report = AgentBringTests.report
        var scans: [[String]] = []
        var entries: [AccessRequests.Entry] = []
        var saved: [String: Data] = [:]
        var logged: [(event: String, key: String, detail: String)] = []
        var answer = AgentBridge.Announcement.later
        var paused = false
    }

    /// What the engine prints, with values planted where no field an agent reads would carry them: a field
    /// keyreeve does not know, a section, a JSON path, a server, a reason and the projects it suggests.
    static let report = Data(
        #"""
        {"schema":1,"scope":"places","roots":["/p"],"suggested_projects":["/CANARYproject"],"files":3,"checked":false,
         "value":"CANARYtop","skipped":{"too_large":1,"unreadable":0,"too_deep":0,"examples":0,"stopped_early":false},
         "summary":{"works":0,"doubtful":2,"other":1,"dead":0,"duplicates":1},
         "candidates":[
          {"id":1,"group":"doubtful","class":"key","why":"starts like an OpenAI key","provider":"openai","evidence":"prefix",
           "guessed":[],"check":{"recipe":"openai","result":"works","reason":"CANARYreason"},"unchecked":"not checked",
           "server":"CANARYserver","value":"sk-CANARYvalue","duplicate":true,"from_project":true,"suggested":"decide",
           "origins":[
             {"path":"/p/app/.env","area":"project","bytes":40,"modified":1,
              "parts":[{"name":"OPENAI_API_KEY","section":"CANARYsection","line":4,"span":[15,40],"json":["CANARYjson"],"whole":false}]},
             {"path":"/h/.zshrc","area":"home","bytes":9,"modified":1,
              "parts":[{"name":"OPENAI_API_KEY","section":null,"line":2,"span":[1,2],"json":null,"whole":false}]}]},
          {"id":2,"group":"doubtful","class":"key","why":"a long random value","provider":null,"evidence":null,
           "guessed":["telegram"],"check":null,"unchecked":"only its name suggests a provider","server":null,
           "duplicate":false,"from_project":false,"suggested":"decide",
           "origins":[{"path":"/p/bot/.env","area":"project","bytes":20,"modified":1,
              "parts":[{"name":"CANARY value with spaces","section":null,"line":1,"span":[0,5],"json":null,"whole":false}]}]},
          {"id":3,"group":"other","class":"configuration","why":"an address","provider":null,"evidence":null,"guessed":[],
           "check":null,"unchecked":null,"server":null,"duplicate":false,"from_project":true,"suggested":"skip",
           "origins":[{"path":"/p/app/.env","area":"project","bytes":40,"modified":1,
              "parts":[{"name":"DATABASE_HOST","section":null,"line":5,"span":[1,2],"json":null,"whole":false}]}]}
         ]}
        """#.utf8)

    func bridge(_ world: World) -> AgentBridge {
        AgentBridge(
            policy: { AgentPolicy() }, names: { [] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            log: { event, key, detail, _ in world.logged.append((event, key, detail)) },
            offered: { ["openai", "telegram", "github"] },
            requests: { world.entries }, addRequest: { world.entries.append($0) }, announce: { _ in world.answer },
            paused: { world.paused },
            saveProposal: { world.saved[$0] = $1 },
            scanKeys: { arguments in
                world.scans.append(arguments)
                return world.report
            })
    }

    func call(_ bridge: AgentBridge, _ name: String, _ arguments: [String: Any]) throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, name, arguments)
    }

    @Test func findKeysListsKeysByNumberAndNeverAValue() throws {
        let world = World()
        let bridge = bridge(world)
        let answer = try call(bridge, "find_keys", ["where": "places", "projects": [NSTemporaryDirectory()]])
        #expect(!answer.error)
        #expect(!answer.text.contains("CANARY"), "\(answer.text)")
        let object = try #require(try JSONSerialization.jsonObject(with: Data(answer.text.utf8)) as? [String: Any])
        #expect(object["keys"] == nil, "a summary lists projects, not keys")
        let projects = try #require(object["projects"] as? [[Any]])
        #expect(projects.map { $0[0] as? String } == ["/h", "/p/app", "/p/bot"])
        let counts = try #require(object["counts"] as? [String: Int])
        #expect(counts["keys"] == 2 && counts["other"] == 1 && counts["not_compared"] == 2 && counts["projects"] == 3)
        #expect((object["known_providers"] as? [String])?.contains("telegram") == true)
        let app = try call(bridge, "find_keys", ["project": "/p/app"])
        #expect(!app.text.contains("CANARY"), "\(app.text)")
        let appObject = try #require(try JSONSerialization.jsonObject(with: Data(app.text.utf8)) as? [String: Any])
        let keys = try #require(appObject["keys"] as? [[String: Any]])
        #expect(keys.map { $0["n"] as? Int } == [1], "configuration is counted, not listed")
        #expect(keys[0]["names"] as? String == "OPENAI_API_KEY")
        #expect(keys[0]["at"] as? [String] == [".env:4"] && keys[0]["elsewhere"] as? Int == 1)
        #expect(keys[0]["provider"] as? String == "openai" && keys[0]["by"] as? String == "prefix")
        let bot = try call(bridge, "find_keys", ["project": "/p/bot"])
        let botKeys = try #require((try JSONSerialization.jsonObject(with: Data(bot.text.utf8)) as? [String: Any])?["keys"] as? [[String: Any]])
        #expect(botKeys[0]["guess"] as? [String] == ["telegram"] && botKeys[0]["provider"] == nil)
        #expect(botKeys[0]["names"] as? String == "line 1", "a name that does not read as one is shown as its line")
        // Always a dry run: nothing is sent to a provider from an agent's call.
        let arguments = try #require(world.scans.first)
        #expect(arguments.first == "bring" && arguments.contains("--dry-run") && !arguments.contains("--check"))
        #expect(arguments.contains("--places") && arguments.contains("--projects"))
        #expect(world.logged.map(\.event) == ["scanned"])
        #expect(world.entries.isEmpty && world.saved.isEmpty)
    }

    @Test func pagesReuseTheSameSearch() throws {
        let world = World()
        let bridge = bridge(world)
        let first = try call(bridge, "find_keys", ["limit": 1])
        #expect(first.text.contains("\"next_offset\":1"))
        let second = try call(bridge, "find_keys", ["offset": 1, "limit": 1])
        #expect(second.text.contains("[\"/p/app\",") && !second.text.contains("[\"/h\","))
        #expect(world.scans.count == 1, "a later page keeps the numbers of the first")
    }

    @Test func findKeysTakesFullPathsToFoldersOnly() throws {
        let world = World()
        let bridge = bridge(world)
        let temp = NSTemporaryDirectory()
        #expect(try call(bridge, "find_keys", ["where": "folders", "folders": ["relative/path"]]).error)
        #expect(try call(bridge, "find_keys", ["where": "folders", "folders": ["/no/such/folder/here"]]).error)
        #expect(try call(bridge, "find_keys", ["where": "folders"]).error)
        #expect(try call(bridge, "find_keys", ["where": "folders", "folders": [temp], "projects": [temp]]).error)
        #expect(try call(bridge, "find_keys", ["where": "everywhere", "folders": [temp]]).error)
        #expect(try call(bridge, "find_keys", ["where": "places", "folders": [temp]]).error)
        #expect(try call(bridge, "find_keys", ["where": "somewhere"]).error)
        #expect(world.scans.isEmpty)
        #expect(!(try call(bridge, "find_keys", ["where": "folders", "folders": [temp, "~"]]).error))
        let standard = URL(fileURLWithPath: temp).standardizedFileURL.path
        #expect(world.scans.last == ["bring", "--everywhere", "--under", standard, "--under", NSHomeDirectory(), "--dry-run", "--json"])
        #expect(!(try call(bridge, "find_keys", ["where": "everywhere"]).error))
        #expect(world.scans.last == ["bring", "--everywhere", "--dry-run", "--json"])
    }

    @Test func aSearchThatRanOutOfTimeSaysWhereToGoOn() throws {
        let world = World()
        var report = try #require(try JSONSerialization.jsonObject(with: world.report) as? [String: Any])
        report["unfinished"] = ["/h/code", "/h/Documents"]
        world.report = try JSONSerialization.data(withJSONObject: report)
        let answer = try call(bridge(world), "find_keys", ["where": "everywhere"])
        let object = try #require(try JSONSerialization.jsonObject(with: Data(answer.text.utf8)) as? [String: Any])
        #expect(object["unfinished"] as? [String] == ["/h/code", "/h/Documents"])
        #expect((object["budget"] as? String)?.contains("where = folders") == true)
        #expect(object["where"] as? String == "everywhere")
        #expect(world.logged.last?.detail.contains("2 folders not finished") == true)
        #expect(!answer.text.contains("CANARY"))
    }

    @Test func aPausedKeyreeveFindsNothing() throws {
        let world = World()
        world.paused = true
        #expect(try call(bridge(world), "find_keys", [:]).error)
        #expect(world.scans.isEmpty)
    }

    @Test func proposingNeedsASearchAndRefusesUnknownCandidatesAndProvidersWhole() throws {
        let world = World()
        let bridge = bridge(world)
        #expect(try call(bridge, "propose_bring", ["reason": "r", "seal": [["candidates": [1]]]]).text.contains("find_keys first"))
        _ = try call(bridge, "find_keys", [:])
        let wrong: [[String: Any]] = [
            ["reason": "r", "seal": [["candidates": [1]], ["candidates": [99]]]],
            ["reason": "r", "seal": [["candidates": [1], "provider": "nosuchprovider"]]],
            ["reason": "r", "seal": [["candidates": [3]]]],
            ["reason": "r", "seal": [["candidates": [1]]], "skip": [["candidates": [1], "reason": "twice"]]],
            ["reason": "r", "seal": [["candidates": [1, 2], "id": "one-name"]]],
            ["reason": "r", "seal": [["candidates": [1], "id": "Not Valid"]]],
            ["reason": "r", "skip": [["candidates": [2]]]],
            ["reason": "r"],
            ["seal": [["candidates": [1]]]],
        ]
        for arguments in wrong {
            let answer = try call(bridge, "propose_bring", arguments)
            #expect(answer.error, "\(arguments)")
        }
        #expect(world.entries.isEmpty && world.saved.isEmpty, "nothing is kept from a refused proposal")
    }

    @Test func aProposalWaitsForThePersonAndSealsNothing() throws {
        let world = World()
        let bridge = bridge(world)
        _ = try call(bridge, "find_keys", [:])
        let answer = try call(bridge, "propose_bring", [
            "reason": "bring in my project keys",
            "seal": [["candidates": [1], "id": "openai-app", "description": "The app's OpenAI key", "tags": ["App", "bad tag"]]],
            "skip": [["candidates": [2], "reason": "an old bot"]],
        ])
        #expect(!answer.error)
        #expect(answer.text.contains("Pending in Keyreeve: 1 keys to seal and 1 to skip"))
        #expect(answer.text.contains("The person decides") && answer.text.contains("list_keys will not show them"))
        let asked = try #require(world.entries.first)
        #expect(asked.kind == AgentBringing.kind && asked.event == .asked && asked.agent == "claude")
        let proposal = try #require(world.saved[asked.id].flatMap(AgentBringing.decode))
        #expect(proposal.scope == AgentBringing.Scope(place: .places))
        #expect(proposal.items.map(\.candidate) == [1, 2])
        #expect(proposal.items[0].seal && proposal.items[0].id == "openai-app" && proposal.items[0].tags == ["app"])
        #expect(proposal.items[0].origins.count == 2, "a key found twice is found again by either place")
        #expect(!proposal.items[1].seal && proposal.items[1].reason == "an old bot")
        #expect(!String(decoding: world.saved[asked.id]!, as: UTF8.self).contains("CANARY"))
        #expect(world.logged.last?.event == "requested")
        // One at a time, and the next one says how the last went.
        #expect(try call(bridge, "propose_bring", ["reason": "r", "seal": [["candidates": [2]]]]).text.hasPrefix("Still waiting"))
        world.entries.append(AccessRequests.Entry(
            id: asked.id, at: Date(), event: .allowed, agent: "claude", provider: "keyreeve", kind: AgentBringing.kind,
            result: "the person sealed 1 keys"))
        let next = try call(bridge, "propose_bring", ["reason": "r", "seal": [["candidates": [2]]]])
        #expect(next.text.hasPrefix("Your last proposal: the person sealed 1 keys."))
    }

    @Test func aProviderAgainstTheKeysOwnEvidenceIsNotedNotSaved() throws {
        let world = World()
        let bridge = bridge(world)
        _ = try call(bridge, "find_keys", [:])
        let answer = try call(bridge, "propose_bring", [
            "reason": "r", "seal": [["candidates": [1], "provider": "github"], ["candidates": [2], "provider": "telegram"]],
        ])
        #expect(answer.text.contains("1: its prefix names openai, so it is saved as openai"))
        #expect(answer.text.contains("2: telegram is shown to the person as your suggestion, and not saved with the key"))
    }

    @Test func aDeniedProposalIsAnsweredAndKeptAsDeclined() throws {
        let world = World()
        world.answer = .deny
        let bridge = bridge(world)
        _ = try call(bridge, "find_keys", [:])
        #expect(try call(bridge, "propose_bring", ["reason": "r", "seal": [["candidates": [1]]]]).error)
        #expect(world.entries.map(\.event) == [.asked, .declined])
    }

    /// The real engine, over a folder of planted keys, with HOME and KEYREEVE_HOME in a temporary folder so the
    /// person's own are never read. Runs when `cargo build` made the engine.
    @Test(.enabled(if: AgentBringTests.engine != nil)) func theRealEngineGivesNoValueToAnAgent() throws {
        let engine = try #require(Self.engine)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("agent-bring-\(UUID().uuidString)")
        let folder = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try "OPENAI_API_KEY=sk-proj-CANARYopenai000000000000\nGITHUB_TOKEN=ghp_CANARYgithub0000000000000000000000\nDATABASE_HOST=db.example.com\n"
            .write(to: folder.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        let environment = ["HOME": root.path, "KEYREEVE_HOME": root.appendingPathComponent("kr").path, "PATH": "/usr/bin:/bin"]
        let world = World()
        var bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { [] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            describe: { ["openai-app": KeyIndex.Key(id: "openai-app", source: "added/openai")] },
            offered: { [] }, requests: { world.entries }, addRequest: { world.entries.append($0) },
            saveProposal: { world.saved[$0] = $1 },
            scanKeys: { try AgentBringing.runEngine(binary: engine, arguments: $0, environment: environment) })
        // The vault holds the OpenAI key, as its keyed digest says; the GitHub token is new.
        let openai = "sk-proj-CANARYopenai000000000000"
        let digestKey = DigestKey(key: SymmetricKey(size: .bits256))
        var digests = ValueDigests()
        digests.learn(name: "added/openai", revision: "r1", value: Data(openai.utf8), key: digestKey)
        bridge.sealedMatcher = {
            .success(SealedMatcher(digests: digests, key: digestKey, revisions: ["added/openai": "r1"], keys: [("openai-app", "added/openai", nil)]))
        }
        var handed: URL?
        bridge.scanKeysHashed = { arguments in
            try EngineHashes.around { extra in
                handed = URL(fileURLWithPath: extra[1])
                return try AgentBringing.runEngine(binary: engine, arguments: arguments + extra, environment: environment)
            }
        }
        let answer = try call(bridge, "find_keys", ["where": "folders", "folders": [folder.path]])
        #expect(!answer.error, "\(answer.text)")
        let plain = SHA256.hash(data: Data(openai.utf8)).map { String(format: "%02x", $0) }.joined()
        let handedFile = try #require(handed)
        #expect(!FileManager.default.fileExists(atPath: handedFile.path), "the hashes file is removed once read")
        #expect(!FileManager.default.fileExists(atPath: handedFile.deletingLastPathComponent().path))
        let listed = try call(bridge, "find_keys", ["project": folder.path])
        for text in [answer.text, listed.text] {
            #expect(!text.contains("CANARY"), "\(text)")
            #expect(!text.contains(plain) && !text.contains(digestKey.digest(ofValue: openai)))
        }
        let counts = try #require((try JSONSerialization.jsonObject(with: Data(answer.text.utf8)) as? [String: Any])?["counts"] as? [String: Int])
        #expect(counts["already_sealed"] == 1 && counts["new"] == 1, "\(answer.text)")
        #expect(listed.text.contains("OPENAI_API_KEY") && listed.text.contains("GITHUB_TOKEN"))
        #expect(listed.text.contains("\"sealed_as\":[\"openai-app\"]"), "\(listed.text)")
        #expect(!listed.text.contains("DATABASE_HOST"), "configuration is only counted")
        let proposed = try call(bridge, "propose_bring", ["reason": "r", "seal": [["candidates": [1, 2]]]])
        #expect(!proposed.error, "\(proposed.text)")
        let saved = try #require(world.saved.values.first)
        #expect(!String(decoding: saved, as: UTF8.self).contains("CANARY"))
        #expect(!String(decoding: saved, as: UTF8.self).contains(plain))
    }

    /// The engine `cargo build` leaves in the repository's target folder, if there is one.
    static let engine: URL? = {
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return ["target/debug/keyreeve", "target/release/keyreeve"].map { repo.appendingPathComponent($0) }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }()
}
