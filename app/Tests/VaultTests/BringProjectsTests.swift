import CryptoKit
import Foundation
import KeyreeveVault
import Testing

/// Bring in by project: whether the vault already holds a key found, told by keyed digest with no value; the folders
/// never looked in; and projects as the person keeps them. No value, and no plain hash of one, reaches an agent, a
/// report, a log, projects.toml or a file left behind.
struct BringProjectsTests {
    static let openai = "sk-proj-CANARYopenai000000000000"
    static let github = "ghp_CANARYgithub0000000000000000000000"
    static let clientID = "CANARY-id.apps.googleusercontent.com"
    static let clientSecret = "CANARYclientSecret000000"
    static let unoffered = "secret-vault-name-zz"

    static func sha(_ text: String) -> String { SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined() }

    /// A unique folder for each test, removed after.
    static func temp(_ name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("bring-projects-\(name)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// The vault as digests know it: an OpenAI key sealed alone, a dotenv with a GitHub token in a field, and a Google
    /// client sealed as two fields. Its revisions now, and one earlier value of the OpenAI key.
    static func vault(key: DigestKey) -> (digests: ValueDigests, revisions: [String: String], keys: [(id: String, source: String, field: String?)]) {
        var digests = ValueDigests()
        digests.learn(name: "added/openai", revision: "r2", value: Data(openai.utf8), key: key)
        digests.learn(name: "added/openai", revision: "r1", value: Data("sk-proj-CANARYolder00000000000000".utf8), key: key)
        digests.learn(name: "app.env", revision: "e1", value: Data("SITE=x\nGITHUB_TOKEN=\(github)\n".utf8), key: key)
        digests.learn(
            name: "added/google", revision: "g1",
            value: Data("GOOGLE_CLIENT_ID=\(clientID)\nGOOGLE_CLIENT_SECRET=\(clientSecret)\n".utf8), key: key)
        let revisions = ["added/openai": "r2", "app.env": "e1", "added/google": "g1"]
        let keys: [(id: String, source: String, field: String?)] = [
            ("openai-app", "added/openai", nil), (unoffered, "app.env", "GITHUB_TOKEN"),
            ("google-client", "added/google", "GOOGLE_CLIENT_ID+GOOGLE_CLIENT_SECRET"),
        ]
        return (digests, revisions, keys)
    }

    static let digestKey = DigestKey(key: SymmetricKey(size: .bits256))

    static func matcher(complete: Bool = true) -> SealedMatcher {
        var made = vault(key: digestKey)
        if !complete { made.revisions["added/never-opened"] = "n1" }
        return SealedMatcher(digests: made.digests, key: digestKey, revisions: made.revisions, keys: made.keys)
    }

    @Test func wholeValuesAndFieldsAreFoundByKeyedDigest() {
        let matcher = Self.matcher()
        #expect(matcher.match([Self.sha(Self.openai)]) == SealedMatcher.Hit(ids: ["openai-app"], earlier: false))
        #expect(matcher.match([Self.sha(Self.github)]) == SealedMatcher.Hit(ids: [Self.unoffered], earlier: false), "a field of a dotenv")
        #expect(matcher.match([Self.sha(Self.clientID), Self.sha(Self.clientSecret)])?.ids == ["google-client"], "two parts, two fields")
        #expect(matcher.match([Self.sha(Self.clientID), Self.sha(Self.openai)]) == nil, "parts of two different keys are not one key")
        #expect(matcher.match([Self.sha("sk-proj-CANARYolder00000000000000")]) == SealedMatcher.Hit(ids: ["openai-app"], earlier: true))
        #expect(matcher.match([Self.sha("never-seen")]) == nil)
        #expect(matcher.match([]) == nil)
        #expect(matcher.coverage == SealedMatcher.Coverage(known: 3, total: 3))
        // Another Mac's key makes other digests, so nothing matches.
        let other = SealedMatcher(
            digests: Self.vault(key: Self.digestKey).digests, key: DigestKey(key: SymmetricKey(size: .bits256)),
            revisions: Self.vault(key: Self.digestKey).revisions, keys: [])
        #expect(other.match([Self.sha(Self.openai)]) == nil)
    }

    // MARK: The engine's report, made up

    /// A report as the engine prints it, with values planted where no field an agent reads would carry them.
    static func report(projects: Int = 2) -> Data {
        var candidates: [String] = []
        var paths: [String] = []
        let home = NSHomeDirectory()
        var number = 0
        func add(_ project: String, _ file: String, _ name: String, kind: String = "key", provider: String? = nil) {
            number += 1
            let provider = provider.map { "\"\($0)\"" } ?? "null"
            candidates.append(
                #"{"id":\#(number),"group":"doubtful","class":"\#(kind)","why":"w","provider":\#(provider),"evidence":"prefix","guessed":[],"#
                    + #""check":null,"unchecked":"not checked","server":"CANARYserver","value":"CANARYvalue","duplicate":false,"from_project":true,"suggested":"decide","#
                    + #""origins":[{"path":"\#(project)/\#(file)","area":"project","bytes":40,"modified":1,"project":"\#(project)","#
                    + #""parts":[{"name":"\#(name)","section":"CANARYsection","line":3,"span":[1,2],"json":null,"whole":false}]}]}"#)
        }
        for index in 0..<projects {
            let project = "\(home)/Desktop/proyectos/01-activos/project-\(String(format: "%03d", index))/app"
            paths.append(project)
            add(project, ".env", "OPENAI_API_KEY", provider: "openai")
            add(project, "config/.env.local", "GITHUB_TOKEN", provider: "github")
        }
        let shared = "\(home)/code/google"
        paths.append(shared)
        add(shared, ".env", "GOOGLE_CLIENT_ID+GOOGLE_CLIENT_SECRET")
        candidates.append(
            #"{"id":\#(number + 1),"group":"other","class":"configuration","why":"w","provider":null,"evidence":null,"guessed":[],"check":null,"#
                + #""unchecked":null,"server":null,"duplicate":false,"from_project":true,"suggested":"skip","origins":[{"path":"\#(shared)/.env","area":"project","#
                + #""bytes":1,"modified":1,"project":"\#(shared)","parts":[{"name":"SITE","section":null,"line":1,"span":[1,2],"json":null,"whole":false}]}]}"#)
        let projectsJSON = paths.map { #"{"path":"\#($0)","name":"\#(URL(fileURLWithPath: $0).lastPathComponent)","marker":".env"}"# }
        let text = #"{"schema":1,"scope":"everywhere","roots":["\#(home)"],"suggested_projects":[],"files":9,"checked":false,"#
            + #""skipped":{"too_large":0,"unreadable":0,"too_deep":0,"examples":1,"stopped_early":false,"rules":{"tests":40,"~/wapentake-bench-swe":1}},"#
            + #""summary":{"works":0,"doubtful":3,"other":1,"dead":0,"duplicates":0},"candidates":[\#(candidates.joined(separator: ","))],"#
            + #""projects":[\#(projectsJSON.joined(separator: ","))],"unfinished":[]}"#
        return Data(text.utf8)
    }

    /// The hashes the engine hands over for that report: the first project's OpenAI key and GitHub token are in the
    /// vault, the second project's are not, and the Google client is.
    static func hashes(projects: Int = 2) -> [Int: [String]] {
        var out: [Int: [String]] = [:]
        for index in 0..<projects {
            out[index * 2 + 1] = [sha(index == 0 ? openai : "sk-proj-CANARYnew\(index)000000000000")]
            out[index * 2 + 2] = [sha(index == 0 ? github : "ghp_CANARYnew\(index)00000000000000000000")]
        }
        out[projects * 2 + 1] = [sha(clientID), sha(clientSecret)]
        return out
    }

    final class World: @unchecked Sendable {
        var entries: [AccessRequests.Entry] = []
        var saved: [String: Data] = [:]
        var logged: [String] = []
        var matcher: Result<SealedMatcher, SealedMatcher.UnavailableError> = .success(BringProjectsTests.matcher())
        var report = BringProjectsTests.report()
        var hashes = BringProjectsTests.hashes()
        var projects = Projects()
    }

    func bridge(_ world: World) -> AgentBridge {
        var bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { [] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            log: { event, key, detail, reason in world.logged.append([event, key, detail, reason ?? ""].joined(separator: " ")) },
            describe: { ["openai-app": KeyIndex.Key(id: "openai-app", source: "added/openai")] },
            offered: { ["openai", "github"] },
            requests: { world.entries }, addRequest: { world.entries.append($0) },
            saveProposal: { world.saved[$0] = $1 })
        bridge.scanKeysHashed = { _ in (world.report, world.hashes) }
        bridge.sealedMatcher = { world.matcher }
        bridge.projects = { world.projects }
        return bridge
    }

    func call(_ bridge: AgentBridge, _ name: String, _ arguments: [String: Any]) throws -> (text: String, error: Bool) {
        try AgentTests().call(bridge, name, arguments)
    }

    func object(_ text: String) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    /// Nothing an agent reads holds a value, a plain hash of one, a keyed digest, or a key not offered to it.
    func expectClean(_ text: String, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(!text.contains("CANARY"), "a value reached the answer", sourceLocation: sourceLocation)
        for hexes in Self.hashes().values {
            for hex in hexes {
                #expect(!text.contains(hex), "a plain hash reached the answer", sourceLocation: sourceLocation)
                #expect(!text.contains(Self.digestKey.digest(ofHex: hex) ?? "-"), "a digest reached the answer", sourceLocation: sourceLocation)
            }
        }
        #expect(!text.contains(Self.unoffered), "an unoffered key's name reached the answer", sourceLocation: sourceLocation)
    }

    @Test func theSummaryIsByProjectAndSaysWhatTheVaultHolds() throws {
        let world = World()
        let bridge = bridge(world)
        let answer = try call(bridge, "find_keys", ["where": "everywhere"])
        #expect(!answer.error, "\(answer.text)")
        expectClean(answer.text)
        let summary = try object(answer.text)
        #expect(summary["keys"] == nil, "no key is listed in a summary")
        #expect((summary["sealed_check"] as? String)?.hasPrefix("compared") == true)
        let counts = try #require(summary["counts"] as? [String: Int])
        #expect(counts["keys"] == 5 && counts["already_sealed"] == 3 && counts["new"] == 2 && counts["projects"] == 3)
        #expect(counts["other"] == 1)
        #expect(summary["under"] as? String == "~", "the folder every project is under")
        #expect(summary["columns"] as? [String] == ["path", "keys", "logins", "duplicates", "sealed", "new", "providers"])
        let projects = try #require(summary["projects"] as? [[Any]])
        #expect(projects.count == 3)
        let first = try #require(projects.first { ($0[0] as? String) == "Desktop/proyectos/01-activos/project-000/app" })
        #expect(first[1] as? Int == 2 && first[4] as? Int == 2 && first[5] as? Int == 0)
        #expect(first[6] as? String == "openai github")
        let second = try #require(projects.first { ($0[0] as? String)?.hasSuffix("project-001/app") == true })
        #expect(second[5] as? Int == 2 && second[4] as? Int == 0)
        let google = try #require(projects.first { ($0[0] as? String) == "code/google" })
        #expect(google[4] as? Int == 1)
        #expect((summary["left_out"] as? [String: Int])?["tests"] == 40)
        #expect((summary["left_out"] as? [String: Int])?["~/wapentake-bench-swe"] == 1)
    }

    @Test func aProjectListsItsKeysAndOnlyOfferedIdentifiers() throws {
        let world = World()
        let bridge = bridge(world)
        #expect(try call(bridge, "find_keys", ["project": "~/x"]).text.contains("call find_keys first"))
        _ = try call(bridge, "find_keys", ["where": "everywhere"])
        let first = try call(bridge, "find_keys", ["project": "~/Desktop/proyectos/01-activos/project-000/app"])
        #expect(!first.error, "\(first.text)")
        expectClean(first.text)
        let rows = try #require(try object(first.text)["keys"] as? [[String: Any]])
        #expect(rows.map { $0["n"] as? Int } == [1, 2])
        #expect(rows[0]["names"] as? String == "OPENAI_API_KEY" && rows[0]["at"] as? [String] == [".env:3"])
        #expect(rows[0]["sealed_as"] as? [String] == ["openai-app"], "an offered key is named")
        #expect(rows[1]["sealed"] as? Bool == true && rows[1]["sealed_as"] == nil, "an unoffered one is only said to be sealed")
        #expect(rows[1]["at"] as? [String] == ["config/.env.local:3"])
        // A path as the summary gave it, and the second project's keys are new.
        let second = try call(bridge, "find_keys", ["project": "/" + NSHomeDirectory().dropFirst() + "/Desktop/proyectos/01-activos/project-001/app"])
        let newRows = try #require(try object(second.text)["keys"] as? [[String: Any]])
        #expect(newRows.allSatisfy { $0["new"] as? Bool == true })
        #expect(try call(bridge, "find_keys", ["project": "~/nowhere"]).error)
        // Numbers from a project's list go straight into a proposal, with folders to suggest leaving out.
        let proposed = try call(bridge, "propose_bring", [
            "reason": "r", "seal": [["candidates": [3, 4, 1]]],
            "ignore": ["~/wapentake-bench-swe", "fixtures-old"],
        ])
        #expect(!proposed.error, "\(proposed.text)")
        #expect(proposed.text.contains("1 is already in the vault"))
        expectClean(proposed.text)
        let saved = try #require(world.saved.values.first.flatMap(AgentBringing.decode))
        #expect(saved.items.map(\.candidate) == [3, 4, 1])
        #expect(saved.ignore == ["~/wapentake-bench-swe", "fixtures-old"])
        #expect(try call(bridge, "propose_bring", ["reason": "r", "ignore": ["relative/path"]]).error)
        for line in world.logged { expectClean(line) }
        for data in world.saved.values { expectClean(String(decoding: data, as: UTF8.self)) }
    }

    @Test func withoutLearnedDigestsItSaysSoAndNeverSaysNew() throws {
        for reason in [SealedMatcher.Unavailable.nothingLearned, .noKey] {
            let world = World()
            world.matcher = .failure(.init(reason))
            let bridge = bridge(world)
            let answer = try call(bridge, "find_keys", ["where": "everywhere"])
            expectClean(answer.text)
            let summary = try object(answer.text)
            #expect((summary["sealed_check"] as? String)?.contains("Learn what the vault holds first") == true)
            let counts = try #require(summary["counts"] as? [String: Int])
            #expect(counts["not_compared"] == 5 && counts["new"] == nil && counts["already_sealed"] == nil)
            let rows = try #require(summary["projects"] as? [[Any]])
            #expect(rows.allSatisfy { $0[4] is NSNull && $0[5] is NSNull }, "neither sealed nor new is claimed")
            let project = try call(bridge, "find_keys", ["project": "~/Desktop/proyectos/01-activos/project-001/app"])
            #expect(!project.text.contains("\"new\""), "\(project.text)")
            #expect(!answer.text.contains("\"new\":"), "no count of new keys")
        }
        // Part of the vault known: what matched is said, and nothing is called new.
        let world = World()
        world.matcher = .success(Self.matcher(complete: false))
        let answer = try call(bridge(world), "find_keys", ["where": "everywhere"])
        let summary = try object(answer.text)
        #expect((summary["sealed_check"] as? String)?.hasPrefix("partly compared") == true)
        let counts = try #require(summary["counts"] as? [String: Int])
        #expect(counts["already_sealed"] == 3 && counts["not_matched"] == 2 && counts["new"] == nil)
        // An engine that handed no hashes over compares nothing.
        let none = World()
        none.hashes = [:]
        let plain = try object(try call(bridge(none), "find_keys", ["where": "everywhere"]).text)
        #expect((plain["counts"] as? [String: Int])?["not_compared"] == 5)
    }

    @Test func aSummaryOfAHundredProjectsStaysSmall() throws {
        let world = World()
        world.report = Self.report(projects: 100)
        world.hashes = Self.hashes(projects: 100)
        let answer = try call(bridge(world), "find_keys", ["where": "everywhere"])
        let summary = try object(answer.text)
        #expect((summary["projects"] as? [[Any]])?.count == 100)
        #expect(summary["next_offset"] as? Int == 100, "the hundred and first is on the next page")
        #expect(answer.text.utf8.count < 10_000, "\(answer.text.utf8.count) bytes")
        // The 101st project is on the next page of the same search.
        let next = try object(try call(bridge(world), "find_keys", ["where": "everywhere", "limit": 50]).text)
        #expect(next["next_offset"] as? Int == 50)
    }

    @Test func listProjectsNamesOnlyOfferedKeys() throws {
        let world = World()
        world.projects = Projects(projects: [
            Projects.Project(
                name: "app", folder: NSHomeDirectory() + "/code/app", keys: ["openai-app", Self.unoffered, "another-hidden"],
                places: [NSHomeDirectory() + "/code/app/.env"], set: "app")
        ])
        let answer = try call(bridge(world), "list_projects", [:])
        expectClean(answer.text)
        #expect(!answer.text.contains("another-hidden"))
        let row = try #require((try object(answer.text)["projects"] as? [[String: Any]])?.first)
        #expect(row["keys"] as? [String] == ["openai-app"] && row["other_keys"] as? Int == 2)
        #expect(row["folder"] as? String == "~/code/app" && row["places"] as? Int == 1 && row["set"] as? String == "app")
    }

    // MARK: Files

    @Test func projectsTomlHoldsIdentifiersAndPathsOnly() throws {
        let folder = try Self.temp("projects-toml")
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent(Projects.fileName)
        try Projects.update(at: file) { book in
            try book.merge(Projects.Project(name: "shop", folder: "/code/shop", keys: ["openai-app"], places: ["/code/shop/.env"]))
            try book.merge(Projects.Project(name: "other-name", folder: "/code/shop", keys: ["openai-app", "github-ci"], places: ["/code/shop/web/.env"]))
            try book.merge(Projects.Project(name: "bot", folder: "/code/bot", keys: [], places: []))
        }
        let read = try Projects.loadStrict(from: file)
        #expect(read.projects.map(\.name) == ["bot", "shop"], "a project keeps its name when keys are added")
        #expect(read.project(at: "/code/shop")?.keys == ["openai-app", "github-ci"])
        #expect(read.project(at: "/code/shop")?.places == ["/code/shop/.env", "/code/shop/web/.env"])
        let text = try String(contentsOf: file, encoding: .utf8)
        #expect(!text.contains("CANARY") && !text.contains(Self.sha(Self.openai)))
        #expect((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(throws: VaultError.self) { try Projects.parse("[[project]]\nname = \"x\"\nfolder = \"relative\"\n") }
        #expect(throws: VaultError.self) { try Projects.parse("[[project]]\nname = \"x\"\nfolder = \"/a\"\nvalue = \"y\"\n") }
        var book = read
        #expect(throws: VaultError.self) { try book.merge(Projects.Project(name: "Bad Name", folder: "/x")) }
    }

    @Test func theIgnoreListReadsWhatTheEngineWrites() throws {
        let written = "# Folders Bring in never looks in.\nignore = [\n  \"~/Desktop/proyectos/99-archivo\", # old\n  \"/tmp/a \\\"b\\\"\",\n  \"scratch\",\n]\n"
        #expect(try BringIgnore.parse(written) == ["~/Desktop/proyectos/99-archivo", "/tmp/a \"b\"", "scratch"])
        #expect(try BringIgnore.parse("ignore = [\"~/x\"]\n") == ["~/x"])
        #expect(try BringIgnore.parse("") == [])
        #expect(throws: VaultError.self) { try BringIgnore.parse("other = 1\n") }
        #expect(throws: VaultError.self) { try BringIgnore.parse("ignore = [oops]\n") }
        #expect(try BringIgnore.parse(BringIgnore.render(["~/a b", "c\"d"])) == ["~/a b", "c\"d"])
        let folder = try Self.temp("ignore")
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent(BringIgnore.fileName)
        #expect(try BringIgnore.update(at: file) { $0 += ["~/a", "relative/path", "~/a", "b"] } == ["~/a", "b"])
        #expect(try BringIgnore.update(at: file) { $0.removeAll { $0 == "~/a" } } == ["b"])
        #expect(BringIgnore.rule(for: NSHomeDirectory() + "/x/y") == "~/x/y")
    }

    @Test func learningRecordsEveryValueAndEveryField() throws {
        let folder = try Self.temp("learn")
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent(ValueDigests.fileName)
        let values = ["added/openai": Self.openai, "app.env": "SITE=x\nGITHUB_TOKEN=\(Self.github)\n"]
        var opened: [String] = []
        let counts = try ValueDigests.learnAll(
            revisions: ["added/openai": "r2", "app.env": "e1", "broken": "b1", "x#pending": "p1"],
            open: { name in
                opened.append(name)
                guard let value = values[name] else { throw VaultError("cannot open") }
                return Data(value.utf8)
            },
            key: Self.digestKey, file: file, now: Date(timeIntervalSince1970: 1_000))
        #expect(counts.learned == 2 && counts.failed == 1)
        #expect(!opened.contains("x#pending"), "a value waiting for the person is not learned")
        let read = ValueDigests.load(from: file)
        #expect(read.learned == Date(timeIntervalSince1970: 1_000))
        #expect(read.knows(name: "added/openai", revision: "r2") && read.knows(name: "app.env", revision: "e1"))
        #expect(read.entries["app.env"]?["e1"]?["GITHUB_TOKEN"] == Self.digestKey.digest(ofValue: Self.github))
        let text = try String(contentsOf: file, encoding: .utf8)
        #expect(!text.contains("CANARY") && !text.contains(Self.sha(Self.openai)) && !text.contains(Self.sha(Self.github)))
    }

    @Test func theHashesFileIsGoneOnceRead() throws {
        var seen: URL?
        let (report, hashes) = try EngineHashes.around { extra -> Data in
            #expect(extra.first == "--hashes-out")
            let file = URL(fileURLWithPath: extra[1])
            seen = file
            let folder = file.deletingLastPathComponent()
            #expect((try FileManager.default.attributesOfItem(atPath: folder.path)[.posixPermissions] as? NSNumber)?.intValue == 0o700)
            #expect(!FileManager.default.fileExists(atPath: file.path), "the engine makes it, and refuses one that is there")
            try Data(#"{"schema":1,"keys":{"1":["\#(Self.sha(Self.openai))"],"2":["short"]}}"#.utf8).write(to: file)
            return Data("{}".utf8)
        }
        #expect(report == Data("{}".utf8))
        #expect(hashes == [1: [Self.sha(Self.openai)]], "a malformed hash is dropped")
        let file = try #require(seen)
        #expect(!FileManager.default.fileExists(atPath: file.path))
        #expect(!FileManager.default.fileExists(atPath: file.deletingLastPathComponent().path))
        // Removed when the engine fails too.
        var failed: URL?
        #expect(throws: VaultError.self) {
            _ = try EngineHashes.around { extra -> Data in
                failed = URL(fileURLWithPath: extra[1])
                try Data("{}".utf8).write(to: failed!)
                throw VaultError("the engine stopped")
            }
        }
        #expect(!FileManager.default.fileExists(atPath: try #require(failed).deletingLastPathComponent().path))
    }
}
