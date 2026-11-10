import Foundation
import Testing

@testable import KeyreeveCatalog

/// What the app reads of `keyreeve bring`, and how it reads a value back from where the report says it is.
struct BringTests {
    func folder() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("bring-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    /// The size and time the report would hold for this file now.
    func origin(_ url: URL, _ parts: [BringCandidate.Part], area: String = "folder") throws -> BringCandidate.Origin {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attributes[.size] as! NSNumber).uint64Value
        let modified = UInt64((attributes[.modificationDate] as! Date).timeIntervalSince1970.rounded(.down))
        return .init(path: url.path, area: area, bytes: size, modified: modified, parts: parts)
    }

    func span(_ text: String, _ value: String, name: String?) -> BringCandidate.Part {
        let range = text.range(of: value)!
        let from = text.utf8.distance(from: text.startIndex, to: range.lowerBound)
        return .init(name: name, section: nil, line: 1, span: [from, from + value.utf8.count], json: nil, whole: false)
    }

    @Test func readsTheReportTheCommandWrites() throws {
        let json = """
        {"schema":1,"scope":"places","roots":["/h/code"],"suggested_projects":["/h/Desktop"],"files":3,"checked":true,
         "skipped":{"too_large":0,"unreadable":0,"too_deep":1,"examples":1,"stopped_early":false},
         "summary":{"works":1,"doubtful":0,"other":0,"dead":0,"duplicates":1},
         "candidates":[{"id":1,"group":"works","class":"key","why":"starts as a provider's keys do","provider":"openai",
           "recipes":["openai"],"check":{"recipe":"openai","result":"works","reason":null,"tried":["openai"]},"server":null,
           "origins":[{"path":"/h/.zshrc","area":"home","bytes":10,"modified":5,"parts":[{"name":"OPENAI_API_KEY","section":null,"line":3,"span":[2,8],"json":null,"whole":false}]},
                      {"path":"/h/code/a/.env","area":"project","bytes":10,"modified":5,"parts":[{"name":"OPENAI_API_KEY","section":null,"line":1,"span":[2,8],"json":null,"whole":false}]}],
           "duplicate":true,"from_project":true,"suggested":"seal"}]}
        """
        let report = try JSONDecoder().decode(BringReport.self, from: Data(json.utf8))
        #expect(report.summary.duplicates == 1)
        let key = try #require(report.candidates.first)
        #expect(key.kind == "key" && key.group == .works && key.from_project)
        #expect(key.partNames == "OPENAI_API_KEY")
        #expect(BringScope.places(projects: [URL(fileURLWithPath: "/h/code")]).arguments == ["--places", "--projects", "/h/code"])
        #expect(BringScope.folder(URL(fileURLWithPath: "/k")).arguments == ["--folder", "/k"])
    }

    @Test func readsOneValueFromItsSpan() throws {
        let root = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".env")
        let text = "# x\nAPI_KEY=\"CANARY-one\"\nOTHER=2\n"
        try text.write(to: file, atomically: true, encoding: .utf8)
        let read = try BringValue.read(try origin(file, [span(text, "CANARY-one", name: "API_KEY")]))
        #expect(String(decoding: read.data, as: UTF8.self) == "CANARY-one")
        #expect(read.field == nil)
    }

    @Test func aKeyOfSeveralPartsIsSealedAsNamedLines() throws {
        let root = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("paypal.json")
        let text = #"{"client_id":"CANARY-id","client_secret":"CANARY secret#1"}"#
        try text.write(to: file, atomically: true, encoding: .utf8)
        let parts: [BringCandidate.Part] = [
            .init(name: "client_id", section: nil, line: 0, span: nil, json: ["client_id"], whole: false),
            .init(name: "client_secret", section: nil, line: 0, span: nil, json: ["client_secret"], whole: false),
        ]
        let read = try BringValue.read(try origin(file, parts))
        #expect(read.field == "client_id+client_secret")
        #expect(String(decoding: read.data, as: UTF8.self) == "client_id=CANARY-id\nclient_secret=\"CANARY secret#1\"\n")
    }

    @Test func partsWithNoNameOrTheSameNameGetTheirOwn() throws {
        let root = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("notes.txt")
        let text = "CANARYaaa\nCANARYbbb\n"
        try text.write(to: file, atomically: true, encoding: .utf8)
        let read = try BringValue.read(try origin(file, [span(text, "CANARYaaa", name: nil), span(text, "CANARYbbb", name: "a b")]))
        #expect(read.field == "part1+part2")
    }

    @Test func aWholeFileIsSealedAsItIs() throws {
        let root = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("id_ed25519")
        let bytes = Data("-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY\n-----END OPENSSH PRIVATE KEY-----\n".utf8)
        try bytes.write(to: file)
        let whole = BringCandidate.Part(name: nil, section: nil, line: 1, span: nil, json: nil, whole: true)
        #expect(try BringValue.read(try origin(file, [whole])).data == bytes)
    }

    @Test func aFileChangedSinceItWasReadGivesNothing() throws {
        let root = try folder()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".env")
        let text = "API_KEY=CANARYold\n"
        try text.write(to: file, atomically: true, encoding: .utf8)
        let found = try origin(file, [span(text, "CANARYold", name: "API_KEY")])
        try "API_KEY=CANARYnewer\n".write(to: file, atomically: true, encoding: .utf8)
        #expect(throws: CheckError.self) { try BringValue.read(found) }
        // A span that would cross a line, or run past the end, is refused too.
        var bad = try origin(file, [span("API_KEY=CANARYnewer\n", "CANARYnewer\n", name: "API_KEY")])
        #expect(throws: CheckError.self) { try BringValue.read(bad) }
        bad.parts[0].span = [0, 999]
        #expect(throws: CheckError.self) { try BringValue.read(bad) }
        try FileManager.default.removeItem(at: file)
        #expect(throws: CheckError.self) { try BringValue.read(found) }
    }
}
